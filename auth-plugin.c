#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>

#include <mosquitto.h>
#include <mosquitto/broker.h>
#include <mosquitto/broker_plugin.h>

#include "go-auth.h"

// Same constants as in go-auth.go.
#define AuthRejected 0
#define AuthGranted 1
#define AuthError 2

static mosquitto_plugin_id_t *plg_id;

static int basic_auth_callback(int event, void *event_data, void *user_data);
static int acl_check_callback(int event, void *event_data, void *user_data);
static int tick_callback(int event, void *event_data, void *user_data);

MOSQUITTO_PLUGIN_DECLARE_VERSION(5);

int mosquitto_plugin_init(mosquitto_plugin_id_t *identifier, void **user_data,
                          struct mosquitto_opt *auth_opts, int auth_opt_count) {
  plg_id = identifier;

  // Convert mosquitto_opt array to parallel key/value arrays for Go.
  GoInt32 opts_count = auth_opt_count;
  char *keys[auth_opt_count];
  char *values[auth_opt_count];
  int i;
  struct mosquitto_opt *o;
  for (i = 0, o = auth_opts; i < auth_opt_count; i++, o++) {
    keys[i] = o->key;
    values[i] = o->value;
  }

  GoSlice keysSlice = {keys, auth_opt_count, auth_opt_count};
  GoSlice valuesSlice = {values, auth_opt_count, auth_opt_count};

  char versionArray[10];
  sprintf(versionArray, "%i.%i.%i", LIBMOSQUITTO_MAJOR, LIBMOSQUITTO_MINOR, LIBMOSQUITTO_REVISION);

  AuthPluginInit(keysSlice, valuesSlice, opts_count, versionArray);

  // Register callbacks for the v5 plugin API.
  mosquitto_callback_register(plg_id, MOSQ_EVT_BASIC_AUTH, basic_auth_callback, NULL, NULL);
  mosquitto_callback_register(plg_id, MOSQ_EVT_ACL_CHECK, acl_check_callback, NULL, NULL);
  mosquitto_callback_register(plg_id, MOSQ_EVT_TICK, tick_callback, NULL, NULL);

  return MOSQ_ERR_SUCCESS;
}

int mosquitto_plugin_cleanup(void *user_data, struct mosquitto_opt *auth_opts, int auth_opt_count) {
  mosquitto_callback_unregister(plg_id, MOSQ_EVT_BASIC_AUTH, basic_auth_callback, NULL);
  mosquitto_callback_unregister(plg_id, MOSQ_EVT_ACL_CHECK, acl_check_callback, NULL);
  mosquitto_callback_unregister(plg_id, MOSQ_EVT_TICK, tick_callback, NULL);

  AuthPluginCleanup();
  return MOSQ_ERR_SUCCESS;
}

/*
 * Basic auth callback — fires when a client connects with username/password.
 *
 * Instead of blocking the mosquitto event loop while waiting for the HTTP
 * backend to respond (which runs bcrypt), we start the auth check in a Go
 * goroutine and return MOSQ_ERR_AUTH_DELAYED. The tick callback will later
 * call mosquitto_complete_basic_auth() with the result.
 */
static int basic_auth_callback(int event, void *event_data, void *user_data) {
  struct mosquitto_evt_basic_auth *ed = event_data;
  const char *clientid = mosquitto_client_id(ed->client);

  if (ed->username == NULL || ed->password == NULL) {
    printf("error: received null username or password for unpwd check\n");
    fflush(stdout);
    return MOSQ_ERR_AUTH;
  }

  // Fire off the auth check in a Go goroutine; returns immediately.
  AuthUnpwdCheckAsync((char *)ed->username, (char *)ed->password, (char *)clientid);
  return MOSQ_ERR_AUTH_DELAYED;
}

/*
 * Tick callback — runs on the main mosquitto thread on every broker tick.
 *
 * Drains completed auth results from the Go channel and calls
 * mosquitto_complete_basic_auth() for each one (which must be called
 * from the main thread).
 */
static int tick_callback(int event, void *event_data, void *user_data) {
  struct mosquitto_evt_tick *ed = event_data;

  #define MAX_BATCH 64
  char *clientids[MAX_BATCH];
  uint8_t results[MAX_BATCH];

  GoInt count = DrainAuthResults(clientids, results, MAX_BATCH);
  for (int i = 0; i < count; i++) {
    int mosq_result;
    switch (results[i]) {
      case AuthGranted:
        mosq_result = MOSQ_ERR_SUCCESS;
        break;
      case AuthRejected:
        mosq_result = MOSQ_ERR_AUTH;
        break;
      case AuthError:
      default:
        mosq_result = MOSQ_ERR_UNKNOWN;
        break;
    }
    mosquitto_complete_basic_auth(clientids[i], mosq_result);
    free(clientids[i]);
  }

  // Use a fast tick interval (10ms) so completed auth results are picked up quickly.
  ed->next_ms = 10;

  return MOSQ_ERR_SUCCESS;
}

/*
 * ACL check callback — stays synchronous.
 *
 * ACL checks are already fast when the go-auth cache is warm (keyed by
 * username+topic+clientid+acc). No need to make these async.
 */
static int acl_check_callback(int event, void *event_data, void *user_data) {
  struct mosquitto_evt_acl_check *ed = event_data;
  const char *clientid = mosquitto_client_id(ed->client);
  const char *username = mosquitto_client_username(ed->client);

  if (clientid == NULL || username == NULL || ed->topic == NULL || ed->access < 1) {
    printf("error: received null username, clientid or topic, or access is equal or less than 0 for acl check\n");
    fflush(stdout);
    return MOSQ_ERR_ACL_DENIED;
  }

  GoUint8 ret = AuthAclCheck((char *)clientid, (char *)username, (char *)ed->topic, ed->access);

  switch (ret) {
    case AuthGranted:
      return MOSQ_ERR_SUCCESS;
    case AuthRejected:
      return MOSQ_ERR_ACL_DENIED;
    case AuthError:
      return MOSQ_ERR_UNKNOWN;
    default:
      fprintf(stderr, "unknown plugin error: %d\n", ret);
      return MOSQ_ERR_UNKNOWN;
  }
}
