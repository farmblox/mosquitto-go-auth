#!/bin/bash

# Set up multi-platform builder (one-time)
# docker buildx create --use

VERSION=3.1.0-mosquitto_2.1.2

# Build and push
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  --push \
  -t farmblox/mosquitto-go-auth:${VERSION} \
  -t farmblox/mosquitto-go-auth:latest \
  .