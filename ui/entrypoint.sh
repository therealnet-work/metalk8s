#!/bin/bash

set -eu

npm ci

npm run build

chown -R "$TARGET_UID:$TARGET_GID" build
