#!/bin/sh
set -e

ENV_FILE="/app/.env"
EXAMPLE_FILE="/app/env.example"

# Ensure the env file exists so it can be populated from the example
if [ ! -f "$ENV_FILE" ]; then
  echo "Creating missing $ENV_FILE" 
  touch "$ENV_FILE"
fi

if [ -f "$EXAMPLE_FILE" ]; then
  while IFS= read -r line; do
    case "$line" in
      ''|\#*) continue ;;
    esac
    key="${line%%=*}"
    if ! grep -qE "^${key}=" "$ENV_FILE"; then
      echo "$line" >> "$ENV_FILE"
      echo "Added missing env var: $key"
    fi
  done < "$EXAMPLE_FILE"
fi

exec "$@"
