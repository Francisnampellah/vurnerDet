#!/bin/bash

# Create acme.json if it doesn't exist
if [ ! -f "./acme.json" ]; then
  echo "Creating acme.json..."
  touch ./acme.json
  chmod 600 ./acme.json
fi

# Start docker-compose
docker-compose up -d --build
