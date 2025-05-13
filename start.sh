#!/bin/bash

# Create acme.json if it doesn't exist
if [ ! -f "./acme.json" ]; then
  echo "Creating acme.json..."
  sudo touch ./acme.json
  sudo chmod 600 ./acme.json
fi

# Start docker-compose
sudo docker-compose up -d --build
