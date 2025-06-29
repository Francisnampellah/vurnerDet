#!/bin/bash

echo "🔄 Restarting AutoScanWorker..."

# Stop the worker container
echo "🛑 Stopping worker container..."
docker-compose stop worker

# Remove the worker container
echo "🗑️ Removing worker container..."
docker-compose rm -f worker

# Clean up any dangling images
echo "🧹 Cleaning up dangling images..."
docker image prune -f

# Start the worker container
echo "🚀 Starting worker container..."
docker-compose up -d worker

# Show logs
echo "📋 Showing worker logs..."
docker-compose logs -f worker 