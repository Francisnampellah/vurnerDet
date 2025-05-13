#!/bin/bash
set -e

# Load environment variables from .env file
if [ -f .env ]; then
  export $(grep -v '^#' .env | xargs)
else
  echo "Error: .env file not found. Creating template..."
  cat > .env << EOL
# Domain configuration
DOMAIN_NAME=bluetech.software

# Database configuration
DB_USER=dbuser
DB_PASSWORD=$(openssl rand -base64 16 | tr -d '/+=' | cut -c1-16)
DB_NAME=vurnerDB

# ZAP configuration
ZAP_API_KEY=$(openssl rand -base64 32 | tr -d '/+=' | cut -c1-32)

# Environment
NODE_ENV=production
AWS_REGION=us-east-1
EOL
  echo "Please edit .env file with appropriate values and run this script again."
  exit 1
fi

# Create necessary directories
mkdir -p logs/traefik

# Create acme.json if it doesn't exist
if [ ! -f "./acme.json" ]; then
  echo "Creating acme.json..."
  touch ./acme.json
  chmod 600 ./acme.json
fi

# Create traefik_users.htpasswd file for authentication
if [ ! -f "./traefik_users.htpasswd" ]; then
  echo "Creating traefik_users.htpasswd..."
  # Generate random password if ADMIN_PASSWORD is not set
  ADMIN_PASSWORD=${ADMIN_PASSWORD:-$(openssl rand -base64 12 | tr -d '/+=' | cut -c1-12)}
  echo "Admin password: $ADMIN_PASSWORD"
  
  # Install apache2-utils if not available
  if ! command -v htpasswd &> /dev/null; then
    echo "Installing htpasswd utility..."
    sudo apt-get update && sudo apt-get install -y apache2-utils
  fi
  
  # Create htpasswd file
  htpasswd -bc ./traefik_users.htpasswd admin "$ADMIN_PASSWORD"
  chmod 600 ./traefik_users.htpasswd
fi

# Create network if it doesn't exist
if ! docker network ls | grep -q zap-network; then
  echo "Creating zap-network..."
  docker network create zap-network
fi

# Setup AWS specific configurations
# Check if running on EC2
if curl -s http://169.254.169.254/latest/meta-data/ -m 1 > /dev/null; then
  echo "Running on AWS EC2 instance..."
  
  # Configure instance hostname if DOMAIN_NAME is set
  if [ -n "$DOMAIN_NAME" ]; then
    INSTANCE_ID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)
    sudo hostnamectl set-hostname "$INSTANCE_ID.$DOMAIN_NAME"
  fi
  
  # Install AWS CLI if not available
  if ! command -v aws &> /dev/null; then
    echo "Installing AWS CLI..."
    curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
    unzip awscliv2.zip
    sudo ./aws/install
    rm -rf aws awscliv2.zip
  fi
  
  # Fetch any secrets from AWS Parameter Store if needed
  # AWS_REGION is defined in .env
  if [ -n "$AWS_REGION" ]; then
    # Example: Fetch a secret if DB_PASSWORD contains a parameter reference
    if [[ "$DB_PASSWORD" == "ssm:"* ]]; then
      PARAM_NAME=${DB_PASSWORD#"ssm:"}
      DB_PASSWORD=$(aws ssm get-parameter --name "$PARAM_NAME" --with-decryption --region "$AWS_REGION" --query "Parameter.Value" --output text)
      # Update .env file
      sed -i "s/^DB_PASSWORD=.*/DB_PASSWORD=$DB_PASSWORD/" .env
    fi
  fi
fi

# Stop and remove existing containers
echo "Stopping existing containers..."
docker-compose down

# Pull latest images
echo "Pulling latest images..."
docker-compose pull

# Start docker-compose
echo "Starting services..."
docker-compose up -d --build

# Display container statuses
echo "Container statuses:"
docker-compose ps

echo "Deployment completed successfully!"
echo "Access your services at:"
echo "- Backend: https://security.$DOMAIN_NAME"
echo "- Traefik Dashboard: https://traefik.$DOMAIN_NAME (admin:$ADMIN_PASSWORD)"
echo "- ZAP UI: https://zap.$DOMAIN_NAME (admin:$ADMIN_PASSWORD)"