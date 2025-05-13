#!/bin/bash

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to install Docker on different operating systems
install_docker() {
    echo "Installing Docker..."
    
    if command_exists apt-get; then
        # Debian/Ubuntu
        sudo apt-get update
        sudo apt-get install -y \
            apt-transport-https \
            ca-certificates \
            curl \
            gnupg \
            lsb-release
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
        echo \
            "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu \
            $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
        sudo apt-get update
        sudo apt-get install -y docker-ce docker-ce-cli containerd.io
    elif command_exists yum; then
        # CentOS/RHEL
        sudo yum install -y yum-utils
        sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
        sudo yum install -y docker-ce docker-ce-cli containerd.io
    elif command_exists brew; then
        # macOS
        brew install docker
    else
        echo "Unsupported operating system. Please install Docker manually."
        exit 1
    fi

    # Start Docker service
    if command_exists systemctl; then
        sudo systemctl start docker
        sudo systemctl enable docker
    fi

    # Add current user to docker group
    sudo usermod -aG docker $USER
    echo "Docker installed successfully!"
}

# Check if Docker is installed
if ! command_exists docker; then
    echo "Docker is not installed. Installing Docker..."
    install_docker
else
    echo "Docker is already installed."
fi

# Check if Docker Compose is installed
if ! command_exists docker-compose; then
    echo "Docker Compose is not installed. Installing Docker Compose..."
    sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    sudo chmod +x /usr/local/bin/docker-compose
else
    echo "Docker Compose is already installed."
fi

# Create necessary directories and files
echo "Setting up deployment environment..."
mkdir -p security_backend
cd security_backend

# Create and configure traefik.yml
cat > traefik.yml << 'EOL'
api:
  dashboard: true
  insecure: true

entryPoints:
  web:
    address: ":80"
    http:
      redirections:
        entryPoint:
          to: websecure
          scheme: https
  websecure:
    address: ":443"

providers:
  docker:
    endpoint: "unix:///var/run/docker.sock"
    exposedByDefault: false
    network: zap-network

certificatesResolvers:
  letsencrypt:
    acme:
      email: "admin@bluetech.software"
      storage: "/acme.json"
      httpChallenge:
        entryPoint: web

log:
  level: INFO
EOL

# Create acme.json for Traefik SSL certificates
touch acme.json
chmod 600 acme.json

# Ensure proper permissions
sudo chown -R $USER:$USER .

# Stop any running containers and remove networks
echo "Cleaning up existing containers and networks..."
docker-compose down --remove-orphans
docker network prune -f

# Start the services
echo "Starting services..."
docker-compose up -d

echo "Deployment initialization completed!"
echo "Please log out and log back in for Docker group changes to take effect."
echo "You can then run 'docker ps' to verify the installation."
echo "To check Traefik logs, run: docker logs -f traefik" 