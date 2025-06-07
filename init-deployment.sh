#!/bin/bash

set -e

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Install Docker
install_docker() {
    echo "[+] Installing Docker..."

    if command_exists apt-get; then
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
    else
        echo "[-] Unsupported OS: Please install Docker manually."
        exit 1
    fi

    sudo systemctl start docker
    sudo systemctl enable docker
    sudo usermod -aG docker "$USER"
    echo "[+] Docker installed successfully."
}

# Install Docker Compose (plugin preferred)
install_docker_compose() {
    echo "[+] Checking Docker Compose..."
    if docker compose version >/dev/null 2>&1; then
        echo "[+] Docker Compose plugin is already installed."
    elif command_exists docker-compose; then
        echo "[+] Classic docker-compose is already installed."
    else
        echo "[+] Installing Docker Compose plugin fallback..."
        sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
        sudo chmod +x /usr/local/bin/docker-compose
        echo "[+] Docker Compose installed."
    fi
}

# Install Docker & Compose if needed
if ! command_exists docker; then
    install_docker
else
    echo "[+] Docker already installed."
fi

install_docker_compose

# Prepare project structure
echo "[+] Setting up deployment environment..."
mkdir -p security_backend
cd security_backend

# Create Docker network if not exists
echo "[+] Creating 'zap-network' Docker network..."
docker network inspect zap-network >/dev/null 2>&1 || docker network create zap-network

# Create acme.json with proper permissions
echo "[+] Creating acme.json..."
touch acme.json
chmod 600 acme.json

# Generate traefik.yml
echo "[+] Writing traefik.yml..."
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
      storage: "acme.json"
      httpChallenge:
        entryPoint: web

log:
  level: INFO
EOL

# Generate minimal docker-compose.yml
echo "[+] Writing docker-compose.yml..."
cat > docker-compose.yml << 'EOL'
version: '3.9'

services:
  traefik:
    image: traefik:2.8
    container_name: traefik
    restart: always
    networks:
      - zap-network
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - "/var/run/docker.sock:/var/run/docker.sock:ro"
      - "./traefik.yml:/traefik.yml:ro"
      - "./acme.json:/acme.json"
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.traefik.rule=Host(`traefik.bluetech.software`)"
      - "traefik.http.routers.traefik.entrypoints=websecure"
      - "traefik.http.routers.traefik.tls.certresolver=letsencrypt"
      - "traefik.http.routers.traefik.service=api@internal"

networks:
  zap-network:
    external: true
EOL

# Clean up existing containers
echo "[+] Cleaning up old containers..."
docker compose down --remove-orphans || docker-compose down --remove-orphans
docker network prune -f

# Start services
echo "[+] Starting services..."
docker compose up -d || docker-compose up -d

echo "[✓] Deployment initialization completed!"
echo "⚠️  Log out and back in if this is your first Docker install to apply group changes."
echo "💡 Check Traefik logs: docker logs -f traefik"
