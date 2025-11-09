#!/bin/bash

# Quick start script for Teams Webhook Server
# This script helps set up and start the webhook server

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=========================================="
echo "OVPN Bridge Teams Webhook Setup"
echo "=========================================="
echo ""

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "[ERROR] Python 3 is not installed. Please install Python 3.7 or higher."
    exit 1
fi

echo "[INFO] Python 3 found: $(python3 --version)"

# Check if pip is installed
if ! command -v pip3 &> /dev/null; then
    echo "[ERROR] pip3 is not installed. Please install pip3."
    exit 1
fi

echo "[INFO] pip3 found: $(pip3 --version)"

# Check if OpenVPN CA is initialized
if [ ! -d "openvpn-ca/pki" ]; then
    echo "[WARNING] OpenVPN CA not found. Please run ./deploy-minimal.sh first."
    read -p "Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Install Python dependencies
echo ""
echo "[INFO] Installing Python dependencies..."
pip3 install -r requirements.txt

# Check if .env file exists
if [ ! -f ".env" ]; then
    echo ""
    echo "[WARNING] No .env file found."
    echo "[INFO] Creating .env from .env.example..."
    cp .env.example .env
    echo ""
    echo "=========================================="
    echo "IMPORTANT: Configure your webhook secret!"
    echo "=========================================="
    echo ""
    echo "1. Edit the .env file and set your TEAMS_WEBHOOK_SECRET"
    echo "2. Get the secret from your Teams Outgoing Webhook configuration"
    echo ""
    echo "Edit .env now? (opens with nano)"
    read -p "Press Y to edit, or N to skip: " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        nano .env
    fi
fi

# Load environment variables from .env
if [ -f ".env" ]; then
    echo "[INFO] Loading configuration from .env..."
    export $(grep -v '^#' .env | xargs)
fi

# Check if webhook secret is configured
if [ -z "$TEAMS_WEBHOOK_SECRET" ] || [ "$TEAMS_WEBHOOK_SECRET" = "your-secret-token-here" ]; then
    echo ""
    echo "[WARNING] TEAMS_WEBHOOK_SECRET is not properly configured!"
    echo "[WARNING] The webhook will work but signature verification will be disabled."
    echo ""
fi

# Display configuration
echo ""
echo "=========================================="
echo "Configuration:"
echo "=========================================="
echo "Host: ${WEBHOOK_HOST:-0.0.0.0}"
echo "Port: ${WEBHOOK_PORT:-5000}"
echo "Debug: ${WEBHOOK_DEBUG:-False}"
echo "Secret configured: $([ -n "$TEAMS_WEBHOOK_SECRET" ] && echo "Yes" || echo "No")"
echo "=========================================="
echo ""

# Ask how to run
echo "How do you want to run the webhook server?"
echo ""
echo "1. Run in foreground (press Ctrl+C to stop)"
echo "2. Install as systemd service (recommended for production)"
echo "3. Run with Docker"
echo "4. Exit"
echo ""
read -p "Enter choice [1-4]: " -n 1 -r
echo

case $REPLY in
    1)
        echo ""
        echo "[INFO] Starting webhook server in foreground..."
        echo "[INFO] Press Ctrl+C to stop"
        echo ""
        python3 teams_webhook.py
        ;;
    2)
        echo ""
        echo "[INFO] Installing as systemd service..."
        
        # Update service file with actual paths
        SERVICE_FILE="teams-webhook.service"
        TEMP_SERVICE="/tmp/teams-webhook.service"
        
        sed "s|/path/to/OVPN-bridge|$SCRIPT_DIR|g" "$SERVICE_FILE" > "$TEMP_SERVICE"
        
        # Update with environment variables if set
        if [ -n "$TEAMS_WEBHOOK_SECRET" ]; then
            sed -i "s|change-me-to-your-secret|$TEAMS_WEBHOOK_SECRET|g" "$TEMP_SERVICE"
        fi
        
        sudo cp "$TEMP_SERVICE" /etc/systemd/system/teams-webhook.service
        sudo systemctl daemon-reload
        sudo systemctl enable teams-webhook
        sudo systemctl start teams-webhook
        
        echo "[SUCCESS] Service installed and started!"
        echo ""
        echo "Useful commands:"
        echo "  sudo systemctl status teams-webhook    # Check status"
        echo "  sudo systemctl stop teams-webhook      # Stop service"
        echo "  sudo systemctl restart teams-webhook   # Restart service"
        echo "  sudo journalctl -u teams-webhook -f    # View logs"
        
        rm "$TEMP_SERVICE"
        ;;
    3)
        echo ""
        echo "[INFO] Docker deployment instructions:"
        echo ""
        echo "1. Build the Docker image:"
        echo "   docker build -t ovpn-bridge-webhook ."
        echo ""
        echo "2. Run the container:"
        echo "   docker run -d \\"
        echo "     -p 5000:5000 \\"
        echo "     -e TEAMS_WEBHOOK_SECRET=\"$TEAMS_WEBHOOK_SECRET\" \\"
        echo "     -v $(pwd)/openvpn-ca:/app/openvpn-ca \\"
        echo "     -v $(pwd)/clients:/app/clients \\"
        echo "     --name ovpn-webhook \\"
        echo "     ovpn-bridge-webhook"
        echo ""
        ;;
    4)
        echo "[INFO] Exiting..."
        exit 0
        ;;
    *)
        echo "[ERROR] Invalid choice"
        exit 1
        ;;
esac
