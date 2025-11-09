#!/bin/bash

# Minimal OpenVPN Server Deployment - Working Certificate Solution
# Uses configuration file and relative paths

set -e

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="$SCRIPT_DIR/config.conf"

# Load configuration
if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "[ERROR] Configuration file not found: $CONFIG_FILE"
    exit 1
fi

source "$CONFIG_FILE"

# Set relative paths
PKI_DIR="$SCRIPT_DIR/$PKI_DIR_NAME"
CLIENT_DIR="$SCRIPT_DIR/$CLIENT_OUTPUT_DIR"

# Auto-detect local network if not configured
if [[ -z "$LOCAL_NETWORK" ]]; then
    INTERFACE=$(ip route | grep default | awk '{print $5}' | head -1)
    LOCAL_NETWORK=$(ip route | grep "$INTERFACE" | grep -E '192\.168\.|10\.|172\.' | head -1 | awk '{print $1}' | head -1)
fi

print_status() {
    echo "[INFO] $1"
}

print_success() {
    echo "[SUCCESS] $1"
}

print_config() {
    echo "=========================================="
    echo "OpenVPN Configuration:"
    echo "=========================================="
    echo "VPN Network: $VPN_NETWORK/$VPN_NETMASK"
    echo "Port: $VPN_PORT/$VPN_PROTOCOL"
    echo "Local Network: $LOCAL_NETWORK"
    echo "PKI Directory: $PKI_DIR"
    echo "Client Output: $CLIENT_DIR"
    echo "=========================================="
}

# Show configuration
print_config

# Stop existing server
print_status "Stopping existing OpenVPN server..."
sudo systemctl stop openvpn@server 2>/dev/null || true

# Clean previous installation
print_status "Cleaning previous installation..."
sudo rm -rf $OPENVPN_DIR/*
rm -rf $PKI_DIR
rm -rf $SCRIPT_DIR/easy-rsa

# Create client output directory
mkdir -p "$CLIENT_DIR"

# Setup Easy-RSA
print_status "Setting up Easy-RSA..."
cd "$SCRIPT_DIR"
git clone https://github.com/OpenVPN/easy-rsa.git
cp -r easy-rsa/easyrsa3 "$PKI_DIR_NAME"
cd "$PKI_DIR"

# Create vars file from config
cat > vars << EOF
set_var EASYRSA_REQ_COUNTRY    "$CERT_COUNTRY"
set_var EASYRSA_REQ_PROVINCE   "$CERT_PROVINCE"
set_var EASYRSA_REQ_CITY       "$CERT_CITY"
set_var EASYRSA_REQ_ORG        "$CERT_ORG"
set_var EASYRSA_REQ_EMAIL      "$CERT_EMAIL"
set_var EASYRSA_REQ_OU         "$CERT_OU"
set_var EASYRSA_KEY_SIZE       $KEY_SIZE
set_var EASYRSA_ALGO           rsa
set_var EASYRSA_CA_EXPIRE      $CA_EXPIRE
set_var EASYRSA_CERT_EXPIRE    $CERT_EXPIRE

# Initialize PKI
print_status "Initializing PKI..."
./easyrsa init-pki

# Create CA
print_status "Creating Certificate Authority..."
echo "$SERVER_CN" | ./easyrsa build-ca nopass

# Create server certificate
print_status "Creating server certificate..."
./easyrsa gen-req server nopass
echo "yes" | ./easyrsa sign-req server server

# Generate DH parameters
print_status "Generating DH parameters..."
./easyrsa gen-dh

# Generate TLS-auth key
print_status "Generating TLS-auth key..."
openvpn --genkey secret ta.key

# Copy certificates to OpenVPN directory
print_status "Copying certificates..."
sudo cp pki/ca.crt $OPENVPN_DIR/
sudo cp pki/issued/server.crt $OPENVPN_DIR/
sudo cp pki/private/server.key $OPENVPN_DIR/
sudo cp pki/dh.pem $OPENVPN_DIR/
sudo cp ta.key $OPENVPN_DIR/

# Create server configuration
print_status "Creating server configuration..."
sudo tee $OPENVPN_DIR/server.conf > /dev/null << EOF
port $VPN_PORT
proto $VPN_PROTOCOL
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
server $VPN_NETWORK $VPN_NETMASK
ifconfig-pool-persist ipp.txt
push "route $LOCAL_NETWORK"
keepalive 10 120
tls-auth ta.key 0
cipher $CIPHER
auth $AUTH
user nobody
group nogroup
persist-key
persist-tun
status openvpn-status.log
verb $VERB_LEVEL
explicit-exit-notify 1
