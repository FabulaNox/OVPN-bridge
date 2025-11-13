#!/bin/bash

# Minimal OpenVPN Server Deployment - Working Certificate Solution
# Uses configuration file and relative paths

set -e

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="$SCRIPT_DIR/config.conf"
LOCAL_CONFIG_FILE="$SCRIPT_DIR/config.local.conf"

# Load configuration
if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "[ERROR] Configuration file not found: $CONFIG_FILE"
    exit 1
fi

# shellcheck source=config.conf
source "$CONFIG_FILE"

# Load local overrides if they exist
if [[ -f "$LOCAL_CONFIG_FILE" ]]; then
    echo "[INFO] Loading local configuration overrides..."
    # shellcheck source=config.local.conf
    source "$LOCAL_CONFIG_FILE"
fi

# Set relative paths
PKI_DIR="$SCRIPT_DIR/$PKI_DIR_NAME"
CLIENT_DIR="$SCRIPT_DIR/$CLIENT_OUTPUT_DIR"

# Auto-detect network settings if not configured
INTERFACE=$(ip route | grep default | awk '{print $5}' | head -1)

if [[ -z "$LOCAL_NETWORK" ]]; then
    LOCAL_NETWORK=$(ip route | grep "$INTERFACE" | grep -v default | grep -E '192\.168\.|10\.|172\.' | head -1 | awk '{print $1}')
fi

if [[ -z "$SERVER_LOCAL_IP" ]]; then
    SERVER_LOCAL_IP=$(ip addr show "$INTERFACE" | grep "inet " | awk '{print $2}' | cut -d'/' -f1)
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
    echo "Server Local IP: $SERVER_LOCAL_IP"
    echo "Interface: $INTERFACE"
    echo "PKI Directory: $PKI_DIR"
    echo "Client Output: $CLIENT_DIR"
    echo "=========================================="
}

# Show configuration
print_config

# Stop existing server
print_status "Stopping existing OpenVPN server..."
sudo systemctl stop openvpn-server@server 2>/dev/null || true
sudo systemctl stop openvpn@server 2>/dev/null || true

# Clean previous installation
print_status "Cleaning previous installation..."
sudo rm -rf "$OPENVPN_DIR"/*
rm -rf "$PKI_DIR"
rm -rf "$SCRIPT_DIR"/easy-rsa

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
EOF

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
sudo cp pki/ca.crt "$OPENVPN_DIR"/
sudo cp pki/issued/server.crt "$OPENVPN_DIR"/
sudo cp pki/private/server.key "$OPENVPN_DIR"/
sudo cp pki/dh.pem "$OPENVPN_DIR"/
sudo cp ta.key "$OPENVPN_DIR"/

# Create server configuration
print_status "Creating server configuration..."
sudo tee "$OPENVPN_DIR"/server.conf > /dev/null << EOF
port $VPN_PORT
proto $VPN_PROTOCOL
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
server $VPN_NETWORK $VPN_NETMASK
ifconfig-pool-persist ipp.txt
push "route $SERVER_LOCAL_IP 255.255.255.255"
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
EOF

# Enable IP forwarding
print_status "Enabling IP forwarding..."
if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf; then
    echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf
fi
sudo sysctl -p

# Configure firewall with UFW
print_status "Configuring UFW firewall..."
sudo ufw allow "$VPN_PORT"/"$VPN_PROTOCOL" comment "OpenVPN"

# Enable IP masquerading for VPN clients (check if rule already exists)
print_status "Configuring IP masquerading..."
INTERFACE=$(ip route | grep default | awk '{print $5}' | head -1)
if ! sudo iptables -t nat -C POSTROUTING -s "$VPN_NETWORK"/24 -o "$INTERFACE" -j MASQUERADE 2>/dev/null; then
    sudo iptables -t nat -A POSTROUTING -s "$VPN_NETWORK"/24 -o "$INTERFACE" -j MASQUERADE
    print_status "Added MASQUERADE rule for $VPN_NETWORK/24 on $INTERFACE"
else
    print_status "MASQUERADE rule already exists for $VPN_NETWORK/24 on $INTERFACE"
fi

# Start and enable OpenVPN
print_status "Starting OpenVPN server..."
sudo systemctl enable openvpn-server@server
sudo systemctl start openvpn-server@server

print_success "OpenVPN server deployed successfully!"
print_success "Server is running on port $VPN_PORT/$VPN_PROTOCOL"
print_success "Update your router port forwarding to: $VPN_PORT/$VPN_PROTOCOL"
