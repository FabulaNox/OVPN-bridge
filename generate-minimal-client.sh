#!/bin/bash

# Minimal Client Certificate Generator - Working Solution
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

# Set paths
PKI_DIR="$SCRIPT_DIR/$PKI_DIR_NAME"
CLIENT_DIR="$SCRIPT_DIR/$CLIENT_OUTPUT_DIR"

CLIENT_NAME="$1"
CUSTOM_IP="$2"

if [ -z "$CLIENT_NAME" ]; then
    echo "Usage: $0 <client-name> [custom-ip]"
    echo ""
    echo "Examples:"
    echo "  $0 laptop                    # Auto-detect public IP"
    echo "  $0 phone 192.168.1.100      # Use specific IP"
    echo "  $0 office auto               # Auto-detect public IP"
    exit 1
fi

# Validate PKI directory exists
if [[ ! -d "$PKI_DIR" ]]; then
    echo "[ERROR] PKI directory not found: $PKI_DIR"
    echo "[ERROR] Please run ./deploy-minimal.sh first"
    exit 1
fi

# Determine server IP
if [[ -n "$CUSTOM_IP" && "$CUSTOM_IP" != "auto" ]]; then
    SERVER_IP="$CUSTOM_IP"
else
    # Get public IP
    SERVER_IP=$(curl -s ipinfo.io/ip 2>/dev/null || echo "YOUR_PUBLIC_IP")
fi

# Create client output directory
mkdir -p "$CLIENT_DIR"

cd "$PKI_DIR"

# Check if client already exists
if [[ -f "pki/issued/${CLIENT_NAME}.crt" ]]; then
    echo "[WARNING] Certificate for $CLIENT_NAME already exists"
    read -p "Recreate certificate? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "[INFO] Using existing certificate"
        SERVER_IP_EXISTING=$(grep "^remote " "$CLIENT_DIR/${CLIENT_NAME}.ovpn" 2>/dev/null | awk '{print $2}' || echo "")
        if [[ -n "$SERVER_IP_EXISTING" ]]; then
            echo "[INFO] Existing .ovpn uses IP: $SERVER_IP_EXISTING"
            read -p "Update IP to $SERVER_IP? (y/N): " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                # Just update the IP in existing .ovpn
                sed -i "s/^remote .*/remote $SERVER_IP $VPN_PORT/" "$CLIENT_DIR/${CLIENT_NAME}.ovpn"
                echo "[SUCCESS] Updated $CLIENT_NAME.ovpn with new IP: $SERVER_IP"
                exit 0
            else
                echo "[INFO] No changes made"
                exit 0
            fi
        fi
    fi
fi

# Generate client certificate
echo "[INFO] Generating certificate for $CLIENT_NAME..."
./easyrsa gen-req $CLIENT_NAME nopass
echo "yes" | ./easyrsa sign-req client $CLIENT_NAME

# Create .ovpn file
echo "[INFO] Creating $CLIENT_NAME.ovpn..."
cat > "$CLIENT_DIR/${CLIENT_NAME}.ovpn" << EOF
client
dev tun
proto $VPN_PROTOCOL
remote $SERVER_IP $VPN_PORT
resolv-retry infinite
nobind
persist-key
persist-tun
cipher $CIPHER
auth $AUTH
key-direction 1
verb $VERB_LEVEL
remote-cert-tls server
tls-version-min 1.2

<ca>
$(cat pki/ca.crt)
</ca>
<cert>
$(cat pki/issued/$CLIENT_NAME.crt)
</cert>
<key>
$(cat pki/private/$CLIENT_NAME.key)
</key>
<tls-auth>
$(cat ta.key)
</tls-auth>

# Set secure permissions
chmod 600 "$CLIENT_DIR/${CLIENT_NAME}.ovpn"

echo "[SUCCESS] Client configuration created: $CLIENT_DIR/${CLIENT_NAME}.ovpn"
echo "[INFO] Server IP used: $SERVER_IP"
echo "[INFO] Port: $VPN_PORT/$VPN_PROTOCOL"
echo "[INFO] Ensure port forwarding is configured on your router"
