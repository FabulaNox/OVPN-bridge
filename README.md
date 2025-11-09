# OpenVPN Bridge - Configurable Solution

A minimal, working OpenVPN server deployment with configuration file support and relative paths.

## Features

- **Configuration-driven**: All settings in `config.conf`
- **Relative paths**: Works from any directory
- **Auto-detection**: Automatically detects local network and public IP
- **Client management**: Organized client output directory
- **Proven working**: Based on tested TLS handshake solution
- **🆕 Microsoft Teams Integration**: Manage certificates directly from Teams ([Documentation](TEAMS_WEBHOOK.md))

## Quick Start

### 1. Configure Settings
Edit `config.conf` to customize your setup:
```bash
# Network settings
VPN_NETWORK="10.8.0.0"
VPN_PORT="1194"

# Certificate settings  
CERT_COUNTRY="US"
CERT_ORG="Your Organization"

# See config.conf for all options
```

### 2. Deploy Server
```bash
./deploy-minimal.sh
```

### 3. Generate Client Certificates
```bash
# Auto-detect public IP
./generate-minimal-client.sh laptop

# Use specific IP
./generate-minimal-client.sh office-pc 203.0.113.1

# Update existing client IP
./generate-minimal-client.sh laptop 203.0.113.2
```

### 4. Use Client Configuration
- Client files are saved to `./clients/`
- Transfer `.ovpn` file to client device
- Import and connect with OpenVPN client

## File Structure

```
OVPN bridge/
├── config.conf                 # 🔧 Configuration file
├── deploy-minimal.sh           # 🚀 Server deployment
├── generate-minimal-client.sh  # 👤 Client generation
├── README.md                   # 📄 Documentation
├── clients/                    # 📁 Generated client configs
│   ├── laptop.ovpn
│   └── phone.ovpn
└── openvpn-ca/                 # 🔐 Certificate Authority
    └── pki/
```

## Configuration Options

### Network Settings
- `VPN_NETWORK`: VPN subnet (default: 10.8.0.0)
- `VPN_PORT`: OpenVPN port (default: 1194)
- `VPN_PROTOCOL`: Protocol (default: udp)
- `LOCAL_NETWORK`: Local network to route (auto-detected)

### Certificate Settings
- `CERT_COUNTRY`, `CERT_PROVINCE`, `CERT_CITY`: Certificate location
- `CERT_ORG`, `CERT_EMAIL`: Organization details
- `KEY_SIZE`: RSA key size (default: 2048)
- `CA_EXPIRE`: CA expiration in days (default: 3650)

### Security Settings
- `CIPHER`: Encryption cipher (default: AES-256-GCM)
- `AUTH`: Authentication hash (default: SHA256)
- `VERB_LEVEL`: Logging verbosity (default: 3)

## Client Management

### Generate new client:
```bash
./generate-minimal-client.sh <name> [ip]
```

### Update existing client IP:
When generating for existing client, script will offer to update IP only

### List clients:
```bash
ls -la clients/
```

### View certificate info:
```bash
openssl x509 -in openvpn-ca/pki/issued/client-name.crt -noout -dates
```

## Network Requirements

### Router Configuration
Configure port forwarding:
- **External Port**: 1194/UDP (or your configured port)
- **Internal IP**: Your server's local IP
- **Internal Port**: 1194/UDP

### Firewall
The deployment script automatically:
- Opens required port in UFW
- Enables IP forwarding
- Configures basic rules

## Troubleshooting

### Check server status:
```bash
sudo systemctl status openvpn@server
sudo journalctl -u openvpn@server -f
```

### Test connectivity:
```bash
sudo netstat -ulnp | grep 1194
sudo tcpdump -i any port 1194
```

### Verify configuration:
```bash
sudo openvpn --config /etc/openvpn/server.conf --verb 4
```

## Security Notes

- Client `.ovpn` files contain private keys - keep secure
- Certificate files are excluded from git
- Use certificate revocation for compromised devices
- Regular certificate rotation recommended

## Microsoft Teams Integration

Manage your OpenVPN certificates directly from Microsoft Teams! The Teams webhook integration allows you to:

- 🔐 **Generate certificates** through Teams commands
- 📊 **Check certificate status** in real-time
- ❌ **Revoke certificates** instantly
- 🔒 **Secure communication** with HMAC signature verification

### Quick Setup

1. Install Python dependencies:
   ```bash
   pip3 install -r requirements.txt
   ```

2. Configure Teams webhook:
   ```bash
   cp .env.example .env
   # Edit .env and set your TEAMS_WEBHOOK_SECRET
   ```

3. Start the webhook server:
   ```bash
   ./start-webhook.sh
   ```

For complete setup instructions, usage examples, and troubleshooting, see [TEAMS_WEBHOOK.md](TEAMS_WEBHOOK.md).

### Quick API Test

Test the webhook API programmatically:
```bash
# Run the example script
python3 example_webhook_usage.py
```

## Tested Environment

✅ **Confirmed Working:**
- Server: OpenVPN 2.6.14 on Ubuntu
- Client: Windows OpenVPN GUI
- Connection: External (mobile hotspot → router → server)
- Result: Successful TLS handshake and VPN tunnel
