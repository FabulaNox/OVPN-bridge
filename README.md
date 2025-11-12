# OpenVPN Bridge - Multi-Platform VPN Solution

A configurable OpenVPN server deployment with multi-platform client generation, featuring split tunneling and platform-specific optimizations.

## Features

- **Multi-platform clients**: Windows, Linux, macOS, Android, iOS, and generic configurations
- **Split tunneling**: Only VPN network traffic routed through tunnel (internet stays local)
- **Configuration-driven**: All settings centralized in `config.conf`
- **Platform optimizations**: OS-specific DNS leak protection and compatibility
- **Auto-detection**: Automatically detects local network and public IP
- **Client management**: Organized client output with setup instructions
- **Tested and proven**: Verified working on Windows platform

## Quick Start

### 1. Configure Settings
Edit `config.conf` to customize your setup:
```bash
# Network settings
VPN_NETWORK="10.8.0.0"
VPN_PORT="61123"

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

**Multi-platform generator (recommended):**
```bash
# Interactive mode - choose platform and settings
./generate-client-multiplatform.sh

# Command line mode
./generate-client-multiplatform.sh laptop auto 1  # Windows client
./generate-client-multiplatform.sh phone auto 4   # Android client
```

**Simple generator:**
```bash
# Auto-detect public IP
./generate-minimal-client.sh laptop

# Use specific IP
./generate-minimal-client.sh office-pc YOUR.SERVER.IP
```

### 4. Use Client Configuration
- Client files are saved to `./clients/` with platform-specific names
- Each client includes setup instructions file
- Transfer `.ovpn` file to target device
- Import with platform-specific OpenVPN client

## File Structure

```
OVPN-bridge/
├── config.conf                       # 🔧 Configuration file
├── deploy-minimal.sh                 # 🚀 Server deployment
├── generate-client-multiplatform.sh  # 👥 Multi-platform client generator
├── generate-minimal-client.sh        # 👤 Simple client generation
├── README.md                         # 📄 Documentation
├── MULTIPLATFORM.md                  # 📱 Platform-specific guides
├── clients/                          # 📁 Generated client configs
│   ├── laptop-windows.ovpn
│   ├── laptop-windows-setup.txt
│   ├── phone-android.ovpn
│   └── phone-android-setup.txt
└── openvpn-ca/                       # 🔐 Certificate Authority
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

### Multi-Platform Client Generation

**Interactive mode (recommended):**
```bash
./generate-client-multiplatform.sh
```
- Choose platform (Windows, Linux, macOS, Android, iOS, Generic)
- Auto-detects server IP or allows custom IP
- Generates platform-specific configuration
- Creates setup instruction files

**Command line mode:**
```bash
./generate-client-multiplatform.sh <name> <ip> <platform>
# Platform options: 1=Windows, 2=Linux, 3=macOS, 4=Android, 5=iOS, 6=Generic
```

### Simple Client Generation

**Basic generation:**
```bash
./generate-minimal-client.sh <name> [ip]
```

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
- **External Port**: Your configured VPN port/UDP (default: 1194)
- **Internal IP**: Your server's local IP address
- **Internal Port**: Same as external port

## Troubleshooting

### Check server status:
```bash
sudo systemctl status openvpn@server
sudo journalctl -u openvpn@server -f
```

### Test connectivity:
```bash
sudo netstat -ulnp | grep <YOUR_VPN_PORT>
sudo tcpdump -i any port <YOUR_VPN_PORT>
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

## Platform Support Status

### ✅ Tested and Working:
- **Windows**: OpenVPN GUI - Full functionality confirmed
  - Split tunneling operational
  - Certificate generation working
  - External connectivity verified
  - DNS leak protection active

### 🔄 Pending Testing:
- **Linux**: NetworkManager/OpenVPN integration
- **macOS**: Tunnelblick compatibility  
- **Android**: OpenVPN for Android app
- **iOS**: OpenVPN Connect app

### 📋 Server Tested On:
- Ubuntu 24.04 LTS
- OpenVPN 2.6.14
- RouterOS 7.x (MikroTik) port forwarding
- External connectivity validation
