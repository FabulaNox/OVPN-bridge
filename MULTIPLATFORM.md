# Multi-Platform OpenVPN Client Generator

## Overview

The `generate-client-multiplatform.sh` script creates optimized OpenVPN client configurations for different operating systems with **split tunneling** enabled. This means only traffic destined for the VPN server's network goes through the tunnel, while regular internet traffic uses the client's normal connection.

## Key Features

✅ **Split Tunneling**: Internet traffic stays local, only VPN server network is routed  
✅ **Embedded Certificates**: All certificates included in .ovpn files for easy deployment  
✅ **OS-Specific Optimizations**: Tailored for each platform's preferred OpenVPN client  
✅ **Linux Server Optimized**: Designed for Linux-based OpenVPN servers  
✅ **DNS Leak Protection**: Prevents DNS leaks while maintaining split tunneling  

## Supported Platforms

| Platform | Recommended Client | Key Optimizations |
|----------|-------------------|-------------------|
| **Windows** | OpenVPN GUI | Registry DNS protection, route-method exe |
| **Linux** | NetworkManager | resolvconf integration, script-security |
| **macOS** | Tunnelblick | Route filtering, DNS management |
| **Android** | OpenVPN for Android | Fast-io, compression, battery optimization |
| **iOS** | OpenVPN Connect | Compression, iOS-specific routing |
| **Generic** | Any OpenVPN client | Standard split-tunnel configuration |

## Usage

### Interactive Mode
```bash
./generate-client-multiplatform.sh
```

### Command Line Mode
```bash
./generate-client-multiplatform.sh <client-name> [server-ip] [os-choice]
```

### Examples
```bash
# Interactive mode - will prompt for all options
./generate-client-multiplatform.sh

# Windows client with auto-detected IP
./generate-client-multiplatform.sh laptop auto 1

# Android client with specific IP
./generate-client-multiplatform.sh phone 192.168.1.100 4

# macOS client with custom IP
./generate-client-multiplatform.sh macbook 203.0.113.50 3
```

## OS Choices

1. **Windows** - OpenVPN GUI optimized
2. **Linux** - NetworkManager/OpenVPN optimized  
3. **macOS** - Tunnelblick optimized
4. **Android** - OpenVPN for Android optimized
5. **iOS** - OpenVPN Connect optimized
6. **Generic** - Standard split-tunnel .ovpn

## Output Files

For each client, the script generates:

- `<client-name>-<os>.ovpn` - The OpenVPN configuration file
- `<client-name>-<os>-setup.txt` - Platform-specific setup instructions

## Split Tunneling Configuration

All configurations include:

```
# Split tunneling settings
pull-filter ignore "redirect-gateway"
pull-filter ignore "dhcp-option DNS"
route 10.8.0.0 255.255.255.0  # Only VPN network routed
```

This ensures:
- ✅ Only VPN server network traffic goes through tunnel
- ✅ Internet browsing uses regular connection
- ✅ Better performance and reduced server load
- ✅ Access to local network resources maintained

## Prerequisites

1. Run `./deploy-minimal.sh` first to set up the server
2. Ensure PKI directory exists with valid certificates
3. Configure port forwarding on your router

## Platform-Specific Notes

### Windows (OpenVPN GUI)
- Includes registry-based DNS leak protection
- Optimized for Windows routing table management
- Run as Administrator for best results

### Linux (NetworkManager)
- Integrates with system DNS management
- Works with NetworkManager GUI and command line
- Supports both Ubuntu/Debian and Fedora/RHEL

### macOS (Tunnelblick)
- Optimized for Tunnelblick's routing engine
- Includes macOS-specific DNS handling
- Alternative OpenVPN Connect support

### Android (OpenVPN for Android)
- Battery-optimized settings
- Fast-io and compression enabled
- Per-app VPN support maintained

### iOS (OpenVPN Connect)
- Optimized for iOS networking stack
- Efficient compression and routing
- Seamless profile import support

## Troubleshooting

### Connection Issues
1. Verify server is running: `sudo systemctl status openvpn@server`
2. Check port forwarding on router
3. Confirm firewall allows OpenVPN traffic

### Split Tunneling Verification
```bash
# Check routes after connecting (client-side)
ip route | grep 10.8.0.0        # Linux
route print | findstr 10.8.0.0  # Windows
netstat -rn | grep 10.8.0.0     # macOS
```

### DNS Leak Testing
- Visit https://dnsleaktest.com/
- Should show your regular ISP DNS, not VPN server DNS
- VPN server network should still be accessible

## Security Notes

- All certificates are embedded for security and convenience
- TLS-auth provides additional security layer
- Split tunneling reduces attack surface
- Client certificates can be revoked individually

## Network Topology

```
Client Device
     ↓ (internet traffic)
Local ISP/Router ← Regular Internet Access
     ↓ (VPN server network traffic only)
OpenVPN Server → VPN Network (10.8.0.0/24)
```

This topology ensures optimal performance while maintaining secure access to VPN server resources.