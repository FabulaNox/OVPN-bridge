#!/bin/bash

# Multi-Platform OpenVPN Client Generator
# Supports Windows, Linux, macOS, Android, and iOS with OS-specific configurations

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

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

print_header() {
    echo -e "${BLUE}=========================================="
    echo -e " Multi-Platform OpenVPN Client Generator"
    echo -e "==========================================${NC}"
}

print_status() {
    echo -e "${CYAN}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

show_os_menu() {
    echo ""
    echo -e "${PURPLE}Select target operating system:${NC}"
    echo -e "${CYAN}All configurations use SPLIT TUNNELING (internet traffic stays local)${NC}"
    echo ""
    echo "1) Windows (OpenVPN GUI optimized)"
    echo "2) Linux (NetworkManager/OpenVPN optimized)"
    echo "3) macOS (Tunnelblick optimized)"
    echo "4) Android (OpenVPN for Android optimized)"
    echo "5) iOS (OpenVPN Connect optimized)"
    echo "6) Generic (Standard split-tunnel .ovpn)"
    echo ""
    read -p "Enter your choice (1-6): " os_choice
    echo ""
}

get_client_name() {
    if [ -z "$1" ]; then
        read -p "Enter client name: " CLIENT_NAME
    else
        CLIENT_NAME="$1"
    fi
    
    if [ -z "$CLIENT_NAME" ]; then
        print_error "Client name cannot be empty"
        exit 1
    fi
}

get_server_ip() {
    local custom_ip="$1"
    
    if [[ -n "$custom_ip" && "$custom_ip" != "auto" ]]; then
        SERVER_IP="$custom_ip"
    else
        print_status "Auto-detecting public IP..."
        SERVER_IP=$(curl -s ipinfo.io/ip 2>/dev/null || curl -s ifconfig.me 2>/dev/null || echo "YOUR_PUBLIC_IP")
        if [[ "$SERVER_IP" == "YOUR_PUBLIC_IP" ]]; then
            print_warning "Could not auto-detect public IP"
            read -p "Enter your server's public IP address: " SERVER_IP
        fi
    fi
    print_status "Using server IP: $SERVER_IP"
}

validate_environment() {
    if [[ ! -d "$PKI_DIR" ]]; then
        print_error "PKI directory not found: $PKI_DIR"
        print_error "Please run ./deploy-minimal.sh first"
        exit 1
    fi
    
    mkdir -p "$CLIENT_DIR"
}

generate_certificate() {
    local client_name="$1"
    
    cd "$PKI_DIR"
    
    # Remove any existing lock file
    rm -f pki/lock.file 2>/dev/null || true
    
    # Check if client already exists
    if [[ -f "pki/issued/${client_name}.crt" ]]; then
        print_warning "Certificate for $client_name already exists"
        read -p "Recreate certificate? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_status "Using existing certificate"
            return 0
        fi
        # Remove existing certificate files
        rm -f "pki/issued/${client_name}.crt"
        rm -f "pki/private/${client_name}.key"
        rm -f "pki/reqs/${client_name}.req"
    fi
    
    print_status "Generating certificate for $client_name..."
    
    # Generate certificate request (non-interactive)
    echo "$client_name" | ./easyrsa gen-req "$client_name" nopass
    
    # Sign the certificate (non-interactive)
    echo "yes" | ./easyrsa sign-req client "$client_name"
    
    print_success "Certificate generated successfully"
}

create_windows_config() {
    local client_name="$1"
    local output_file="$CLIENT_DIR/${client_name}-windows.ovpn"
    
    print_status "Creating Windows configuration (OpenVPN GUI)..."
    
    cat > "$output_file" << EOF
# Windows OpenVPN Configuration - OpenVPN GUI
# Split tunneling: Only VPN server network traffic goes through tunnel
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
verb 3
remote-cert-tls server
tls-version-min 1.2

# Windows-specific optimizations for OpenVPN GUI
route-method exe
route-delay 2
mute-replay-warnings
pull-filter ignore "redirect-gateway"
pull-filter ignore "dhcp-option DNS"

# Split tunneling: Only route VPN server's network
route $VPN_NETWORK 255.255.255.0

# Windows registry DNS leak protection
block-outside-dns

<ca>
$(cat "$PKI_DIR/pki/ca.crt")
</ca>
<cert>
$(cat "$PKI_DIR/pki/issued/$client_name.crt")
</cert>
<key>
$(cat "$PKI_DIR/pki/private/$client_name.key")
</key>
<tls-auth>
$(cat "$PKI_DIR/ta.key")
</tls-auth>
EOF

    chmod 600 "$output_file"
    print_success "Windows configuration created: $output_file"
}

create_linux_config() {
    local client_name="$1"
    local output_file="$CLIENT_DIR/${client_name}-linux.ovpn"
    
    print_status "Creating Linux configuration (NetworkManager/OpenVPN)..."
    
    cat > "$output_file" << EOF
# Linux OpenVPN Configuration - NetworkManager/OpenVPN
# Split tunneling: Only VPN server network traffic goes through tunnel
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
verb 3
remote-cert-tls server
tls-version-min 1.2

# Linux-specific settings for NetworkManager
script-security 2
pull-filter ignore "redirect-gateway"
pull-filter ignore "dhcp-option DNS"

# Split tunneling: Only route VPN server's network
route $VPN_NETWORK 255.255.255.0

# Prevent DNS leaks while maintaining split tunneling
up /etc/openvpn/update-resolv-conf
down /etc/openvpn/update-resolv-conf

<ca>
$(cat "$PKI_DIR/pki/ca.crt")
</ca>
<cert>
$(cat "$PKI_DIR/pki/issued/$client_name.crt")
</cert>
<key>
$(cat "$PKI_DIR/pki/private/$client_name.key")
</key>
<tls-auth>
$(cat "$PKI_DIR/ta.key")
</tls-auth>
EOF

    chmod 600 "$output_file"
    print_success "Linux configuration created: $output_file"
    print_status "For NetworkManager: Import this file through Settings > Network > VPN"
}

create_macos_config() {
    local client_name="$1"
    local output_file="$CLIENT_DIR/${client_name}-macos.ovpn"
    
    print_status "Creating macOS configuration (Tunnelblick)..."
    
    cat > "$output_file" << EOF
# macOS OpenVPN Configuration - Tunnelblick Optimized
# Split tunneling: Only VPN server network traffic goes through tunnel
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
verb 3
remote-cert-tls server
tls-version-min 1.2

# macOS-specific settings for Tunnelblick
pull-filter ignore "redirect-gateway"
pull-filter ignore "dhcp-option DNS"

# Split tunneling: Only route VPN server's network
route $VPN_NETWORK 255.255.255.0

# Prevent DNS leaks on macOS
block-outside-dns

<ca>
$(cat "$PKI_DIR/pki/ca.crt")
</ca>
<cert>
$(cat "$PKI_DIR/pki/issued/$client_name.crt")
</cert>
<key>
$(cat "$PKI_DIR/pki/private/$client_name.key")
</key>
<tls-auth>
$(cat "$PKI_DIR/ta.key")
</tls-auth>
EOF

    chmod 600 "$output_file"
    print_success "macOS configuration created: $output_file"
    print_status "For Tunnelblick: Double-click the .ovpn file to import"
}

create_android_config() {
    local client_name="$1"
    local output_file="$CLIENT_DIR/${client_name}-android.ovpn"
    
    print_status "Creating Android configuration (OpenVPN for Android)..."
    
    cat > "$output_file" << EOF
# Android OpenVPN Configuration - OpenVPN for Android
# Split tunneling: Only VPN server network traffic goes through tunnel
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
verb 3
remote-cert-tls server
tls-version-min 1.2

# Android-specific optimizations for OpenVPN for Android
fast-io
sndbuf 0
rcvbuf 0
compress lz4-v2
push-peer-info
pull-filter ignore "redirect-gateway"
pull-filter ignore "dhcp-option DNS"

# Split tunneling: Only route VPN server's network
route $VPN_NETWORK 255.255.255.0

# Android doesn't need explicit DNS leak protection
# as the app handles this internally

<ca>
$(cat "$PKI_DIR/pki/ca.crt")
</ca>
<cert>
$(cat "$PKI_DIR/pki/issued/$client_name.crt")
</cert>
<key>
$(cat "$PKI_DIR/pki/private/$client_name.key")
</key>
<tls-auth>
$(cat "$PKI_DIR/ta.key")
</tls-auth>
EOF

    chmod 600 "$output_file"
    print_success "Android configuration created: $output_file"
    print_status "Import: Copy file to device and open with 'OpenVPN for Android'"
}

create_ios_config() {
    local client_name="$1"
    local output_file="$CLIENT_DIR/${client_name}-ios.ovpn"
    
    print_status "Creating iOS configuration (OpenVPN Connect)..."
    
    cat > "$output_file" << EOF
# iOS OpenVPN Configuration - OpenVPN Connect
# Split tunneling: Only VPN server network traffic goes through tunnel
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
verb 3
remote-cert-tls server
tls-version-min 1.2

# iOS-specific optimizations for OpenVPN Connect
fast-io
compress lz4-v2
push-peer-info
pull-filter ignore "redirect-gateway"
pull-filter ignore "dhcp-option DNS"

# Split tunneling: Only route VPN server's network
route $VPN_NETWORK 255.255.255.0

# iOS OpenVPN Connect handles DNS management internally

<ca>
$(cat "$PKI_DIR/pki/ca.crt")
</ca>
<cert>
$(cat "$PKI_DIR/pki/issued/$client_name.crt")
</cert>
<key>
$(cat "$PKI_DIR/pki/private/$client_name.key")
</key>
<tls-auth>
$(cat "$PKI_DIR/ta.key")
</tls-auth>
EOF

    chmod 600 "$output_file"
    print_success "iOS configuration created: $output_file"
    print_status "Import: AirDrop/email file and open with 'OpenVPN Connect'"
}

create_generic_config() {
    local client_name="$1"
    local output_file="$CLIENT_DIR/${client_name}.ovpn"
    
    print_status "Creating generic configuration..."
    
    cat > "$output_file" << EOF
# Generic OpenVPN Configuration - Split Tunneling
# Only VPN server network traffic goes through tunnel
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
verb 3
remote-cert-tls server
tls-version-min 1.2

# Split tunneling configuration
pull-filter ignore "redirect-gateway"
pull-filter ignore "dhcp-option DNS"

# Only route VPN server's network
route $VPN_NETWORK 255.255.255.0

<ca>
$(cat "$PKI_DIR/pki/ca.crt")
</ca>
<cert>
$(cat "$PKI_DIR/pki/issued/$client_name.crt")
</cert>
<key>
$(cat "$PKI_DIR/pki/private/$client_name.key")
</key>
<tls-auth>
$(cat "$PKI_DIR/ta.key")
</tls-auth>
EOF

    chmod 600 "$output_file"
    print_success "Generic configuration created: $output_file"
}

create_setup_instructions() {
    local client_name="$1"
    local os_type="$2"
    local instructions_file="$CLIENT_DIR/${client_name}-${os_type}-setup.txt"
    
    case $os_type in
        windows)
            cat > "$instructions_file" << EOF
OpenVPN Setup Instructions for Windows
=====================================

Recommended Client: OpenVPN GUI (Official)
Download: https://openvpn.net/community-downloads/

Setup Steps:
1. Install OpenVPN GUI as Administrator
2. Copy ${client_name}-windows.ovpn to: C:\Program Files\OpenVPN\config\
3. Right-click OpenVPN GUI icon in system tray
4. Select "${client_name}-windows" from the context menu
5. Click "Connect"

Split Tunneling Configuration:
- This configuration only routes traffic to the VPN server's network ($VPN_NETWORK)
- Your general internet traffic remains through your regular connection
- DNS leaks are prevented while maintaining split tunneling

Troubleshooting:
- Run OpenVPN GUI as Administrator if connection fails
- Ensure Windows Firewall allows OpenVPN
- Check that TAP adapter is installed properly
- Verify the VPN server's network ($VPN_NETWORK) appears in route table when connected
EOF
            ;;
        linux)
            cat > "$instructions_file" << EOF
OpenVPN Setup Instructions for Linux
===================================

Recommended Client: NetworkManager with OpenVPN plugin

Setup for Ubuntu/Debian:
1. Install: sudo apt install network-manager-openvpn-gnome
2. Open Settings > Network
3. Click "+" next to VPN
4. Select "Import from file"
5. Choose ${client_name}-linux.ovpn
6. Click "Add" then toggle ON to connect

Setup for Fedora/RHEL:
1. Install: sudo dnf install NetworkManager-openvpn-gnome
2. Follow Ubuntu steps above

Command Line Alternative:
sudo apt install openvpn
sudo openvpn ${client_name}-linux.ovpn

Split Tunneling Configuration:
- Only traffic to VPN server's network ($VPN_NETWORK) goes through tunnel
- Internet traffic uses your regular connection
- Prevents routing all traffic through VPN server

Troubleshooting:
- Ensure openvpn-systemd-resolved is installed for DNS management
- Check: ip route | grep $VPN_NETWORK (should show route when connected)
- Verify: systemctl status NetworkManager
EOF
            ;;
        macos)
            cat > "$instructions_file" << EOF
OpenVPN Setup Instructions for macOS
===================================

Recommended Client: Tunnelblick (Free, Open Source)
Download: https://tunnelblick.net/

Setup Steps:
1. Download and install Tunnelblick
2. Double-click ${client_name}-macos.ovpn
3. Choose "I have configuration files"
4. Select "Only me" or "All users" 
5. Enter admin password when prompted
6. Connect from Tunnelblick menu bar icon

Alternative: OpenVPN Connect (Official)
1. Download from Mac App Store
2. Open app and import ${client_name}-macos.ovpn
3. Connect from the application

Split Tunneling Configuration:
- Only routes traffic to VPN server's network ($VPN_NETWORK)
- Internet browsing uses your regular connection
- Optimized for accessing server resources without routing all traffic

Troubleshooting:
- Allow Tunnelblick in System Preferences > Security & Privacy
- Check route table: netstat -rn | grep $VPN_NETWORK
- Ensure "Route all traffic" is NOT enabled in Tunnelblick
EOF
            ;;
        android)
            cat > "$instructions_file" << EOF
OpenVPN Setup Instructions for Android
=====================================

Recommended Client: OpenVPN for Android (Arne Schwabe)
Download: Google Play Store (de.blinkt.openvpn)

Setup Steps:
1. Install "OpenVPN for Android" from Play Store
2. Transfer ${client_name}-android.ovpn to your device:
   - Email attachment (tap to download)
   - Google Drive/Dropbox (share to OpenVPN app)
   - USB transfer to Downloads folder
3. Open OpenVPN for Android
4. Tap "+" (Import Profile)
5. Select "Import" and choose ${client_name}-android.ovpn
6. Tap profile name and then "Connect"

Split Tunneling Features:
- Only VPN server network ($VPN_NETWORK) traffic uses tunnel
- Regular internet apps use mobile/WiFi connection
- Built-in per-app VPN control available in app settings
- No battery drain from routing all internet traffic

Troubleshooting:
- Grant VPN permission when prompted (required)
- Disable battery optimization: Settings > Battery > OpenVPN
- Check "Allowed Apps" in OpenVPN settings for split tunneling
- Verify connection: Settings > Status shows connected VPN
EOF
            ;;
        ios)
            cat > "$instructions_file" << EOF
OpenVPN Setup Instructions for iOS
=================================

Recommended Client: OpenVPN Connect (Official)
Download: App Store (OpenVPN Inc.)

Setup Steps:
1. Install "OpenVPN Connect" from App Store
2. Transfer ${client_name}-ios.ovpn to iOS device:
   - Email to yourself, tap attachment, select "Copy to OpenVPN"
   - AirDrop from Mac (share with OpenVPN Connect)
   - Save to Files app, share with OpenVPN Connect
3. Open OpenVPN Connect app
4. Profile should appear automatically, tap "ADD"
5. Tap the toggle switch to connect

Split Tunneling Configuration:
- Only traffic to VPN server's network ($VPN_NETWORK) routed through tunnel
- Safari, apps, and internet use regular cellular/WiFi
- Optimized for accessing server resources without full tunnel
- Battery efficient as internet traffic not routed through VPN

Troubleshooting:
- Allow VPN configuration in Settings when prompted
- Check: Settings > General > VPN & Device Management (should show profile)
- Verify: Settings > VPN (should show connected status)
- Reset network settings if connection issues persist
EOF
            ;;
    esac
    
    if [[ -f "$instructions_file" ]]; then
        print_success "Setup instructions created: $instructions_file"
    fi
}

# Main execution
main() {
    print_header
    
    # Parse command line arguments
    CLIENT_NAME="$1"
    CUSTOM_IP="$2"
    OS_CHOICE="$3"
    
    # Validate environment
    validate_environment
    
    # Get client name
    get_client_name "$CLIENT_NAME"
    
    # Get server IP
    get_server_ip "$CUSTOM_IP"
    
    # Show OS selection if not provided
    if [[ -z "$OS_CHOICE" ]]; then
        show_os_menu
        OS_CHOICE="$os_choice"
    fi
    
    # Generate certificate
    generate_certificate "$CLIENT_NAME"
    
    # Create OS-specific configuration
    case $OS_CHOICE in
        1)
            create_windows_config "$CLIENT_NAME"
            create_setup_instructions "$CLIENT_NAME" "windows"
            OS_NAME="Windows"
            ;;
        2)
            create_linux_config "$CLIENT_NAME"
            create_setup_instructions "$CLIENT_NAME" "linux"
            OS_NAME="Linux"
            ;;
        3)
            create_macos_config "$CLIENT_NAME"
            create_setup_instructions "$CLIENT_NAME" "macos"
            OS_NAME="macOS"
            ;;
        4)
            create_android_config "$CLIENT_NAME"
            create_setup_instructions "$CLIENT_NAME" "android"
            OS_NAME="Android"
            ;;
        5)
            create_ios_config "$CLIENT_NAME"
            create_setup_instructions "$CLIENT_NAME" "ios"
            OS_NAME="iOS"
            ;;
        6)
            create_generic_config "$CLIENT_NAME"
            OS_NAME="Generic"
            ;;
        *)
            print_error "Invalid choice. Please select 1-6."
            exit 1
            ;;
    esac
    
    echo ""
    print_success "Client configuration completed!"
    echo -e "${GREEN}===============================================${NC}"
    echo -e "${GREEN}Client:${NC} $CLIENT_NAME"
    echo -e "${GREEN}OS:${NC} $OS_NAME"
    echo -e "${GREEN}Server IP:${NC} $SERVER_IP"
    echo -e "${GREEN}Port:${NC} $VPN_PORT/$VPN_PROTOCOL"
    echo -e "${GREEN}VPN Network:${NC} $VPN_NETWORK (split tunneling)"
    echo -e "${GREEN}Output Directory:${NC} $CLIENT_DIR"
    echo -e "${GREEN}===============================================${NC}"
    echo -e "${CYAN}Configuration Details:${NC}"
    echo "• Split tunneling enabled (internet stays local)"
    echo "• Only VPN server network traffic routed through tunnel"
    echo "• Embedded certificates for easy deployment"
    echo "• Optimized for Linux server environment"
    
    if [[ $OS_CHOICE != 6 ]]; then
        print_status "Setup instructions included in the output directory"
    fi
    print_status "Ensure port $VPN_PORT/$VPN_PROTOCOL is forwarded on your router"
}

# Show usage if no arguments and not interactive
if [[ $# -eq 0 && ! -t 0 ]]; then
    echo "Usage: $0 [client-name] [server-ip] [os-choice]"
    echo ""
    echo "Arguments:"
    echo "  client-name   Name for the client certificate"
    echo "  server-ip     Server IP address (or 'auto' to detect)"
    echo "  os-choice     OS choice (1-6, optional - will prompt if not provided)"
    echo ""
    echo "OS Choices:"
    echo "  1 - Windows"
    echo "  2 - Linux" 
    echo "  3 - macOS"
    echo "  4 - Android"
    echo "  5 - iOS"
    echo "  6 - Generic"
    echo ""
    echo "Examples:"
    echo "  $0                           # Interactive mode"
    echo "  $0 laptop auto 1             # Windows client with auto-detected IP"
    echo "  $0 phone YOUR.SERVER.IP 4    # Android client with specific IP"
    exit 1
fi

# Run main function
main "$@"