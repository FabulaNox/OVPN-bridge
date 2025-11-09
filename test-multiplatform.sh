#!/bin/bash

# Quick test script for multi-platform client generation
# This script demonstrates the different OS configurations

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLIENT_SCRIPT="$SCRIPT_DIR/generate-client-multiplatform.sh"

echo "=========================================="
echo " OVPN-Bridge Multi-Platform Test"
echo "=========================================="

# Check if deployment is ready
if [[ ! -d "$SCRIPT_DIR/openvpn-ca" ]]; then
    echo "[ERROR] PKI not found. Please run ./deploy-minimal.sh first"
    exit 1
fi

echo "Creating test clients for all platforms..."
echo ""

# Test server IP
TEST_IP="192.168.1.100"

# Generate configs for each platform
declare -a platforms=("windows" "linux" "macos" "android" "ios" "generic")
declare -a choices=("1" "2" "3" "4" "5" "6")

for i in "${!platforms[@]}"; do
    platform="${platforms[$i]}"
    choice="${choices[$i]}"
    
    echo "Creating ${platform} configuration..."
    $CLIENT_SCRIPT "test-${platform}" "$TEST_IP" "$choice"
    echo ""
done

echo "=========================================="
echo "All platform configurations created!"
echo "=========================================="
echo ""
echo "Generated files:"
ls -la "$SCRIPT_DIR/clients/test-"*
echo ""
echo "Setup instructions:"
ls -la "$SCRIPT_DIR/clients/test-"*setup.txt 2>/dev/null || echo "No setup files found"