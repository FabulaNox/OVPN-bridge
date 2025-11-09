#!/usr/bin/env python3
"""
Example script demonstrating how to interact with the OVPN-bridge Teams Webhook API

This script shows how to:
1. List all certificates
2. Generate a new certificate
3. Revoke a certificate

Usage:
    python3 example_webhook_usage.py
"""

import requests
import json

# Configuration
BASE_URL = "http://localhost:5000"
API_ENDPOINT = f"{BASE_URL}/api"


def list_certificates():
    """List all certificates"""
    print("\n📋 Listing all certificates...")
    response = requests.get(f"{API_ENDPOINT}/certificates")
    
    if response.status_code == 200:
        data = response.json()
        if data['success']:
            print(f"   Total certificates: {data.get('total', 0)}")
            print(f"   Active: {data.get('active', 0)}")
            print(f"   Revoked: {data.get('revoked', 0)}")
            
            for cert in data.get('certificates', []):
                status_icon = "✅" if cert['status'] == 'active' else "❌"
                print(f"   {status_icon} {cert['name']} - {cert['status']}")
        else:
            print(f"   ⚠️  {data.get('message')}")
    else:
        print(f"   ❌ Error: {response.status_code}")


def generate_certificate(client_name, custom_ip=None):
    """Generate a new certificate"""
    print(f"\n🔐 Generating certificate for '{client_name}'...")
    
    payload = {'client_name': client_name}
    if custom_ip:
        payload['custom_ip'] = custom_ip
    
    response = requests.post(
        f"{API_ENDPOINT}/certificates",
        json=payload
    )
    
    if response.status_code == 200:
        data = response.json()
        if data['success']:
            print(f"   ✅ {data['message']}")
            print(f"   📄 OVPN file: {data.get('ovpn_file')}")
        else:
            print(f"   ⚠️  {data['message']}")
    else:
        print(f"   ❌ Error: {response.status_code}")


def revoke_certificate(client_name):
    """Revoke a certificate"""
    print(f"\n❌ Revoking certificate for '{client_name}'...")
    
    response = requests.delete(f"{API_ENDPOINT}/certificates/{client_name}")
    
    if response.status_code == 200:
        data = response.json()
        if data['success']:
            print(f"   ✅ {data['message']}")
        else:
            print(f"   ⚠️  {data['message']}")
    else:
        print(f"   ❌ Error: {response.status_code}")


def check_health():
    """Check if the webhook server is running"""
    print("🏥 Checking webhook server health...")
    try:
        response = requests.get(f"{BASE_URL}/health", timeout=5)
        if response.status_code == 200:
            data = response.json()
            print(f"   ✅ Server is healthy (version {data.get('version')})")
            return True
        else:
            print(f"   ⚠️  Server returned status {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"   ❌ Cannot connect to server: {e}")
        print(f"   💡 Make sure the webhook server is running:")
        print(f"      python3 teams_webhook.py")
        return False


def main():
    """Main demonstration function"""
    print("=" * 60)
    print("OVPN-Bridge Webhook API Example")
    print("=" * 60)
    
    # Check if server is running
    if not check_health():
        return
    
    # List certificates
    list_certificates()
    
    # Example: Generate a certificate (commented out to avoid errors)
    # Uncomment the following line to test certificate generation:
    # generate_certificate('example-client', '192.168.1.100')
    
    # Example: Revoke a certificate (commented out to avoid errors)
    # Uncomment the following line to test certificate revocation:
    # revoke_certificate('example-client')
    
    print("\n" + "=" * 60)
    print("Example completed!")
    print("=" * 60)
    print("\n💡 To use this script:")
    print("   1. Start the webhook server: python3 teams_webhook.py")
    print("   2. Deploy OpenVPN server: ./deploy-minimal.sh")
    print("   3. Uncomment example commands in this script")
    print("   4. Run: python3 example_webhook_usage.py")


if __name__ == '__main__':
    main()
