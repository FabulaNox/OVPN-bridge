#!/usr/bin/env python3
"""
Microsoft Teams Webhook Integration for OVPN-bridge
Provides a secure REST API to manage OpenVPN certificates through Microsoft Teams
"""

import os
import sys
import json
import logging
import subprocess
import hmac
import hashlib
from datetime import datetime
from pathlib import Path
from flask import Flask, request, jsonify
from typing import Dict, List, Optional, Tuple

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)

# Configuration
SCRIPT_DIR = Path(__file__).parent.resolve()
CONFIG_FILE = SCRIPT_DIR / "config.conf"
PKI_DIR_NAME = "openvpn-ca"
CLIENT_OUTPUT_DIR = "clients"

# Load webhook secret from environment
WEBHOOK_SECRET = os.environ.get('TEAMS_WEBHOOK_SECRET', '')


class CertificateManager:
    """Manages OpenVPN certificate operations"""
    
    def __init__(self, script_dir: Path):
        self.script_dir = script_dir
        self.pki_dir = script_dir / PKI_DIR_NAME
        self.client_dir = script_dir / CLIENT_OUTPUT_DIR
        self.generate_script = script_dir / "generate-minimal-client.sh"
        
    def generate_certificate(self, client_name: str, custom_ip: Optional[str] = None) -> Dict:
        """
        Generate a new client certificate
        
        Args:
            client_name: Name of the client
            custom_ip: Optional custom IP address for the client
            
        Returns:
            Dict with status and message
        """
        try:
            # Validate client name (alphanumeric and hyphens only)
            if not client_name.replace('-', '').replace('_', '').isalnum():
                return {
                    'success': False,
                    'message': f'Invalid client name: {client_name}. Use only alphanumeric characters, hyphens, and underscores.'
                }
            
            # Check if PKI directory exists
            if not self.pki_dir.exists():
                return {
                    'success': False,
                    'message': 'OpenVPN CA not initialized. Please run deploy-minimal.sh first.'
                }
            
            # Check if client already exists
            client_cert = self.pki_dir / "pki" / "issued" / f"{client_name}.crt"
            if client_cert.exists():
                return {
                    'success': False,
                    'message': f'Certificate for {client_name} already exists. Use revoke first if you want to recreate it.'
                }
            
            # Build command
            cmd = [str(self.generate_script), client_name]
            if custom_ip:
                cmd.append(custom_ip)
            
            # Execute certificate generation
            result = subprocess.run(
                cmd,
                cwd=str(self.script_dir),
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0:
                ovpn_file = self.client_dir / f"{client_name}.ovpn"
                return {
                    'success': True,
                    'message': f'Certificate generated successfully for {client_name}',
                    'client_name': client_name,
                    'ovpn_file': str(ovpn_file),
                    'output': result.stdout
                }
            else:
                return {
                    'success': False,
                    'message': f'Failed to generate certificate: {result.stderr}',
                    'output': result.stderr
                }
                
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'message': 'Certificate generation timed out'
            }
        except Exception as e:
            logger.exception("Error generating certificate")
            return {
                'success': False,
                'message': f'Error: {str(e)}'
            }
    
    def list_certificates(self) -> Dict:
        """
        List all active certificates
        
        Returns:
            Dict with list of certificates and their details
        """
        try:
            if not self.pki_dir.exists():
                return {
                    'success': False,
                    'message': 'OpenVPN CA not initialized'
                }
            
            issued_dir = self.pki_dir / "pki" / "issued"
            revoked_dir = self.pki_dir / "pki" / "revoked" / "certs_by_serial"
            
            if not issued_dir.exists():
                return {
                    'success': True,
                    'certificates': [],
                    'message': 'No certificates found'
                }
            
            certificates = []
            revoked_certs = set()
            
            # Get list of revoked certificates
            if revoked_dir.exists():
                revoked_certs = {f.stem for f in revoked_dir.glob("*.crt")}
            
            # List all issued certificates
            for cert_file in issued_dir.glob("*.crt"):
                cert_name = cert_file.stem
                
                # Skip server certificate
                if cert_name == "server":
                    continue
                
                # Get certificate details using openssl
                try:
                    cmd = [
                        "openssl", "x509",
                        "-in", str(cert_file),
                        "-noout",
                        "-subject", "-dates", "-serial"
                    ]
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                    
                    if result.returncode == 0:
                        # Parse output
                        lines = result.stdout.strip().split('\n')
                        info = {}
                        for line in lines:
                            if '=' in line:
                                key, value = line.split('=', 1)
                                info[key.strip()] = value.strip()
                        
                        # Check if revoked
                        is_revoked = cert_name in revoked_certs or any(
                            cert_name in str(f) for f in (revoked_dir.glob("*") if revoked_dir.exists() else [])
                        )
                        
                        certificates.append({
                            'name': cert_name,
                            'subject': info.get('subject', 'N/A'),
                            'not_before': info.get('notBefore', 'N/A'),
                            'not_after': info.get('notAfter', 'N/A'),
                            'serial': info.get('serial', 'N/A'),
                            'status': 'revoked' if is_revoked else 'active',
                            'ovpn_file': str(self.client_dir / f"{cert_name}.ovpn") if (self.client_dir / f"{cert_name}.ovpn").exists() else None
                        })
                except subprocess.TimeoutExpired:
                    logger.warning(f"Timeout getting details for {cert_name}")
                    certificates.append({
                        'name': cert_name,
                        'status': 'unknown'
                    })
            
            return {
                'success': True,
                'certificates': certificates,
                'total': len(certificates),
                'active': sum(1 for c in certificates if c.get('status') == 'active'),
                'revoked': sum(1 for c in certificates if c.get('status') == 'revoked')
            }
            
        except Exception as e:
            logger.exception("Error listing certificates")
            return {
                'success': False,
                'message': f'Error: {str(e)}'
            }
    
    def revoke_certificate(self, client_name: str) -> Dict:
        """
        Revoke a client certificate
        
        Args:
            client_name: Name of the client certificate to revoke
            
        Returns:
            Dict with status and message
        """
        try:
            # Validate client name
            if not client_name.replace('-', '').replace('_', '').isalnum():
                return {
                    'success': False,
                    'message': f'Invalid client name: {client_name}'
                }
            
            # Check if PKI directory exists
            if not self.pki_dir.exists():
                return {
                    'success': False,
                    'message': 'OpenVPN CA not initialized'
                }
            
            # Check if certificate exists
            client_cert = self.pki_dir / "pki" / "issued" / f"{client_name}.crt"
            if not client_cert.exists():
                return {
                    'success': False,
                    'message': f'Certificate for {client_name} not found'
                }
            
            # Revoke certificate using easyrsa
            easyrsa_script = self.pki_dir / "easyrsa"
            cmd = [str(easyrsa_script), "revoke", client_name]
            
            # Run revocation command with 'yes' input
            result = subprocess.run(
                cmd,
                cwd=str(self.pki_dir),
                input="yes\n",
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0 or "already revoked" in result.stdout.lower():
                # Generate updated CRL
                crl_cmd = [str(easyrsa_script), "gen-crl"]
                crl_result = subprocess.run(
                    crl_cmd,
                    cwd=str(self.pki_dir),
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                return {
                    'success': True,
                    'message': f'Certificate for {client_name} has been revoked',
                    'client_name': client_name,
                    'output': result.stdout
                }
            else:
                return {
                    'success': False,
                    'message': f'Failed to revoke certificate: {result.stderr}',
                    'output': result.stderr
                }
                
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'message': 'Certificate revocation timed out'
            }
        except Exception as e:
            logger.exception("Error revoking certificate")
            return {
                'success': False,
                'message': f'Error: {str(e)}'
            }


def verify_signature(request_data: str, signature: str) -> bool:
    """
    Verify HMAC signature for webhook security
    
    Args:
        request_data: Raw request body
        signature: Signature from request header
        
    Returns:
        True if signature is valid
    """
    if not WEBHOOK_SECRET:
        logger.warning("No webhook secret configured, skipping signature verification")
        return True
    
    expected_signature = hmac.new(
        WEBHOOK_SECRET.encode(),
        request_data.encode(),
        hashlib.sha256
    ).hexdigest()
    
    return hmac.compare_digest(signature, expected_signature)


def format_teams_message(title: str, message: str, color: str = "0078D4", facts: Optional[List[Dict]] = None) -> Dict:
    """
    Format a message for Microsoft Teams adaptive card
    
    Args:
        title: Message title
        message: Message content
        color: Theme color (hex without #)
        facts: Optional list of facts to display
        
    Returns:
        Teams message card JSON
    """
    card = {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "themeColor": color,
        "title": title,
        "text": message
    }
    
    if facts:
        card["sections"] = [{
            "facts": facts
        }]
    
    return card


# Certificate manager instance
cert_manager = CertificateManager(SCRIPT_DIR)


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'version': '1.0.0'
    })


@app.route('/webhook/teams', methods=['POST'])
def teams_webhook():
    """
    Main Microsoft Teams webhook endpoint
    Handles incoming commands from Teams
    """
    try:
        # Get request data
        request_data = request.get_data(as_text=True)
        
        # Verify signature if secret is configured
        if WEBHOOK_SECRET:
            signature = request.headers.get('X-Webhook-Signature', '')
            if not verify_signature(request_data, signature):
                logger.warning("Invalid webhook signature")
                return jsonify({'error': 'Invalid signature'}), 401
        
        # Parse JSON payload
        payload = request.get_json()
        
        if not payload:
            return jsonify({'error': 'Invalid JSON payload'}), 400
        
        # Extract command and parameters from Teams message
        text = payload.get('text', '').strip()
        
        if not text:
            return jsonify({
                'response': format_teams_message(
                    'OVPN Bridge Help',
                    'Available commands:\n\n'
                    '**generate <client-name> [ip]** - Generate new certificate\n'
                    '**list** - List all certificates\n'
                    '**status** - Show active certificates\n'
                    '**revoke <client-name>** - Revoke a certificate\n'
                    '**help** - Show this help message',
                    color="0078D4"
                )
            })
        
        # Parse command
        parts = text.split()
        command = parts[0].lower()
        
        # Handle commands
        if command == 'generate':
            if len(parts) < 2:
                return jsonify({
                    'response': format_teams_message(
                        'Error',
                        'Usage: generate <client-name> [ip]',
                        color="E81123"
                    )
                })
            
            client_name = parts[1]
            custom_ip = parts[2] if len(parts) > 2 else None
            
            result = cert_manager.generate_certificate(client_name, custom_ip)
            
            if result['success']:
                facts = [
                    {'name': 'Client', 'value': client_name},
                    {'name': 'Status', 'value': 'Generated'},
                    {'name': 'File', 'value': result.get('ovpn_file', 'N/A')}
                ]
                return jsonify({
                    'response': format_teams_message(
                        'Certificate Generated',
                        result['message'],
                        color="107C10",
                        facts=facts
                    )
                })
            else:
                return jsonify({
                    'response': format_teams_message(
                        'Generation Failed',
                        result['message'],
                        color="E81123"
                    )
                })
        
        elif command in ['list', 'status']:
            result = cert_manager.list_certificates()
            
            if result['success']:
                if result['total'] == 0:
                    return jsonify({
                        'response': format_teams_message(
                            'Certificate Status',
                            'No certificates found',
                            color="FFB900"
                        )
                    })
                
                # Format certificate list
                cert_list = []
                for cert in result['certificates']:
                    status_icon = "✅" if cert['status'] == 'active' else "❌"
                    cert_list.append(f"{status_icon} **{cert['name']}** - {cert['status']}")
                
                message = '\n'.join(cert_list)
                facts = [
                    {'name': 'Total', 'value': str(result['total'])},
                    {'name': 'Active', 'value': str(result['active'])},
                    {'name': 'Revoked', 'value': str(result['revoked'])}
                ]
                
                return jsonify({
                    'response': format_teams_message(
                        'Certificate Status',
                        message,
                        color="0078D4",
                        facts=facts
                    )
                })
            else:
                return jsonify({
                    'response': format_teams_message(
                        'Error',
                        result['message'],
                        color="E81123"
                    )
                })
        
        elif command == 'revoke':
            if len(parts) < 2:
                return jsonify({
                    'response': format_teams_message(
                        'Error',
                        'Usage: revoke <client-name>',
                        color="E81123"
                    )
                })
            
            client_name = parts[1]
            result = cert_manager.revoke_certificate(client_name)
            
            if result['success']:
                facts = [
                    {'name': 'Client', 'value': client_name},
                    {'name': 'Status', 'value': 'Revoked'}
                ]
                return jsonify({
                    'response': format_teams_message(
                        'Certificate Revoked',
                        result['message'],
                        color="FFB900",
                        facts=facts
                    )
                })
            else:
                return jsonify({
                    'response': format_teams_message(
                        'Revocation Failed',
                        result['message'],
                        color="E81123"
                    )
                })
        
        elif command == 'help':
            return jsonify({
                'response': format_teams_message(
                    'OVPN Bridge Help',
                    'Available commands:\n\n'
                    '**generate <client-name> [ip]** - Generate new certificate\n'
                    '**list** - List all certificates\n'
                    '**status** - Show active certificates\n'
                    '**revoke <client-name>** - Revoke a certificate\n'
                    '**help** - Show this help message',
                    color="0078D4"
                )
            })
        
        else:
            return jsonify({
                'response': format_teams_message(
                    'Unknown Command',
                    f'Unknown command: {command}\n\nType "help" for available commands.',
                    color="FFB900"
                )
            })
    
    except Exception as e:
        logger.exception("Error processing Teams webhook")
        return jsonify({
            'response': format_teams_message(
                'Error',
                f'An error occurred: {str(e)}',
                color="E81123"
            )
        }), 500


@app.route('/api/certificates', methods=['GET'])
def api_list_certificates():
    """REST API endpoint to list certificates"""
    result = cert_manager.list_certificates()
    return jsonify(result)


@app.route('/api/certificates', methods=['POST'])
def api_generate_certificate():
    """REST API endpoint to generate certificate"""
    data = request.get_json()
    
    if not data or 'client_name' not in data:
        return jsonify({'error': 'client_name is required'}), 400
    
    client_name = data['client_name']
    custom_ip = data.get('custom_ip')
    
    result = cert_manager.generate_certificate(client_name, custom_ip)
    status_code = 200 if result['success'] else 400
    
    return jsonify(result), status_code


@app.route('/api/certificates/<client_name>', methods=['DELETE'])
def api_revoke_certificate(client_name: str):
    """REST API endpoint to revoke certificate"""
    result = cert_manager.revoke_certificate(client_name)
    status_code = 200 if result['success'] else 400
    
    return jsonify(result), status_code


if __name__ == '__main__':
    # Get configuration from environment
    host = os.environ.get('WEBHOOK_HOST', '0.0.0.0')
    port = int(os.environ.get('WEBHOOK_PORT', '5000'))
    debug = os.environ.get('WEBHOOK_DEBUG', 'False').lower() == 'true'
    
    logger.info(f"Starting Teams Webhook Server on {host}:{port}")
    logger.info(f"Script directory: {SCRIPT_DIR}")
    logger.info(f"PKI directory: {SCRIPT_DIR / PKI_DIR_NAME}")
    
    if WEBHOOK_SECRET:
        logger.info("Webhook signature verification enabled")
    else:
        logger.warning("No webhook secret configured - signature verification disabled")
    
    app.run(host=host, port=port, debug=debug)
