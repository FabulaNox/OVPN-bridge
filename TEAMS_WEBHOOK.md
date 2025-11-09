# Microsoft Teams Webhook Integration

This document describes the Microsoft Teams webhook integration for OVPN-bridge, which allows you to manage OpenVPN certificates directly from Microsoft Teams.

## Features

- **Generate Certificates**: Create new client certificates through Teams messages
- **Check Status**: View all active and revoked certificates
- **Revoke Certificates**: Revoke client certificates in real-time
- **Secure Communication**: HMAC-based signature verification for webhook security
- **REST API**: Additional REST endpoints for programmatic access

## Architecture

The integration consists of a Python Flask-based webhook server that:
1. Receives commands from Microsoft Teams
2. Executes certificate operations using existing bash scripts
3. Formats and sends responses back to Teams as adaptive cards

## Prerequisites

- Python 3.7 or higher
- OpenVPN server deployed using `deploy-minimal.sh`
- Microsoft Teams with Incoming Webhook configured
- Public-facing server or tunneling solution (e.g., ngrok) for webhook endpoint

## Installation

### 1. Install Python Dependencies

```bash
cd /path/to/OVPN-bridge
pip3 install -r requirements.txt
```

### 2. Set Up Environment Variables

Create a `.env` file or export the following variables:

```bash
# Required: Teams webhook secret for signature verification
export TEAMS_WEBHOOK_SECRET="your-secret-key-here"

# Optional: Server configuration
export WEBHOOK_HOST="0.0.0.0"
export WEBHOOK_PORT="5000"
export WEBHOOK_DEBUG="False"
```

**Security Note**: The `TEAMS_WEBHOOK_SECRET` should be a strong, randomly generated string. This is used to verify that webhook requests are coming from your Teams connector.

### 3. Configure Microsoft Teams

#### Create an Incoming Webhook in Teams

1. Open Microsoft Teams and navigate to the channel where you want to receive notifications
2. Click the three dots (•••) next to the channel name
3. Select "Connectors" or "Workflows"
4. Search for "Incoming Webhook" and click "Configure"
5. Give your webhook a name (e.g., "OVPN Bridge")
6. Copy the webhook URL provided by Teams (you'll use this later)
7. Click "Create"

#### Create an Outgoing Webhook (for Commands)

1. In Teams, go to Apps
2. Search for "Outgoing Webhook"
3. Click "Add to a team" and select your team
4. Configure the webhook:
   - **Name**: OVPN Bridge Bot
   - **Callback URL**: Your server's public URL + `/webhook/teams` (e.g., `https://your-domain.com/webhook/teams`)
   - **Description**: Manage OpenVPN certificates
   - **Security Token**: Copy this token - this is your `TEAMS_WEBHOOK_SECRET`
5. Click "Create"

### 4. Start the Webhook Server

```bash
cd /path/to/OVPN-bridge
python3 teams_webhook.py
```

Or run as a systemd service (recommended for production):

```bash
sudo cp teams-webhook.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable teams-webhook
sudo systemctl start teams-webhook
```

## Usage

### Teams Commands

Once the webhook is configured, you can use the following commands in Microsoft Teams by mentioning the bot:

#### Generate Certificate
```
@OVPN-Bridge generate laptop
@OVPN-Bridge generate phone 192.168.1.100
```

**Parameters:**
- `<client-name>`: Name for the client certificate (alphanumeric, hyphens, underscores only)
- `[ip]`: Optional custom IP address. If omitted, public IP is auto-detected

**Response:**
- Success: Certificate details and location of .ovpn file
- Error: Reason for failure (e.g., certificate already exists)

#### List Certificates
```
@OVPN-Bridge list
@OVPN-Bridge status
```

**Response:**
- List of all certificates with their status (active/revoked)
- Summary statistics (total, active, revoked)

#### Revoke Certificate
```
@OVPN-Bridge revoke laptop
```

**Parameters:**
- `<client-name>`: Name of the client certificate to revoke

**Response:**
- Success: Confirmation of revocation
- Error: Reason for failure (e.g., certificate not found)

#### Help
```
@OVPN-Bridge help
```

**Response:**
- List of all available commands with descriptions

### REST API Endpoints

The webhook server also provides REST API endpoints for programmatic access:

#### GET /health
Health check endpoint

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2025-11-09T16:42:28.089Z",
  "version": "1.0.0"
}
```

#### GET /api/certificates
List all certificates

**Response:**
```json
{
  "success": true,
  "certificates": [
    {
      "name": "laptop",
      "subject": "CN=laptop",
      "not_before": "Nov  9 00:00:00 2025 GMT",
      "not_after": "Nov  7 00:00:00 2035 GMT",
      "serial": "ABC123",
      "status": "active",
      "ovpn_file": "/path/to/clients/laptop.ovpn"
    }
  ],
  "total": 1,
  "active": 1,
  "revoked": 0
}
```

#### POST /api/certificates
Generate a new certificate

**Request:**
```json
{
  "client_name": "laptop",
  "custom_ip": "192.168.1.100"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Certificate generated successfully for laptop",
  "client_name": "laptop",
  "ovpn_file": "/path/to/clients/laptop.ovpn"
}
```

#### DELETE /api/certificates/<client_name>
Revoke a certificate

**Response:**
```json
{
  "success": true,
  "message": "Certificate for laptop has been revoked",
  "client_name": "laptop"
}
```

## Security Considerations

### 1. Webhook Signature Verification

The webhook server uses HMAC-SHA256 signature verification to ensure requests are authentic. Always set `TEAMS_WEBHOOK_SECRET` in production.

### 2. Network Security

- Run the webhook server behind a reverse proxy (nginx, Apache)
- Use HTTPS for all webhook communications
- Implement rate limiting to prevent abuse
- Consider using a VPN or IP whitelist to restrict access

### 3. Certificate Security

- The webhook server does not expose certificate private keys
- .ovpn files are stored locally and must be retrieved separately
- Consider implementing additional authentication for sensitive operations

### 4. Firewall Configuration

If using UFW, allow the webhook port:
```bash
sudo ufw allow 5000/tcp
```

## Production Deployment

### Using systemd

Create `/etc/systemd/system/teams-webhook.service`:

```ini
[Unit]
Description=OVPN Bridge Teams Webhook
After=network.target

[Service]
Type=simple
User=openvpn-admin
WorkingDirectory=/path/to/OVPN-bridge
Environment="TEAMS_WEBHOOK_SECRET=your-secret-here"
Environment="WEBHOOK_HOST=0.0.0.0"
Environment="WEBHOOK_PORT=5000"
ExecStart=/usr/bin/python3 /path/to/OVPN-bridge/teams_webhook.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Then:
```bash
sudo systemctl daemon-reload
sudo systemctl enable teams-webhook
sudo systemctl start teams-webhook
```

### Using Docker

Create `Dockerfile`:

```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install OpenSSL and OpenVPN tools
RUN apt-get update && \
    apt-get install -y openssl openvpn easy-rsa && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Copy application files
COPY . .

# Expose port
EXPOSE 5000

# Run the webhook server
CMD ["python3", "teams_webhook.py"]
```

Build and run:
```bash
docker build -t ovpn-bridge-webhook .
docker run -d \
  -p 5000:5000 \
  -e TEAMS_WEBHOOK_SECRET=your-secret \
  -v $(pwd)/openvpn-ca:/app/openvpn-ca \
  -v $(pwd)/clients:/app/clients \
  --name ovpn-webhook \
  ovpn-bridge-webhook
```

### Using Reverse Proxy (nginx)

Configure nginx to proxy requests to the webhook server:

```nginx
server {
    listen 443 ssl;
    server_name your-domain.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location /webhook {
        proxy_pass http://localhost:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /api {
        proxy_pass http://localhost:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## Troubleshooting

### Issue: Webhook not receiving requests

**Symptoms:**
- Teams shows "Unable to reach app" error
- No logs in webhook server

**Solutions:**
1. Verify the callback URL is correct and publicly accessible
2. Check firewall rules: `sudo ufw status`
3. Test webhook endpoint: `curl http://your-server:5000/health`
4. Check webhook server logs: `journalctl -u teams-webhook -f`
5. Verify the server is listening: `netstat -tulpn | grep 5000`

### Issue: Signature verification fails

**Symptoms:**
- Webhook returns "Invalid signature" error
- HTTP 401 responses in Teams

**Solutions:**
1. Verify `TEAMS_WEBHOOK_SECRET` matches the security token from Teams
2. Check that the secret is properly set in environment variables
3. Restart the webhook server after changing environment variables

### Issue: Certificate generation fails

**Symptoms:**
- "OpenVPN CA not initialized" error
- "Failed to generate certificate" error

**Solutions:**
1. Verify OpenVPN server is deployed: `ls -la openvpn-ca/`
2. Run deployment script: `./deploy-minimal.sh`
3. Check file permissions: `ls -la generate-minimal-client.sh`
4. Make scripts executable: `chmod +x *.sh`
5. Check logs for detailed error messages

### Issue: Permission denied errors

**Symptoms:**
- Cannot access certificate files
- Cannot execute bash scripts

**Solutions:**
1. Run webhook server with appropriate user privileges
2. Ensure script files are executable: `chmod +x *.sh`
3. Check directory permissions: `ls -la openvpn-ca/ clients/`
4. Consider running as sudo or dedicated service user

### Issue: Timeout errors

**Symptoms:**
- Operations take too long and fail
- No response from webhook

**Solutions:**
1. Check system resources: `top`, `df -h`
2. Verify OpenSSL is installed: `openssl version`
3. Increase timeout values in webhook code
4. Check for slow network connections

### Debugging

Enable debug mode for detailed logging:

```bash
export WEBHOOK_DEBUG="True"
python3 teams_webhook.py
```

Check webhook logs:
```bash
# If running as systemd service
sudo journalctl -u teams-webhook -f

# If running directly
# Logs will appear in console output
```

Test webhook locally without Teams:
```bash
# Test health endpoint
curl http://localhost:5000/health

# Test list certificates
curl http://localhost:5000/api/certificates

# Test generate certificate
curl -X POST http://localhost:5000/api/certificates \
  -H "Content-Type: application/json" \
  -d '{"client_name": "test-client"}'
```

## API Response Codes

| Code | Description |
|------|-------------|
| 200 | Success |
| 400 | Bad request (invalid parameters) |
| 401 | Unauthorized (invalid signature) |
| 500 | Internal server error |

## Limitations

- Certificate private keys are not exposed through the API
- Client .ovpn files must be retrieved from the server filesystem
- Certificate updates (changing IP) require manual script execution
- No built-in authentication beyond webhook signature verification

## Future Enhancements

Potential improvements for future versions:

- File upload capability for .ovpn files
- Certificate renewal automation
- Email notifications for certificate operations
- Web UI for certificate management
- Integration with other chat platforms (Slack, Discord)
- Certificate expiration monitoring and alerts
- Audit logging for all operations

## Support

For issues and questions:
1. Check this documentation
2. Review troubleshooting section
3. Check webhook server logs
4. Open an issue on GitHub

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License

This integration follows the same license as the OVPN-bridge project.
