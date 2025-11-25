# Simple SSL Setup for Device Proxy on Port 443

This guide shows how to configure Device Proxy to run on HTTPS port 443 only, without using port 80.

## Overview

- **Device Proxy**: `https://devicehub.qa.fortinet-us.com` (port 443)
- **STF Server**: Runs independently on `http://10.160.13.118/stf` (port 80)
- **No HTTP redirect**: Device Proxy only listens on port 443

## Architecture

```
Internet (HTTPS/443)
         ↓
    Nginx Reverse Proxy
    (SSL Termination)
         ↓
    Device Proxy Hub
    (Docker: port 8080)
```

## Setup Steps

### 1. Install Nginx on Host Server

```bash
sudo apt update && sudo apt install nginx
```

### 2. Place SSL Certificates

```bash
# Copy your SSL certificate and key to the host
sudo mkdir -p /etc/ssl/certs /etc/ssl/private

sudo cp /path/to/your/certificate.crt /etc/ssl/certs/devicehub.crt
sudo cp /path/to/your/privatekey.key /etc/ssl/private/devicehub.key

# Set proper permissions
sudo chmod 644 /etc/ssl/certs/devicehub.crt
sudo chmod 600 /etc/ssl/private/devicehub.key
```

### 3. Configure Nginx Reverse Proxy

```bash
# Copy the reverse proxy configuration
sudo cp nginx-reverse-proxy.conf /etc/nginx/sites-available/devicehub

# Enable the site
sudo ln -s /etc/nginx/sites-available/devicehub /etc/nginx/sites-enabled/

# Remove default site (optional)
sudo rm /etc/nginx/sites-enabled/default

# Test the configuration
sudo nginx -t

# If test passes, reload nginx
sudo systemctl reload nginx
```

### 4. Deploy Docker Containers

```bash
# Stop existing containers
docker-compose down

# Rebuild and start
docker-compose up -d --build
```

### 5. Verify SSL is Working

```bash
# Test HTTPS access
curl -k https://devicehub.qa.fortinet-us.com/nodes

# Should return JSON with node data
```

### 6. Update Browser Bookmarks

Access the Device Proxy Hub at:
```
https://devicehub.qa.fortinet-us.com
```

## Port Configuration

After setup:
- **Port 443 (HTTPS)**: Device Proxy Hub (SSL enabled)
- **Port 8080 (HTTP)**: Docker container internal port (not exposed externally)
- **Port 8090 (HTTP)**: Backend API internal port (not exposed externally)

Port 80 is **not used** by Device Proxy.

## STF Integration

Your STF server configuration in `backend/.env` or node resources should point to:

```bash
# backend/.env
STF_BASE_URL=http://10.160.13.118/stf
```

Or in node resources:
```json
{
  "stf": {
    "base_url": "http://10.160.13.118/stf",
    "control_path_template": "/#!/control/{udid}",
    "enabled": true
  }
}
```

### Optional: Proxy STF Through Same Domain

If you want to access STF through the same domain (e.g., `https://devicehub.qa.fortinet-us.com/stf/`), uncomment the STF proxy sections in `nginx-reverse-proxy.conf` and update your STF configuration:

```bash
# backend/.env
STF_BASE_URL=https://devicehub.qa.fortinet-us.com/stf
```

## Troubleshooting

### Check Nginx Status
```bash
sudo systemctl status nginx
```

### Check Nginx Logs
```bash
sudo tail -f /var/log/nginx/error.log
sudo tail -f /var/log/nginx/devicehub_error.log
```

### Check Docker Containers
```bash
docker-compose ps
docker-compose logs frontend
```

### Verify Port 443 is Listening
```bash
sudo netstat -tlnp | grep :443
# or
sudo ss -tlnp | grep :443
```

### Test SSL Certificate
```bash
openssl s_client -connect devicehub.qa.fortinet-us.com:443 -servername devicehub.qa.fortinet-us.com
```

### Common Issues

**1. Port 443 already in use**
```bash
# Find what's using port 443
sudo lsof -i :443

# Stop the conflicting service
sudo systemctl stop <service-name>
```

**2. Certificate errors**
- Verify certificate paths in nginx config
- Check file permissions (cert: 644, key: 600)
- Ensure certificate matches domain name

**3. 502 Bad Gateway**
- Ensure Docker containers are running: `docker-compose ps`
- Check if port 8080 is accessible: `curl http://localhost:8080`
- Review nginx error logs

**4. Connection refused**
- Check firewall allows port 443: `sudo ufw status`
- Open port if needed: `sudo ufw allow 443/tcp`

## Using Self-Signed Certificates (Development/Testing)

If you don't have a CA-signed certificate, create a self-signed certificate:

```bash
# Generate self-signed certificate (valid for 365 days)
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /etc/ssl/private/devicehub.key \
  -out /etc/ssl/certs/devicehub.crt \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=devicehub.qa.fortinet-us.com"

# Set permissions
sudo chmod 644 /etc/ssl/certs/devicehub.crt
sudo chmod 600 /etc/ssl/private/devicehub.key
```

**Note**: Self-signed certificates will trigger browser warnings. For production, use certificates from a trusted Certificate Authority or Let's Encrypt.

## Security Enhancements (Optional)

### Enable HSTS
Add to the server block in `/etc/nginx/sites-available/devicehub`:
```nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
```

### Hide Nginx Version
Add to http block in `/etc/nginx/nginx.conf`:
```nginx
server_tokens off;
```

### Rate Limiting
Add to http block in `/etc/nginx/nginx.conf`:
```nginx
limit_req_zone $binary_remote_addr zone=devicehub:10m rate=10r/s;
```

Then add to server block:
```nginx
limit_req zone=devicehub burst=20;
```

## Monitoring

### Check SSL Certificate Expiry
```bash
echo | openssl s_client -servername devicehub.qa.fortinet-us.com \
  -connect devicehub.qa.fortinet-us.com:443 2>/dev/null | \
  openssl x509 -noout -dates
```

### Check Service Health
```bash
# Device Proxy API health check
curl -k https://devicehub.qa.fortinet-us.com/nodes

# Should return JSON response
```

## Quick Reference

### Start Services
```bash
docker-compose up -d
sudo systemctl start nginx
```

### Stop Services
```bash
docker-compose down
sudo systemctl stop nginx
```

### Restart Services
```bash
docker-compose restart
sudo systemctl restart nginx
```

### View Logs
```bash
# Docker logs
docker-compose logs -f

# Nginx logs
sudo tail -f /var/log/nginx/devicehub_access.log
sudo tail -f /var/log/nginx/devicehub_error.log
```

## Production Checklist

- [ ] SSL certificates installed and valid
- [ ] Nginx reverse proxy configured and tested
- [ ] Docker containers running successfully
- [ ] Device Proxy accessible via HTTPS on port 443
- [ ] STF integration working correctly
- [ ] Firewall rules configured (allow port 443)
- [ ] Logs being monitored
- [ ] SSL certificate expiry monitoring set up
- [ ] Backups of configuration files
- [ ] Documentation updated with actual domain names
