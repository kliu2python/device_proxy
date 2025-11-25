# SSL Configuration with STF Server Integration

This guide explains how to configure SSL when both Device Proxy Hub and STF Server need to use port 443.

## Architecture Overview

You have two services that need HTTPS access:
1. **Device Proxy Hub** - The device management interface (this application)
2. **STF Server** - Smartphone Test Farm server (external service)

Both services cannot directly bind to port 443 on the same machine. The solution is to use a **reverse proxy** that handles SSL and routes traffic to the appropriate service.

---

## Solution 1: Path-Based Routing (Recommended)

Use the same hostname with different URL paths:
- `https://devicehub.qa.fortinet-us.com/` → Device Proxy Hub
- `https://devicehub.qa.fortinet-us.com/stf/` → STF Server

### Setup Steps

#### 1. Install Main Nginx Reverse Proxy

On your host server (not in Docker):

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install nginx

# CentOS/RHEL
sudo yum install nginx
```

#### 2. Configure SSL Certificates

Place your SSL certificates on the host:

```bash
# Create SSL directory
sudo mkdir -p /etc/ssl/certs /etc/ssl/private

# Copy your certificates
sudo cp devicehub.crt /etc/ssl/certs/devicehub.crt
sudo cp devicehub.key /etc/ssl/private/devicehub.key

# Set proper permissions
sudo chmod 644 /etc/ssl/certs/devicehub.crt
sudo chmod 600 /etc/ssl/private/devicehub.key
```

#### 3. Configure Nginx Reverse Proxy

Copy the provided `nginx-reverse-proxy.conf` to your nginx configuration:

```bash
# Copy configuration
sudo cp nginx-reverse-proxy.conf /etc/nginx/sites-available/devicehub

# Create symbolic link to enable
sudo ln -s /etc/nginx/sites-available/devicehub /etc/nginx/sites-enabled/

# Remove default site if exists
sudo rm /etc/nginx/sites-enabled/default

# Test configuration
sudo nginx -t

# Reload nginx
sudo systemctl reload nginx
```

#### 4. Update docker-compose.yml

The docker-compose.yml has been updated to expose Device Proxy on port 8080 (internal):

```yaml
services:
  proxy:
    ports:
      - "8090:8090"  # Backend API

  frontend:
    ports:
      - "8080:80"    # Frontend (accessed via reverse proxy)
```

#### 5. Deploy Docker Containers

```bash
# Stop existing containers
docker-compose down

# Rebuild and start
docker-compose up -d --build
```

#### 6. Verify Setup

Test the complete setup:

```bash
# Test HTTP redirect
curl -I http://devicehub.qa.fortinet-us.com
# Should return 301 redirect to https://

# Test Device Proxy Hub
curl -k https://devicehub.qa.fortinet-us.com
# Should return the Device Proxy Hub HTML

# Test STF access
curl -k https://devicehub.qa.fortinet-us.com/stf/
# Should return STF interface
```

#### 7. Update STF Configuration

Update your STF base URL in backend/.env or node resources:

```bash
# In backend/.env
STF_BASE_URL=https://devicehub.qa.fortinet-us.com/stf
```

Or in your node resources CSV:

```json
{
  "stf": {
    "base_url": "https://devicehub.qa.fortinet-us.com/stf",
    "control_path_template": "/#!/control/{udid}",
    "enabled": true
  }
}
```

---

## Solution 2: Hostname-Based Routing (Alternative)

Use different hostnames:
- `https://devicehub.qa.fortinet-us.com/` → Device Proxy Hub
- `https://stf.qa.fortinet-us.com/` → STF Server

### Setup Steps

#### 1. DNS Configuration

Create DNS records:
```
devicehub.qa.fortinet-us.com  A  <your-server-ip>
stf.qa.fortinet-us.com        A  <your-server-ip>
```

#### 2. SSL Certificates

Get SSL certificates for both domains:
```bash
# Option 1: Wildcard certificate
*.qa.fortinet-us.com

# Option 2: Multi-domain certificate (SAN)
devicehub.qa.fortinet-us.com
stf.qa.fortinet-us.com
```

#### 3. Nginx Configuration

Create separate server blocks:

```nginx
# Device Proxy Hub
server {
    listen 443 ssl;
    server_name devicehub.qa.fortinet-us.com;

    ssl_certificate /etc/ssl/certs/devicehub.crt;
    ssl_certificate_key /etc/ssl/private/devicehub.key;

    location / {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

# STF Server
server {
    listen 443 ssl;
    server_name stf.qa.fortinet-us.com;

    ssl_certificate /etc/ssl/certs/stf.crt;
    ssl_certificate_key /etc/ssl/private/stf.key;

    location / {
        proxy_pass http://10.160.13.118;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

#### 4. Update STF Configuration

```bash
# In backend/.env
STF_BASE_URL=https://stf.qa.fortinet-us.com
```

---

## Solution 3: Different Ports (Quick & Simple)

Use different ports for each service:
- `https://devicehub.qa.fortinet-us.com:443` → Device Proxy Hub
- `https://devicehub.qa.fortinet-us.com:8443` → STF Server

### Setup Steps

#### 1. Configure Nginx for Multi-Port

```nginx
# Device Proxy on port 443
server {
    listen 443 ssl;
    server_name devicehub.qa.fortinet-us.com;

    ssl_certificate /etc/ssl/certs/devicehub.crt;
    ssl_certificate_key /etc/ssl/private/devicehub.key;

    location / {
        proxy_pass http://localhost:8080;
    }
}

# STF on port 8443
server {
    listen 8443 ssl;
    server_name devicehub.qa.fortinet-us.com;

    ssl_certificate /etc/ssl/certs/devicehub.crt;
    ssl_certificate_key /etc/ssl/private/devicehub.key;

    location / {
        proxy_pass http://10.160.13.118;
    }
}
```

#### 2. Update Firewall

```bash
# Allow port 8443
sudo ufw allow 8443/tcp
```

#### 3. Update STF Configuration

```bash
# In backend/.env
STF_BASE_URL=https://devicehub.qa.fortinet-us.com:8443
```

---

## Troubleshooting

### Check Nginx Status
```bash
sudo systemctl status nginx
sudo nginx -t  # Test configuration
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
docker-compose logs proxy
```

### Test SSL Certificate
```bash
openssl s_client -connect devicehub.qa.fortinet-us.com:443 -servername devicehub.qa.fortinet-us.com
```

### Test Port Availability
```bash
# Check what's listening on port 443
sudo netstat -tlnp | grep :443
# or
sudo ss -tlnp | grep :443
```

### Common Issues

1. **Port 443 already in use**
   ```bash
   # Find process using port 443
   sudo lsof -i :443

   # Stop conflicting service
   sudo systemctl stop <service-name>
   ```

2. **SSL certificate errors**
   - Verify certificate paths in nginx config
   - Check file permissions (cert: 644, key: 600)
   - Ensure certificates match the domain

3. **502 Bad Gateway**
   - Ensure Docker containers are running
   - Check backend service is accessible on port 8090
   - Verify nginx proxy_pass URLs are correct

4. **CORS errors when accessing STF**
   - Ensure X-Forwarded-Proto headers are set
   - Check STF server CORS configuration

---

## Security Recommendations

1. **Use Strong SSL Configuration**
   ```nginx
   ssl_protocols TLSv1.2 TLSv1.3;
   ssl_ciphers HIGH:!aNULL:!MD5;
   ssl_prefer_server_ciphers on;
   ```

2. **Enable HSTS**
   ```nginx
   add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
   ```

3. **Rate Limiting**
   ```nginx
   limit_req_zone $binary_remote_addr zone=mylimit:10m rate=10r/s;
   limit_req zone=mylimit burst=20;
   ```

4. **Hide Nginx Version**
   ```nginx
   server_tokens off;
   ```

5. **Restrict Access (if needed)**
   ```nginx
   allow 10.160.0.0/16;
   deny all;
   ```

---

## Monitoring

### Check Service Health

```bash
# Device Proxy Hub
curl -k https://devicehub.qa.fortinet-us.com/nodes

# STF Server
curl -k https://devicehub.qa.fortinet-us.com/stf/

# Check SSL expiry
echo | openssl s_client -servername devicehub.qa.fortinet-us.com -connect devicehub.qa.fortinet-us.com:443 2>/dev/null | openssl x509 -noout -dates
```

### Automated Monitoring

Set up monitoring for:
- SSL certificate expiration
- Service availability (HTTP 200 responses)
- Response time
- Error rates in nginx logs

---

## Production Deployment Checklist

- [ ] DNS records configured correctly
- [ ] SSL certificates installed and valid
- [ ] Nginx reverse proxy configured and tested
- [ ] Docker containers running successfully
- [ ] HTTP to HTTPS redirect working
- [ ] Device Proxy Hub accessible via HTTPS
- [ ] STF Server accessible via configured URL
- [ ] STF integration working from Device Proxy
- [ ] Firewall rules configured
- [ ] Logs being monitored
- [ ] SSL certificate renewal automated (e.g., Let's Encrypt cron job)
- [ ] Backup configuration files stored safely
