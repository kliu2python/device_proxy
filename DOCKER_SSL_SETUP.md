# Docker-Only SSL Setup (No Host Nginx Required)

This is the **simplest setup** - everything runs in Docker, no host software installation needed!

## Quick Start

### 1. Place Your SSL Certificates

Create an `ssl` directory and place your certificates:

```bash
cd /path/to/device_proxy

# Create ssl directory
mkdir -p ssl

# Copy your certificates
cp /path/to/your/certificate.crt ssl/cert.crt
cp /path/to/your/privatekey.key ssl/cert.key

# Set permissions (optional but recommended)
chmod 644 ssl/cert.crt
chmod 600 ssl/cert.key
```

Your directory structure should look like:
```
device_proxy/
├── ssl/
│   ├── cert.crt
│   └── cert.key
├── docker-compose.yml
├── frontend/
└── backend/
```

### 2. Start Docker Containers

```bash
# Build and start containers
docker compose up -d --build

# Or if you have older Docker:
docker-compose up -d --build
```

### 3. Verify It's Running

```bash
# Check containers are running
docker compose ps

# Should show:
# - device-proxy-frontend running on port 443
# - appium-selenium-proxy running on port 8090
```

### 4. Access Your Application

Open your browser:
```
https://devicehub.qa.fortinet-us.com
```

**Note:** If using a self-signed certificate, you'll see a browser warning. Click "Advanced" → "Proceed" to continue.

## Testing Locally

If you want to test before DNS is set up:

```bash
# Test with localhost
curl -k https://localhost/nodes

# Or add to /etc/hosts:
sudo nano /etc/hosts
# Add: 127.0.0.1 devicehub.qa.fortinet-us.com

# Then test:
curl -k https://devicehub.qa.fortinet-us.com/nodes
```

## Creating Self-Signed Certificates (Development/Testing)

If you don't have SSL certificates yet, create self-signed ones:

```bash
# Create ssl directory
mkdir -p ssl

# Generate self-signed certificate (valid for 365 days)
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout ssl/cert.key \
  -out ssl/cert.crt \
  -subj "/C=US/ST=State/L=City/O=Fortinet/CN=devicehub.qa.fortinet-us.com"

# Verify created files
ls -la ssl/
```

**Warning:** Self-signed certificates will show browser warnings. For production, use certificates from a trusted Certificate Authority or Let's Encrypt.

## Architecture

```
Internet (Port 443 HTTPS)
         ↓
Docker Container: frontend
    - Nginx with SSL (port 443)
    - Serves static files
    - Proxies API to backend
         ↓
Docker Container: proxy
    - Backend API (port 8090)
    - Device management logic
```

## Advantages of Docker-Only Setup

✅ **No host setup required** - No need to install Nginx on host
✅ **Portable** - Everything runs in containers
✅ **Simple deployment** - Just run `docker compose up`
✅ **Easy updates** - Rebuild containers to update
✅ **Isolated** - All dependencies contained in Docker

## Configuration Files

The following files handle SSL in Docker:

1. **`docker-compose.yml`** - Maps port 443 and mounts SSL certificates
2. **`frontend/nginx.conf`** - Configures Nginx to use SSL
3. **`frontend/Dockerfile`** - Exposes port 443

## Troubleshooting

### Container Fails to Start

Check logs:
```bash
docker compose logs frontend
```

Common issues:
- **Certificate not found:** Make sure `ssl/cert.crt` and `ssl/cert.key` exist
- **Permission denied:** Check file permissions
- **Port already in use:** Another service is using port 443

### Port 443 Already in Use

Find what's using it:
```bash
# Linux
sudo netstat -tlnp | grep :443
sudo lsof -i :443

# Stop the conflicting service
sudo systemctl stop <service-name>
```

### Certificate Issues

Check certificate:
```bash
# View certificate details
openssl x509 -in ssl/cert.crt -text -noout

# Verify certificate and key match
openssl x509 -noout -modulus -in ssl/cert.crt | openssl md5
openssl rsa -noout -modulus -in ssl/cert.key | openssl md5
# The two MD5 hashes should match
```

### Browser Shows "Connection Refused"

1. Check container is running:
   ```bash
   docker compose ps
   ```

2. Check port mapping:
   ```bash
   docker compose port frontend 443
   ```

3. Check firewall:
   ```bash
   # Linux
   sudo ufw status
   sudo ufw allow 443/tcp
   ```

### "NET::ERR_CERT_AUTHORITY_INVALID"

This is normal for self-signed certificates. Options:

1. **Development:** Click "Advanced" → "Proceed anyway"
2. **Production:** Use a proper CA-signed certificate
3. **Let's Encrypt:** Free automated certificates (requires domain pointing to your server)

## Updating SSL Certificates

When your certificates expire or need updating:

```bash
# 1. Replace the certificate files
cp /path/to/new/certificate.crt ssl/cert.crt
cp /path/to/new/privatekey.key ssl/cert.key

# 2. Restart the frontend container
docker compose restart frontend

# No rebuild needed - certificates are mounted as volumes!
```

## STF Configuration

Your STF server runs separately on port 80. Configure it in `backend/.env`:

```bash
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

## Production Checklist

- [ ] Obtain CA-signed SSL certificates (not self-signed)
- [ ] SSL certificates placed in `ssl/` directory
- [ ] Docker and Docker Compose installed
- [ ] Port 443 available (not used by another service)
- [ ] Firewall allows port 443
- [ ] DNS points to your server
- [ ] Containers built and running
- [ ] Application accessible via HTTPS
- [ ] STF integration working

## Stopping and Starting

```bash
# Stop containers
docker compose down

# Start containers
docker compose up -d

# Restart containers
docker compose restart

# View logs
docker compose logs -f

# Rebuild and restart
docker compose up -d --build
```

## Security Notes

1. **Keep certificates private:** The `ssl/` directory is in `.gitignore`
2. **Use strong certificates:** RSA 2048-bit minimum, 4096-bit recommended
3. **Regular updates:** Rotate certificates before expiry
4. **Monitor logs:** Check for suspicious access patterns
5. **Firewall:** Only expose necessary ports

## Getting Help

If you encounter issues:

1. Check container logs: `docker compose logs frontend`
2. Verify certificates exist: `ls -la ssl/`
3. Test locally first: `curl -k https://localhost/nodes`
4. Review the [SIMPLE_SSL_SETUP.md](SIMPLE_SSL_SETUP.md) for alternative setup methods
