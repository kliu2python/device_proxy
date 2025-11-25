# SSL Configuration Setup

This guide explains how to set up SSL certificates for the Device Proxy application.

## Prerequisites

You need the following SSL certificate files:
- SSL certificate file (`.crt` or `.pem`)
- SSL private key file (`.key`)

## Setup Instructions

### 1. Create SSL Directory

Create an `ssl` directory in the project root:

```bash
mkdir -p ssl
```

### 2. Place Your SSL Certificates

Copy your SSL certificate and key files to the `ssl` directory:

```bash
# Copy your certificate file
cp /path/to/your/certificate.crt ssl/cert.crt

# Copy your private key file
cp /path/to/your/private.key ssl/cert.key
```

**Important:** Make sure the files are named exactly:
- `ssl/cert.crt` (your SSL certificate)
- `ssl/cert.key` (your SSL private key)

### 3. Set Proper Permissions

Ensure the SSL files have appropriate permissions:

```bash
chmod 644 ssl/cert.crt
chmod 600 ssl/cert.key
```

### 4. Rebuild and Restart Containers

After placing the SSL certificates, rebuild and restart the Docker containers:

```bash
# Stop existing containers
docker-compose down

# Rebuild the frontend image
docker-compose build frontend

# Start the services
docker-compose up -d
```

## Verification

After starting the containers, verify SSL is working:

1. **HTTP Redirect Test:** Visit http://devicehub.qa.fortinet-us.com (port 80)
   - Should automatically redirect to https://devicehub.qa.fortinet-us.com (port 443)

2. **HTTPS Direct Access:** Visit https://devicehub.qa.fortinet-us.com (port 443)
   - Should load with SSL/TLS encryption

3. **Check Certificate:** Click on the padlock icon in your browser to verify the SSL certificate is valid

## Port Configuration

The application now uses:
- **Port 80 (HTTP):** Automatically redirects to HTTPS
- **Port 443 (HTTPS):** Serves the application with SSL/TLS encryption
- **Port 8090:** Backend API (accessible only through the frontend proxy)

## Troubleshooting

### Certificate Not Found Error

If you see "certificate not found" errors in logs:
```bash
docker-compose logs frontend
```

Verify:
1. SSL files exist in `ssl/` directory
2. Files are named correctly (`cert.crt` and `cert.key`)
3. Container has access to the mounted volumes

### Permission Denied Errors

If you see permission errors:
```bash
# Fix permissions
chmod 644 ssl/cert.crt
chmod 600 ssl/cert.key

# Restart containers
docker-compose restart frontend
```

### Browser Certificate Warnings

If using self-signed certificates, browsers will show warnings. For production:
1. Use certificates from a trusted Certificate Authority (CA)
2. Or use Let's Encrypt for free trusted certificates

## Using Self-Signed Certificates (Development Only)

If you don't have SSL certificates yet, you can create self-signed certificates for testing:

```bash
# Create ssl directory
mkdir -p ssl

# Generate self-signed certificate (valid for 365 days)
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout ssl/cert.key \
  -out ssl/cert.crt \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=devicehub.qa.fortinet-us.com"
```

**Note:** Self-signed certificates will trigger browser security warnings and should only be used for development/testing.

## Additional Security Recommendations

For production deployments:

1. **Use Strong Certificates:** Obtain certificates from a trusted CA
2. **Enable HSTS:** Add `add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;` to nginx.conf
3. **Update Regularly:** Keep SSL certificates up to date before expiration
4. **Secure Key Storage:** Protect private keys with proper file permissions
5. **Consider Let's Encrypt:** For free, automated certificate management
