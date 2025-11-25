#!/bin/bash
# Device Proxy SSL Setup Diagnostic Script

echo "========================================="
echo "Device Proxy SSL Setup Diagnostic"
echo "========================================="
echo ""

# Check 1: Docker containers
echo "1. Checking Docker containers..."
if command -v docker &> /dev/null; then
    if docker compose ps 2>/dev/null || docker-compose ps 2>/dev/null; then
        echo "   ✓ Docker containers found"
    else
        echo "   ✗ Docker containers not running"
    fi

    # Check if port 8080 works
    if curl -s http://localhost:8080 > /dev/null 2>&1; then
        echo "   ✓ Frontend accessible on localhost:8080"
    else
        echo "   ✗ Frontend NOT accessible on localhost:8080"
    fi
else
    echo "   ✗ Docker not found"
fi
echo ""

# Check 2: Nginx installation
echo "2. Checking Nginx..."
if command -v nginx &> /dev/null; then
    echo "   ✓ Nginx installed: $(nginx -v 2>&1)"

    if systemctl is-active --quiet nginx; then
        echo "   ✓ Nginx is running"
    else
        echo "   ✗ Nginx is NOT running"
    fi
else
    echo "   ✗ Nginx not installed"
fi
echo ""

# Check 3: SSL certificates
echo "3. Checking SSL certificates..."
if [ -f /etc/ssl/certs/devicehub.crt ]; then
    echo "   ✓ Certificate exists: /etc/ssl/certs/devicehub.crt"
    echo "   Expires: $(openssl x509 -enddate -noout -in /etc/ssl/certs/devicehub.crt 2>/dev/null)"
else
    echo "   ✗ Certificate NOT found: /etc/ssl/certs/devicehub.crt"
fi

if [ -f /etc/ssl/private/devicehub.key ]; then
    echo "   ✓ Private key exists: /etc/ssl/private/devicehub.key"
else
    echo "   ✗ Private key NOT found: /etc/ssl/private/devicehub.key"
fi
echo ""

# Check 4: Nginx configuration
echo "4. Checking Nginx configuration..."
if [ -f /etc/nginx/sites-available/devicehub ]; then
    echo "   ✓ Configuration exists: /etc/nginx/sites-available/devicehub"
else
    echo "   ✗ Configuration NOT found: /etc/nginx/sites-available/devicehub"
fi

if [ -L /etc/nginx/sites-enabled/devicehub ]; then
    echo "   ✓ Configuration enabled: /etc/nginx/sites-enabled/devicehub"
else
    echo "   ✗ Configuration NOT enabled"
fi

echo "   Testing configuration..."
if nginx -t > /dev/null 2>&1; then
    echo "   ✓ Nginx configuration is valid"
else
    echo "   ✗ Nginx configuration has errors:"
    nginx -t 2>&1 | sed 's/^/     /'
fi
echo ""

# Check 5: Port 443
echo "5. Checking port 443..."
if command -v netstat &> /dev/null; then
    if netstat -tlnp 2>/dev/null | grep -q :443; then
        echo "   ✓ Port 443 is listening"
        netstat -tlnp 2>/dev/null | grep :443 | sed 's/^/     /'
    else
        echo "   ✗ Port 443 is NOT listening"
    fi
elif command -v ss &> /dev/null; then
    if ss -tlnp 2>/dev/null | grep -q :443; then
        echo "   ✓ Port 443 is listening"
        ss -tlnp 2>/dev/null | grep :443 | sed 's/^/     /'
    else
        echo "   ✗ Port 443 is NOT listening"
    fi
else
    echo "   ? Cannot check port (netstat/ss not available)"
fi
echo ""

# Check 6: Firewall
echo "6. Checking firewall..."
if command -v ufw &> /dev/null; then
    if ufw status 2>/dev/null | grep -q "443.*ALLOW"; then
        echo "   ✓ Port 443 allowed in firewall"
    else
        echo "   ⚠ Port 443 may be blocked in firewall"
        echo "   Run: sudo ufw allow 443/tcp"
    fi
elif command -v firewall-cmd &> /dev/null; then
    if firewall-cmd --list-ports 2>/dev/null | grep -q "443"; then
        echo "   ✓ Port 443 allowed in firewall"
    else
        echo "   ⚠ Port 443 may be blocked in firewall"
    fi
else
    echo "   ? Cannot check firewall"
fi
echo ""

# Check 7: Test HTTPS locally
echo "7. Testing HTTPS access..."
if curl -k -s https://localhost > /dev/null 2>&1; then
    echo "   ✓ HTTPS works on localhost"
else
    echo "   ✗ HTTPS NOT working on localhost"
fi

if curl -k -s https://localhost/nodes > /dev/null 2>&1; then
    echo "   ✓ API endpoint works: /nodes"
else
    echo "   ✗ API endpoint NOT working: /nodes"
fi
echo ""

# Summary
echo "========================================="
echo "Summary"
echo "========================================="
echo ""
echo "Next steps:"
echo ""

if ! command -v docker &> /dev/null; then
    echo "❌ Install Docker and start containers"
fi

if ! command -v nginx &> /dev/null; then
    echo "❌ Install Nginx: sudo apt install nginx"
fi

if [ ! -f /etc/ssl/certs/devicehub.crt ]; then
    echo "❌ Install SSL certificates to /etc/ssl/certs/devicehub.crt"
fi

if [ ! -f /etc/nginx/sites-available/devicehub ]; then
    echo "❌ Copy nginx-reverse-proxy.conf to /etc/nginx/sites-available/devicehub"
fi

if [ ! -L /etc/nginx/sites-enabled/devicehub ]; then
    echo "❌ Enable site: sudo ln -s /etc/nginx/sites-available/devicehub /etc/nginx/sites-enabled/"
fi

echo ""
echo "Once all issues are resolved, access:"
echo "https://devicehub.qa.fortinet-us.com"
echo ""
