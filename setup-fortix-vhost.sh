#!/bin/bash
set -e

# Create dirs
mkdir -p /usr/local/lsws/conf/vhosts/fortix.my
mkdir -p /home/fortix.my/public_html

# vhost.conf
cat > /usr/local/lsws/conf/vhosts/fortix.my/vhost.conf << 'VEOF'
docRoot                   /home/fortix.my/public_html
vhDomain                  fortix.my
enableGzip                1

index {
  useServer               0
  indexFiles              index.html
}

rewrite {
  enable                  1
  autoLoadHtaccess        1
}

accessControl {
  allow                   *
}

extprocessor fortixmynode {
  type                    proxy
  address                 127.0.0.1:3010
  maxConns                100
  pcKeepAliveTimeout      60
  initTimeout             60
  retryTimeout            0
  respBuffer              0
}

context /app {
  type                    proxy
  handler                 fortixmynode
  addDefaultCharset       off
}

context /api {
  type                    proxy
  handler                 fortixmynode
  addDefaultCharset       off
}
VEOF

# index.html
cat > /home/fortix.my/public_html/index.html << 'IEOF'
<!DOCTYPE html>
<html><head><meta http-equiv="refresh" content="0;url=/app"><title>Fortix</title></head><body></body></html>
IEOF

chown -R nobody:nobody /home/fortix.my

# Add fortix.my to httpd_config.conf
CONF="/usr/local/lsws/conf/httpd_config.conf"
cp "$CONF" "${CONF}.bak_fortix_$(date +%H%M%S)"

# 1. Add map entries to all 3 listeners (Default, SSL, SSL IPv6)
# Find lines with "map.*fortrix.xyz" and insert fortix.my after each
sed -i '/map.*fortrix\.xyz fortrix\.xyz/a\  map                     fortix.my fortix.my' "$CONF"

# 2. Add virtualHost block after fortrix.xyz virtualHost
# Find the closing brace after virtualHost fortrix.xyz and insert fortix.my block
python3 << 'PYEOF'
import re

with open('/usr/local/lsws/conf/httpd_config.conf', 'r') as f:
    content = f.read()

# Find virtualHost fortrix.xyz block and insert fortix.my block after it
pattern = r'(virtualHost fortrix\.xyz \{[^}]+\})'
replacement = r'''\1
virtualHost fortix.my {
  vhRoot                  /home/fortix.my
  configFile              $SERVER_ROOT/conf/vhosts/fortix.my/vhost.conf
  allowSymbolLink         1
  enableScript            1
  restrained              1
}'''
content = re.sub(pattern, replacement, content, count=1)

with open('/usr/local/lsws/conf/httpd_config.conf', 'w') as f:
    f.write(content)

print("virtualHost block added")
PYEOF

echo "---verifying---"
grep -n 'fortix.my' "$CONF"
echo "=== DONE ==="
