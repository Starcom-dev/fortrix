#!/bin/bash
# Add vhssl block and restart OLS
cat >> /usr/local/lsws/conf/vhosts/fortix.my/vhost.conf << 'EOF'

vhssl {
  keyFile                 /etc/letsencrypt/live/fortix.my/privkey.pem
  certFile                /etc/letsencrypt/live/fortix.my/fullchain.pem
  certChain               1
}
EOF

echo "vhssl added"
systemctl restart lsws 2>/dev/null || systemctl start lsws
sleep 2
systemctl status lsws --no-pager | head -3
echo "---"
curl -sk -o /dev/null -w "%{http_code}" -H "Host: fortix.my" https://127.0.0.1/
echo ""
