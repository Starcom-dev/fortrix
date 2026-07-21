#!/bin/bash
systemctl restart lsws
sleep 2
curl -s -o /dev/null -w "%{http_code}" -H "Host: fortix.my" http://127.0.0.1/
echo ""
curl -s -H "Host: fortix.my" http://127.0.0.1/ | head -1
