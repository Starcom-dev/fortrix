#!/bin/bash
# Fix vhost configFile path and add fortix.my mappings

CONF="/usr/local/lsws/conf/httpd_config.conf"
cp "$CONF" "${CONF}.bak_fix_$(date +%H%M)"

# Fix configFile path
sed -i 's|configFile              /conf/vhosts/fortix\.my/vhost\.conf|configFile              $SERVER_ROOT/conf/vhosts/fortix.my/vhost.conf|' "$CONF"

# Check if fortix.my is in the config (it should be from previous sed)
if ! grep -q 'fortix\.my' "$CONF"; then
    # Add fortix.my mappings to all 3 listeners
    sed -i '/map.*fortrix\.xyz fortrix\.xyz/a\  map                     fortix.my fortix.my' "$CONF"

    # Add virtualHost block after fortrix.xyz
    sed -i '/^virtualHost fortrix.xyz {/,/^}/!b; /^}/a\
virtualHost fortix.my {\
  vhRoot                  /home/fortix.my\
  configFile              $SERVER_ROOT/conf/vhosts/fortix.my/vhost.conf\
  allowSymbolLink         1\
  enableScript            1\
  restrained              1\
}\
' "$CONF"
fi

grep -n 'fortix.my' "$CONF"
echo "DONE"
