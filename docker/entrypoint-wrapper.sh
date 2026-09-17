#!/bin/sh -e
# NiFi's own secure.sh does an in-place `sed -i` on conf/authorizers.xml,
# which fails with "Device or resource busy" if that path is itself a bind
# mount (sed -i renames a temp file over the target, and you can't rename
# onto an active mount point). Mounting our pre-filled authorizers.xml at a
# separate path and copying it into place here keeps conf/authorizers.xml a
# plain, rename-able file inside the container.
cp /opt/nifi/custom/authorizers.xml /opt/nifi/nifi-current/conf/authorizers.xml
exec /opt/nifi/scripts/start.sh "$@"
