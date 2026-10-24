#!/bin/sh
set -eu
nginx -g 'daemon off;' &
child=$!
trap 'kill -TERM "$child"; wait "$child"' TERM INT
while kill -0 "$child" 2>/dev/null; do
  sleep 10 & wait $!
  size=$(wc -c </logs/access.log 2>/dev/null || echo 0)
  if [ "$size" -gt 10485760 ]; then
    for i in 3 2 1; do
      [ ! -f "/logs/access.log.$i" ] || mv "/logs/access.log.$i" "/logs/access.log.$((i+1))"
    done
    mv /logs/access.log /logs/access.log.1
    kill -USR1 "$child"
  fi
done
wait "$child"
