#!/usr/bin/env bash
set -euo pipefail

# Badlands canonical live-inference tunnels.
# Safe to run before every live validation; existing listeners are reused.

ensure_tunnel() {
  local port="$1"
  shift
  if nc -z 127.0.0.1 "$port" >/dev/null 2>&1; then
    echo "port $port already listening"
    return 0
  fi
  echo "starting tunnel on local port $port"
  ssh -f -N -o ExitOnForwardFailure=yes "$@"
  sleep 1
  nc -z 127.0.0.1 "$port" >/dev/null 2>&1
}

ensure_tunnel 18000 -L 18000:localhost:8000 spark
ensure_tunnel 18001 -J spark -L 18001:localhost:30000 jarrodbarnes@192.168.100.11
ensure_tunnel 18002 -J spark -L 18002:localhost:30001 jarrodbarnes@192.168.100.11

echo "Badlands live LLM tunnels ready: 18000 attacker, 18001 defender, 18002 green"
