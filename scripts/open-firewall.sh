#!/usr/bin/env bash
# Open TCP 8080 in firewalld so a Windows browser can hit the VM IP.
# Requires sudo on this RHEL host.
set -euo pipefail
sudo firewall-cmd --permanent --add-port=8080/tcp
sudo firewall-cmd --reload
sudo firewall-cmd --list-ports
echo "Port 8080/tcp is now allowed."
