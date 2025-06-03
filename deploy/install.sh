#!/bin/bash

if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

REQUIRED_TOOLS="bpftool capsh sha256sum"
for tool in $REQUIRED_TOOLS; do
    if ! command -v $tool &> /dev/null; then
        echo "Error: $tool is not installed"
        exit 1
    fi
done

mkdir -p /var/log
touch /var/log/kernalert-agent.log
chmod 640 /var/log/kernalert-agent.log

cp kernalert-agent /usr/local/bin/
chmod 755 /usr/local/bin/kernalert-agent

cp kernalert-agent.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable kernalert-agent
systemctl start kernalert-agent

echo "Installation completed successfully"
echo "Check status with: systemctl status kernalert-agent"
echo "View logs with: journalctl -u kernalert-agent -f" 