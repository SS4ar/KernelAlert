# KernelAlert

A distributed Linux kernel security monitoring and alerting system for real-time change detection. 99% Vibe coding. Fucking school

## Overview

KernelAlert is a security system that monitors critical Linux kernel components and sends notifications when suspicious changes are detected. The system consists of lightweight agents on monitored hosts and a centralized server for analysis and alerting.

## Architecture
![[Pasted image 20250603183224.png]]

- **Agent**: Collects kernel data and sends reports to server [1](#1-0) 
- **Server**: Analyzes reports, detects changes, and sends notifications [2](#1-1) 
- **Database**: PostgreSQL for report storage and Redis for caching [3](#1-2) 

## Monitoring Capabilities

The system tracks:
- Loaded kernel modules
- dmesg logs with security pattern detection [4](#1-3) 
- Security state (SELinux, AppArmor, Seccomp)
- eBPF programs and maps
- File integrity (/boot, /proc/sys/kernel)
- Kernel parameters (sysctl)

## Quick Start

### Server Deployment

1. Clone the repository:
```bash
git clone https://github.com/SS4ar/KernelAlert.git
cd KernelAlert
```

2. Configure environment variables (create `.env`):
```bash
POSTGRES_USER=postgres
POSTGRES_PASSWORD=postgres
POSTGRES_DB=kernel_monitor
DB_HOST=postgres
DB_PORT=5432
DB_USER=postgres
DB_PASS=postgres
DB_NAME=kernel_monitor
REDIS_ADDR=redis:6379
TLS_CERT=/certs/server.crt
TLS_KEY=/certs/server.key
TELEGRAM_BOT_TOKEN=BLABLABLA
TELEGRAM_CHAT_ID=123123123
```

3. Start the server:
```bash
docker compose up -d
```

### Agent Installation

1. Build the agent:
```bash
go build -o kernalert-agent cmd/agent/main.go
```

2. Configure environment variables:
```bash
export SERVER_URL=https://your-server:8443/report
export CHECK_INTERVAL=300
```

3. Run the agent:
```bash
./kernalert-agent
```

## Configuration

### Server Environment Variables

- `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASS`, `DB_NAME` - PostgreSQL settings
- `REDIS_ADDR` - Redis address
- `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` - Telegram settings
- `TLS_CERT`, `TLS_KEY` - TLS certificates

### Agent Environment Variables

- `SERVER_URL` - Server URL (default: https://localhost:8443/report)
- `CHECK_INTERVAL` - Check interval in seconds (default: 300)

### Alert Configuration

The system uses a JSON configuration file for alert rules and exceptions [5](#1-4) . Configuration includes:

- Rule categories: selinux, apparmor, modules, ebpf, files, params
- Severity levels: high, medium, low
- Host-specific exceptions
- Pattern-based conditions

## Notifications

The system sends structured Telegram notifications with threat categorization [6](#1-5) :
- 🛡 SELinux/AppArmor
- 📦 Kernel modules
- 🔍 eBPF programs
- 📄 Files
- ⚙️ Kernel parameters
