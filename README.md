# Adversary-in-the-Middle (AitM) Credential Interception Lab

A self-contained, isolated Docker lab environment for teaching adversary-in-the-middle phishing using Evilginx against a locally hosted mock identity provider.

## Overview

This lab teaches students to deploy an AitM reverse proxy attack that captures credentials and session tokens through TOTP-based multi-factor authentication, and then to detect and defend against such attacks through certificate analysis, network traffic inspection, log analysis, and detection rule engineering.

**This lab is for authorised educational use only.** All infrastructure is locally hosted. No real services or credentials are involved.

## Architecture

| Container | Role | Internal IP | Host Access |
|-----------|------|-------------|-------------|
| `idp` | CorpSSO Identity Provider (Flask) | 10.10.10.2 | https://localhost:8443 |
| `evilginx` | Evilginx3 AitM Proxy | 10.10.10.3 | https://login.evil-corpsso.com (host-bridge IP 172.30.0.3 — no host ports) |
| `mailserver` | Mailpit (SMTP/Webmail) | 10.10.10.4 | http://localhost:8025 |
| `tcpdump` | Traffic Capture | shares Evilginx's network | ./captures/ (PCAP files) |

All lab traffic runs on an isolated Docker network (`aitm-lab-net`, 10.10.10.0/24, `internal: true`) with **no internet access**. A second non-internal network (`host-bridge`) is attached to the `idp`, `evilginx`, and `mailserver` containers purely so Docker can publish their ports to the host — an `internal` network cannot publish ports. The `tcpdump` container has no network of its own: it shares the Evilginx container's network stack (`network_mode: service:evilginx`), so it records both legs of the proxied connection (victim → Evilginx on `host-bridge`, Evilginx → IdP on `aitm-lab-net`). Traffic that never passes through Evilginx, such as a direct sign-in or a token replay to port 8443, is not in its capture.

## Quick Start

```bash
# Clone and launch
git clone https://github.com/plumpmonkey/aitm-lab.git
cd aitm-lab
docker compose up --build -d

# Verify all containers are running
docker compose ps

# Configure hosts file (see docs/hosts-file-entries.txt)
# Import Evilginx CA cert into Firefox (see the lab sheet)
```

The full step-by-step exercise — attack walkthrough, CA cert import, and the Phase 2 detection tasks — is in the accompanying lab sheet.

### Attach to the Evilginx console

```bash
# Use docker attach (NOT docker compose exec — exec starts a second Evilginx
# instance and fails on the already-bound ports 443/80/3333).
# Detach with Ctrl+P then Ctrl+Q.
docker attach aitm-evilginx
```

Inside the console, set up the phishlet and create a lure:

```
phishlets hostname corpsso evil-corpsso.com
phishlets enable corpsso
lures create corpsso
sessions
```

### Send the phishing lure

Deliver the lure email to Mailpit (then read it at http://localhost:8025):

```powershell
# Windows
.\docs\send-phish.ps1 -LureUrl "https://login.evil-corpsso.com/XXXXXXXX"
```
```bash
# macOS/Linux
./docs/send-phish.sh "https://login.evil-corpsso.com/XXXXXXXX"
```

## Pre-configured Accounts

| Email | Password | MFA | Purpose |
|-------|----------|-----|---------|
| alice.smith@corpsso.local | LabPassword123! | TOTP | Primary victim |
| bob.jones@corpsso.local | LabPassword456! | TOTP | Secondary account |
| admin@corpsso.local | AdminLab789! | TOTP | Admin log viewer |

## Directory Structure

```
aitm-lab/
├── docker-compose.yml          # Container orchestration (two networks: see below)
├── idp/                        # CorpSSO identity provider
│   ├── Dockerfile              # Python 3.12 + self-signed TLS cert at build time
│   ├── app.py                  # Flask application (auth, MFA, sessions, admin logs)
│   ├── requirements.txt
│   ├── templates/              # login, mfa_setup, mfa_verify, dashboard,
│   │                           #   admin_logs, webauthn_stub
│   └── static/                 # style.css (CSS custom properties for branding)
├── evilginx/                   # Evilginx3 configuration
│   ├── Dockerfile              # Builds Evilginx3 from upstream source
│   └── phishlets/
│       └── corpsso.yaml        # Custom phishlet for CorpSSO
├── captures/                   # PCAP output written by the tcpdump container (both proxy legs)
├── analysis/
│   ├── sample-captures/        # Pre-recorded reference PCAPs
│   ├── sample-data/            # Sample logs the Sigma tester runs rules against
│   ├── sigma-rules/            # Starter Sigma rules (students edit and test these)
│   │   ├── phishing-domain-sni.yml
│   │   └── session-replay.yml
│   └── sigma-tester/           # Tool container for `docker compose run --rm sigma`
└── docs/
    ├── hosts-file-entries.txt  # DNS entries for student hosts file
    ├── send-phish.ps1          # Send the lure email to Mailpit (Windows)
    └── send-phish.sh           # Send the lure email to Mailpit (macOS/Linux)
```

Mailpit runs from the upstream `axllent/mailpit` image and needs no local build directory, which is why there is no `mailserver/` folder.

## Testing Sigma rules (Task 6)

```bash
docker compose run --rm sigma
```

This runs every rule in `analysis/sigma-rules/` through pySigma and reports, in plain
English, whether it is valid and what it matches in:

- your capture: TLS Client Hellos from every file in `captures/` (rules with `logsource: product: zeek, service: ssl`)
- your CorpSSO log: the `auth_logs` table in CorpSSO's database (rules with `logsource: product: corpsso`)
- the sample logs in `analysis/sample-data/`

The tester is a tool container (Compose profile `tools`), so `docker compose up` does
not start it. It is built the first time you run it, which needs internet access; after
that it runs with no network. Edits to a rule take effect without rebuilding.

## Cleanup

**All cleanup steps are mandatory.**

```bash
# Stop and remove all containers and volumes
docker compose --profile tools down -v --rmi local

# Remove hosts file entries (see docs/hosts-file-entries.txt)
# Remove Evilginx CA certificate from Firefox
# Delete the extracted CA certificate file
rm ./evilginx-ca.crt
```

## Requirements

- Docker Engine 24.0+
- Docker Compose v2.20+
- Firefox (latest stable)
- Google Authenticator or Authy (mobile)
- Wireshark (optional, for PCAP analysis)

## Instructor Notes

- The lab is designed for a 3-hour session (or two 1.5-hour sessions).
- Phase 1 (Attack) typically takes 60–90 minutes.
- Phase 2 (Defence) typically takes 60–90 minutes.
- The CorpSSO TOTP secrets are deterministic. QR codes are identical across rebuilds, so you can pre-enrol authenticator apps on shared lab devices.
- The Evilginx Dockerfile builds from the community edition source. If the upstream repository changes, you may need to pin a specific commit hash.
- Evilginx publishes no host ports (it is reached on its Docker host-bridge IP, 172.30.0.3), so a pre-existing web server on the VM's port 80/443 no longer conflicts with the lab. Only ports 1025, 8025, and 8443 need to be free on lab workstations before the session.
- The lab assumes a **Linux** Docker host: the host routes directly to the Evilginx container IP. On Docker Desktop (Mac/Windows) that bridge IP is not host-routable.
- At the end of each session, verify that every student has completed the cleanup checklist.

## Branding

To apply university branding to the CorpSSO interface, modify the files in `idp/static/` and `idp/templates/`. The CSS custom properties in `idp/static/style.css` use a `:root` block that can be overridden with institutional colours.

## Licence

Copyright © 2026 Jon White, University of the West of England.

This lab is licensed under the [Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International Licence](https://creativecommons.org/licenses/by-nc-sa/4.0/) (CC BY-NC-SA 4.0). You may use, share and adapt it for non-commercial purposes, provided you give appropriate credit and release any adaptations under the same licence. See [`LICENSE`](LICENSE) for the full text.

Evilginx is not included in this repository; it is cloned and built from [kgretzky/evilginx2](https://github.com/kgretzky/evilginx2) at build time and remains under its own licence.
