<div align="center">

<img src="assets/hexstrike-logo.png" alt="HexStrike AI Logo" width="220" style="margin-bottom: 20px;"/>

# HexStrike AI MCP v7.0
### AI-Powered Penetration Testing Automation Platform

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-Penetration%20Testing-red.svg)](https://github.com/0x4m4/hexstrike-ai)
[![MCP](https://img.shields.io/badge/MCP-Compatible-purple.svg)](https://github.com/0x4m4/hexstrike-ai)
[![Version](https://img.shields.io/badge/Version-7.0.0-orange.svg)](https://github.com/0x4m4/hexstrike-ai/releases)
[![Tools](https://img.shields.io/badge/Security%20Tools-240%2B-brightgreen.svg)](https://github.com/0x4m4/hexstrike-ai)

**240+ security tools. Scope enforcement. HTML/PDF/SARIF reports. Active Directory module. NTLM relay. Visual recon. Metasploit RPC. Global Burp proxy. Real-time webhook alerts. Connects to Claude Code, VSCode, Cursor and any MCP-compatible AI.**

[🚀 Quick Start](#quick-start) • [🔌 Connecting to AI Clients](#connecting-to-ai-clients) • [🛠️ Tools Reference](#tools-reference) • [📋 Workflow Examples](#workflow-examples) • [🔒 Security Configuration](#security-configuration)

> 📖 **Spanish / Español:** [README.es.md](README.es.md)

</div>

---

## What is HexStrike AI?

HexStrike AI is a **Model Context Protocol (MCP) server** that gives any AI assistant direct access to 240+ penetration testing tools. Instead of manually running tools from a terminal, you describe what you want to do and the AI orchestrates the entire process — including scope enforcement, finding persistence, report generation, and real-time notifications.

```
You: "Scan 192.168.1.0/24, find web services, route everything through Burp,
      screenshot them, check for AD misconfigs, spray passwords safely,
      and generate a PDF + SARIF report."

HexStrike: ✓ set_global_proxy("http://127.0.0.1:8080")  → Burp intercepts all traffic
           ✓ fast_scan_pipeline     → 12 hosts, 47 open ports
           ✓ gowitness (nmap mode)  → 23 screenshots saved
           ✓ get_password_policy    → lockout threshold: 5, safe spray: 3 attempts
           ✓ password_spray         → 2 valid credentials found [CRITICAL finding added]
           ✓ ad_domain_enum         → 3 domain users, 2 SPNs found
           ✓ PDF report generated   → /tmp/engagement_report.pdf
           ✓ SARIF exported         → /tmp/findings.sarif (upload to GitHub)
           ✓ Slack notification     → critical finding alert sent
```

### Architecture

```
┌─────────────────────────────────────────┐
│   AI Client (Claude / Cursor / VSCode)  │
└──────────────────┬──────────────────────┘
                   │ MCP Protocol (stdio)
┌──────────────────▼──────────────────────┐
│         hexstrike_mcp.py                │  ← MCP Server (FastMCP)
│         240 tool definitions            │
└──────────────────┬──────────────────────┘
                   │ HTTP REST API
┌──────────────────▼──────────────────────┐
│         hexstrike_server.py             │  ← Flask Backend
│         Port 8888 · localhost           │
│  ScopeManager · ProxyConfig             │
│  WebhookNotifier · MetasploitRPC        │
│  ReportEngine · SQLite DB · Cache       │
└──────────────────┬──────────────────────┘
                   │ subprocess
┌──────────────────▼──────────────────────┐
│         240+ External Tools             │
│  nmap · nuclei · dalfox · bloodhound    │
│  impacket · certipy · frida · katana    │
│  gowitness · git-dumper · mitm6 …       │
└─────────────────────────────────────────┘
```

---

## What's New in v7.0

| Feature | Description |
|---------|-------------|
| 🔍 **RustScan → Nmap pipeline** | Two-phase port scan: RustScan discovers ports in seconds, Nmap does service detection only on found ports |
| 📸 **gowitness** | Mass web screenshots — single URL, file list, or directly from Nmap XML |
| 🗂️ **git-dumper** | Extracts source code from exposed `.git` directories, auto-runs TruffleHog on the dump |
| 🔑 **Password policy extraction** | Cascade of nxc → enum4linux-ng → rpcclient; calculates safe spray attempts and lockout warning |
| 🔫 **Password spray workflow** | Lockout-safe multi-round spray: auto-fetches policy, calculates safe attempts, timed observation windows |
| ⚡ **NTLM relay workflow** | impacket-ntlmrelayx + mitm6 staged workflow (setup → relay → poison → check loot) |
| 🧠 **Auto-findings (7 parsers)** | Auto-import findings from: nuclei, nmap, nikto, gobuster, sqlmap, hydra, medusa |
| 🌐 **ffuf full rewrite** | All fuzzing modes: directory, vhost, parameter, POST body, header — with filter support |
| 🔄 **Nuclei auto-update** | Templates auto-updated on startup (max once/24h); `/api/tools/nuclei-update` endpoint |
| 💾 **SQLite finding persistence** | Findings survive server restarts; full engagement management |
| 📄 **HTML/PDF reports** | Jinja2 templates + weasyprint; per-engagement with severity breakdown |
| 📊 **SARIF v2.1.0 export** | GitHub Code Scanning, Azure DevOps, VS Code SARIF Viewer, SonarQube — one command |
| 🛡️ **Scope enforcement** | Every tool validates targets against IP/CIDR/domain/wildcard rules before execution |
| 🔒 **API key auth + rate limiting** | `HEXSTRIKE_API_KEY` env var; `@require_api_key` on all 242 endpoints including command execution, file ops, process control, intelligence engine and workflow endpoints |
| 🔔 **Webhook notifications** | Real-time Slack / Discord / generic HTTP alerts on new findings; configurable min severity |
| 🔧 **Tool status inventory** | 80+ tool registry with install commands; readiness check per engagement type (web/internal/AD/mobile/cloud) |
| 🎯 **Metasploit RPC** | Full MSF RPC: sessions, module execution, search, loot, credentials — via pymetasploit3 |
| 🔀 **Global proxy** | One command routes all HTTP tool traffic through Burp Suite, OWASP ZAP, or SOCKS5 |
| 🏢 **Active Directory module** | bloodhound-python, kerbrute, certipy, ldapdomaindump, coercer, lsassy + 4 workflow endpoints |
| 🌍 **Web App tools** | dalfox, jwt_tool, ghauri, commix, corsy, crlfuzz, nomore403, smuggler, graphql-cop, subzy, gau |
| 🔗 **Network discovery** | naabu, dnsx, tlsx, uncover, asnmap, shuffledns, interactsh-client |
| 🔑 **Secrets & SAST** | trufflehog, gitleaks, semgrep |
| 📱 **Mobile security** | frida, objection, apktool, apkleaks, jadx |
| ☁️ **Cloud** | cloudbrute, s3scanner, enumerate-iam |
| 🔀 **Pivoting** | ligolo-ng, chisel |

---

## Quick Start

### 1. Requirements

- **OS:** Kali Linux 2024+ (recommended) · Ubuntu 22.04+ · Debian
- **Python:** 3.8 or higher
- **RAM:** 4 GB minimum (8 GB recommended for headless crawling + gowitness)

### 2. Clone and install

```bash
git clone https://github.com/0x4m4/hexstrike-ai
cd hexstrike-ai

# Create virtual environment
python3 -m venv hexstrike_env
source hexstrike_env/bin/activate

# Install Python dependencies
pip install -r requirements.txt
```

### 3. Start the backend server

```bash
python3 hexstrike_server.py
```

Expected output:
```
INFO - 🚀 Starting HexStrike AI Tools API Server
INFO - 🌐 Port: 8888
INFO - ✨ Enhanced Visual Engine: Active
INFO - 🔄 [startup] Updating nuclei templates in background...
```

Verify it's running:
```bash
curl http://127.0.0.1:8888/health | python3 -m json.tool
```

### 4. Connect an AI client

Keep the server running and proceed to [Connecting to AI Clients](#connecting-to-ai-clients).

---

## Connecting to AI Clients

### Claude Code (Recommended)

Claude Code is the official Anthropic CLI — best supported integration.

**Step 1 — Add to `~/.claude/settings.json`:**

```json
{
  "mcpServers": {
    "hexstrike-ai": {
      "command": "python3",
      "args": [
        "/ABSOLUTE/PATH/TO/hexstrike_mcp.py",
        "--server",
        "http://127.0.0.1:8888"
      ],
      "timeout": 300
    }
  }
}
```

> Replace `/ABSOLUTE/PATH/TO/` with the real path. Example: `/home/kali/hexstrike-ai/hexstrike_mcp.py`

**Step 2 — Verify:**

```bash
claude   # start Claude Code
/mcp     # should list hexstrike-ai with 240 tools
```

**Step 3 — Test:**
```
Check the health of the HexStrike server
```

---

### Cursor

Cursor supports MCP natively since version 0.43.

Edit `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "hexstrike-ai": {
      "command": "python3",
      "args": [
        "/ABSOLUTE/PATH/TO/hexstrike_mcp.py",
        "--server",
        "http://127.0.0.1:8888"
      ],
      "timeout": 300
    }
  }
}
```

Restart Cursor → open Agent mode (`Cmd/Ctrl + I`) → test:
```
Use hexstrike to scan 127.0.0.1 with nmap
```

---

### VSCode — Continue Extension

[Continue](https://continue.dev) is a free open-source AI assistant for VSCode with MCP support.

**Install:** VSCode → Extensions → search `Continue` → Install.

**Edit `~/.continue/config.json`:**

```json
{
  "models": [...],
  "experimental": {
    "modelContextProtocolServers": [
      {
        "transport": {
          "type": "stdio",
          "command": "python3",
          "args": [
            "/ABSOLUTE/PATH/TO/hexstrike_mcp.py",
            "--server",
            "http://127.0.0.1:8888"
          ]
        }
      }
    ]
  }
}
```

Reload VSCode → open Continue sidebar (`Cmd/Ctrl + L`).

---

### VSCode — GitHub Copilot Chat (Agent Mode)

Requires VSCode 1.99+ with GitHub Copilot.

**Edit User Settings JSON** (`Ctrl+Shift+P` → `Open User Settings (JSON)`):

```json
{
  "github.copilot.chat.mcp.enabled": true,
  "mcp": {
    "servers": {
      "hexstrike-ai": {
        "type": "stdio",
        "command": "python3",
        "args": [
          "/ABSOLUTE/PATH/TO/hexstrike_mcp.py",
          "--server",
          "http://127.0.0.1:8888"
        ]
      }
    }
  }
}
```

Switch Copilot Chat to **Agent mode** → test: `@hexstrike-ai check server health`

---

### Windsurf

Edit `~/.codeium/windsurf/mcp_config.json`:

```json
{
  "mcpServers": {
    "hexstrike-ai": {
      "command": "python3",
      "args": [
        "/ABSOLUTE/PATH/TO/hexstrike_mcp.py",
        "--server",
        "http://127.0.0.1:8888"
      ],
      "timeout": 300
    }
  }
}
```

Restart Windsurf → use Cascade (agent mode).

---

### Remote Server Setup

If HexStrike runs on a remote Kali machine (VM, VPS, lab):

```bash
# On the Kali server
HEXSTRIKE_HOST=0.0.0.0 python3 hexstrike_server.py

# Recommended: SSH tunnel (never expose port 8888 directly)
ssh -L 8888:127.0.0.1:8888 user@kali-server
```

In your MCP config use `http://127.0.0.1:8888` (the tunnel endpoint).

> **Security:** Never expose port 8888 to the Internet without API key auth enabled.

---

## Security Configuration

### API Key Authentication

```bash
export HEXSTRIKE_API_KEY="your-strong-random-key-here"
python3 hexstrike_server.py
```

All requests must include:
```
X-API-Key: your-strong-random-key-here
```

For MCP clients, add it to the `env` block:

```json
{
  "mcpServers": {
    "hexstrike-ai": {
      "command": "python3",
      "args": ["/path/hexstrike_mcp.py", "--server", "http://127.0.0.1:8888"],
      "env": {
        "HEXSTRIKE_API_KEY": "your-strong-random-key-here"
      }
    }
  }
}
```

> All 242 endpoints require the API key when `HEXSTRIKE_API_KEY` is set — including `/api/command`, file operations, process control, intelligence engine, and workflow endpoints.

### Scope Management

**The most important safety feature.** When a scope is active, every tool validates its target before running. Out-of-scope requests return HTTP 403.

```
# In your AI chat:
Set the scope to 192.168.1.0/24 and *.lab.internal
```

Via API:
```bash
curl -X POST http://127.0.0.1:8888/api/scope/set \
  -H "Content-Type: application/json" \
  -d '{"targets": ["192.168.1.0/24", "*.lab.internal", "10.10.10.0/24"]}'
```

Supported formats:

| Format | Example |
|--------|---------|
| Single IP | `192.168.1.10` |
| CIDR range | `192.168.1.0/24` |
| Domain | `target.com` |
| Wildcard domain | `*.target.com` |

### Global Proxy (Burp Suite / ZAP)

One command routes **all** HTTP-capable tools through your intercepting proxy:

```
# In your AI chat:
Set the global proxy to http://127.0.0.1:8080
```

Via API:
```bash
# Set proxy (automatically enables it)
curl -X POST http://127.0.0.1:8888/api/config/proxy \
  -H "Content-Type: application/json" \
  -d '{"proxy_url": "http://127.0.0.1:8080"}'

# Disable temporarily (keeps URL stored)
curl -X POST http://127.0.0.1:8888/api/config/proxy/disable

# Re-enable
curl -X POST http://127.0.0.1:8888/api/config/proxy/enable

# Remove completely
curl -X POST http://127.0.0.1:8888/api/config/proxy/clear
```

Supported schemes: `http://`, `https://`, `socks5://`

Tools that automatically receive the proxy flag when set:
`httpx`, `nuclei`, `nikto`, `ffuf`, `sqlmap`, `dalfox`, `gobuster`, `feroxbuster`, `katana`, `ghauri`, `commix`, `whatweb`, `wafw00f`, `wfuzz`, `curl`, `wpscan`, `smuggler`, `crlfuzz`, `corsy` and more.

### Webhook Notifications

Get real-time alerts when findings are added:

```bash
# Slack
curl -X POST http://127.0.0.1:8888/api/webhooks/add \
  -H "Content-Type: application/json" \
  -d '{"url": "https://hooks.slack.com/services/T.../B.../...",
       "platform": "slack", "min_severity": "high", "name": "SlackAlerts"}'

# Discord
curl -X POST http://127.0.0.1:8888/api/webhooks/add \
  -H "Content-Type: application/json" \
  -d '{"url": "https://discord.com/api/webhooks/...",
       "platform": "discord", "min_severity": "critical"}'
```

Severity thresholds: `info` · `low` · `medium` · `high` · `critical`

---

## Tools Reference

### Tool Categories

| Category | Tools | New in v7.0 |
|----------|-------|-------------|
| **Network Recon** | nmap, masscan, rustscan, naabu, dnsx, tlsx, asnmap, shuffledns, uncover, interactsh | naabu, dnsx, tlsx, asnmap, shuffledns, uncover, interactsh |
| **Pipelines** | fast_scan_pipeline (RustScan→Nmap), password_policy, password_spray, ntlm_relay | **All new** |
| **Web Application** | gobuster, ffuf (all modes), nuclei, nikto, sqlmap, dalfox, katana, gau, jwt_tool, ghauri, commix, corsy, crlfuzz, nomore403, smuggler, graphql-cop, subzy | jwt_tool, ghauri, commix, corsy, crlfuzz, nomore403, smuggler, graphql-cop, subzy |
| **Visual Recon** | gowitness | **New** |
| **Source Exposure** | git-dumper | **New** |
| **Active Directory** | bloodhound-python, kerbrute, certipy, ldapdomaindump, coercer, lsassy, impacket suite, ntlmrelayx, mitm6 | **All new** |
| **Post-Exploitation** | ligolo-ng, chisel, metasploit (RPC) | ligolo-ng, chisel, **Metasploit RPC new** |
| **Cloud Security** | prowler, trivy, checkov, cloudbrute, s3scanner, enumerate-iam | cloudbrute, s3scanner, enumerate-iam |
| **Mobile Security** | frida, objection, apktool, apkleaks, jadx | **All new** |
| **Secrets & SAST** | trufflehog, gitleaks, semgrep | **All new** |
| **Binary Analysis** | ghidra, radare2, gdb, binwalk, pwntools, angr | — |
| **Password Attacks** | hydra, hashcat, john, medusa | — |
| **OSINT** | amass, subfinder, theharvester, sherlock | — |
| **Reporting** | HTML, PDF, JSON, SARIF v2.1.0, auto-import (7 parsers) | SARIF, auto-import parsers, engagement management |

---

### Key MCP Tools — Quick Reference

```python
# ── Recon ──────────────────────────────────────────────────────────────────
fast_scan_pipeline(target)                          # RustScan → Nmap, fastest full scan
nmap_scan(target, scan_type="-sV -sC", ports="")
subfinder_scan(domain)
dnsx_dns_toolkit(domain, wordlist="/path/wordlist")
katana_crawl(url, depth=3, js_crawl=True, headless=False)
gau_url_discovery(domain)

# ── Visual recon ───────────────────────────────────────────────────────────
gowitness_screenshot(mode="nmap", nmap_xml="/tmp/scan.xml")   # mass screenshots
gowitness_screenshot(mode="file", url_file="/tmp/urls.txt")
gowitness_screenshot(mode="single", url="https://target.com")

# ── Source exposure ────────────────────────────────────────────────────────
git_dumper(url="https://target.com/.git", output_dir="/tmp/dump")

# ── Global proxy (Burp / ZAP / SOCKS5) ────────────────────────────────────
set_global_proxy("http://127.0.0.1:8080")          # all HTTP tools → Burp
disable_global_proxy()                             # bypass proxy for next tool
enable_global_proxy()                              # re-enable
clear_global_proxy()                               # remove completely
get_global_proxy()                                 # check current status

# ── Web fuzzing ────────────────────────────────────────────────────────────
ffuf_scan(url, mode="directory")                    # path fuzzing
ffuf_scan(url, mode="vhost", domain="target.com",   # virtual host discovery
          filter_size="<baseline>")
ffuf_scan(url, mode="parameter")                    # GET param fuzzing
ffuf_scan(url, mode="post-data", post_data="user=FUZZ&pass=test")

# ── Vulnerability scanning ─────────────────────────────────────────────────
nuclei_scan(target, severity="critical,high")
nuclei_update_templates()                           # update templates (auto on startup)
dalfox_xss_scan(target)
ghauri_sqli_scan(url)
jwt_tool_analyze(token, mode="decode")
corsy_cors_scan(url)
smuggler_scan(url)
graphql_cop_scan(url)
commix_injection_scan(url)
crlfuzz_scan(url)
nomore403_bypass(url)
subzy_takeover_scan(targets)

# ── Active Directory ───────────────────────────────────────────────────────
get_password_policy(target)                         # ALWAYS run before spraying
password_spray(target, passwords=["Winter2024!"], userlist=["admin","user"])
ad_domain_enum_workflow(domain, dc_ip, username, password)
ad_kerberoasting_workflow(domain, dc_ip, username, password)
ad_asreproasting_workflow(domain, dc_ip)
ad_certificate_abuse_workflow(domain, dc_ip, username, password)
bloodhound_python_collect(domain, username, password, dc_ip)
kerbrute_scan(dc_ip, domain, wordlist, mode="userenum")
impacket_secretsdump(target, username, password, domain)

# ── NTLM Relay ─────────────────────────────────────────────────────────────
ntlm_relay_attack(stage="setup")                    # prerequisites checklist
ntlm_relay_attack(stage="relay", targets_file="/tmp/targets.txt", relay_mode="smb")
ntlm_relay_attack(stage="poison", domain="corp.local", interface="eth0")
ntlm_relay_attack(stage="check")                    # parse loot, extract hashes

# ── Metasploit RPC ─────────────────────────────────────────────────────────
msf_connect(password="msf", host="127.0.0.1", port=55553)
msf_sessions()                                      # list active sessions
msf_run_module("exploit", "multi/handler", options={"LHOST": "10.0.0.1"})
msf_session_exec(session_id="1", command="whoami")
msf_search("type:exploit platform:windows smb")
msf_loot()                                          # retrieved credentials / data
msf_credentials()

# ── Tool status ────────────────────────────────────────────────────────────
check_tool_status()                                 # full 80+ tool registry
check_tool_status(engagement_type="web")            # web pentest readiness
check_tool_status(engagement_type="ad")             # AD pentest readiness
check_tool_status(engagement_type="mobile")         # mobile pentest readiness
check_tool_status(engagement_type="cloud")          # cloud pentest readiness

# ── Secrets & SAST ─────────────────────────────────────────────────────────
trufflehog_secrets_scan(target, source="git")
gitleaks_scan(path=".")
semgrep_sast_scan(path=".", config="p/owasp-top-ten")

# ── Mobile ────────────────────────────────────────────────────────────────
frida_instrument(mode="ps")
objection_explore(package="com.example.app", command="android sslpinning disable")
apktool_analyze(apk_path="/tmp/app.apk", mode="decode")
jadx_decompile(apk_path="/tmp/app.apk")
apkleaks_scan(apk_path="/tmp/app.apk")

# ── Cloud ─────────────────────────────────────────────────────────────────
cloudbrute_scan(company="target", provider="aws")
s3scanner_scan(bucket="company-backups")
enumerate_iam_permissions(access_key="AKIA...", secret_key="...")
naabu_port_scan(host="10.0.0.0/24", ports="top-1000")
uncover_search(query="apache port:8080 country:US", engine="shodan")

# ── Pivoting ─────────────────────────────────────────────────────────────
ligolo_ng_tunnel(mode="proxy", listen_addr="0.0.0.0:11601")
chisel_tunnel(mode="server", host="0.0.0.0", port="8080")

# ── Webhooks ───────────────────────────────────────────────────────────────
add_webhook(url, platform="slack", min_severity="high")
list_webhooks()
test_webhook(webhook_id)
remove_webhook(webhook_id)

# ── Reporting ──────────────────────────────────────────────────────────────
set_engagement("ClientX-Internal-2025-04")
add_finding_to_report(title, severity, target, tool, description, evidence)
auto_import_findings("nuclei", nuclei_json_output)
generate_html_report("/tmp/report.html", "Engagement Name")
generate_pdf_report("/tmp/report.pdf")
export_sarif_report("/tmp/findings.sarif")          # GitHub Code Scanning
```

---

## Workflow Examples

### Bug Bounty — Full Web Recon with Burp Intercept

```
You: I'm doing bug bounty on target.com (in scope: *.target.com).
     Route everything through Burp, do full recon, screenshot all subdomains,
     check for common vulns, and generate a PDF + SARIF report.

HexStrike will:
1.  set_scope(["*.target.com"])
2.  set_engagement("BugBounty-target.com-2025")
3.  set_global_proxy("http://127.0.0.1:8080")     → Burp intercepts all traffic
4.  subfinder_scan("target.com")                   → 47 subdomains
5.  httpx_probe(subdomains)                        → 23 live hosts
6.  gowitness_screenshot(mode="file", ...)          → 23 screenshots
7.  katana_crawl(live_hosts, depth=3)              → 312 endpoints
8.  nuclei_scan(live_hosts)                        → 8 findings
9.  auto_import_findings("nuclei", output)         → 8 findings imported
10. dalfox_xss_scan(params_urls)                   → 2 XSS found
11. ghauri_sqli_scan(params_urls)                  → 1 SQLi found
12. generate_pdf_report("/tmp/report.pdf")
13. export_sarif_report("/tmp/findings.sarif")
```

### Internal Pentest — Active Directory

```
You: I'm on the internal network (10.10.10.0/24). No creds yet.
     Find AD, extract password policy, spray, relay NTLM auth.

HexStrike will:
1.  set_scope(["10.10.10.0/24"])
2.  fast_scan_pipeline("10.10.10.0/24")           → discover hosts/services
3.  gowitness_screenshot(mode="nmap", ...)         → screenshot web services
4.  get_password_policy("10.10.10.1")              → lockout threshold: 5
5.  password_spray("10.10.10.0/24",
       passwords=["Winter2024!","Spring2025!"],
       userfile="/tmp/users.txt")                  → 2 valid creds found (CRITICAL)
6.  ntlm_relay_attack(stage="setup")               → prereq checklist
    → nxc smb 10.10.10.0/24 --gen-relay-list /tmp/targets.txt
7.  ntlm_relay_attack(stage="relay", ...)          → start ntlmrelayx
8.  ntlm_relay_attack(stage="poison", ...)         → start mitm6
9.  ntlm_relay_attack(stage="check")               → 3 NTLM hashes captured
10. ad_kerberoasting_workflow(...)
11. ad_certificate_abuse_workflow(...)
12. generate_pdf_report("/tmp/ad_report.pdf")
```

### Web App — Exposed .git Repository

```
You: I found that https://target.com/.git is accessible. Extract it.

HexStrike will:
1. git_dumper(url="https://target.com/.git", output_dir="/tmp/target-src")
   → Dumps full repository source code
   → Runs git log: 47 commits recovered
   → Runs TruffleHog: 3 secrets found (AWS key, DB password, JWT secret)
2. auto_import_findings from TruffleHog output
3. add_finding_to_report(...)
```

### Pre-Spray — Password Policy Check

```
You: Before spraying, check the password policy on 10.10.10.1.

HexStrike will:
1. get_password_policy("10.10.10.1")
   → Method: nxc
   → Lockout threshold: 3
   → ⚠️  DANGER: limit to 1 attempt per user per window
   → Observation window: 30 minutes
   → Safe spray attempts: 1
```

### Metasploit Post-Exploitation

```
You: I have a Meterpreter shell on 10.10.10.5. Extract creds and pivot.

HexStrike will:
1. msf_connect(password="msf")
2. msf_sessions()                         → session 1: meterpreter x64/windows
3. msf_session_exec("1", "getuid")        → NT AUTHORITY\SYSTEM
4. msf_run_module("post", "multi/recon/local_exploit_suggester",
      options={"SESSION": "1"})
5. msf_loot()                             → 3 credential sets retrieved
6. msf_credentials()                      → hash dump available
7. add_finding_to_report("Meterpreter shell", "critical", "10.10.10.5", ...)
```

### SARIF — GitHub Code Scanning Integration

```
You: Export findings to SARIF and upload to GitHub.

HexStrike will:
1. export_sarif_report("/tmp/findings.sarif")
   → 12 findings exported, 10 unique rules
   → SARIF v2.1.0 with CVE taxa linked to NVD

# In terminal after export:
gh code-scanning upload-results \
  --ref refs/heads/main \
  --commit $(git rev-parse HEAD) \
  --sarif /tmp/findings.sarif
```

### Secrets Audit — Code Repository

```
You: Scan /opt/project for leaked secrets and security bugs.

HexStrike will:
1. trufflehog_secrets_scan("/opt/project", source="filesystem")
2. gitleaks_scan("/opt/project")
3. semgrep_sast_scan("/opt/project", config="p/owasp-top-ten")
4. auto_import_findings("trufflehog", output)
5. generate_html_report("/tmp/secrets_audit.html")
```

### Mobile App Security

```
You: Analyze /tmp/app.apk

HexStrike will:
1. apkleaks_scan("/tmp/app.apk")       ← hardcoded secrets
2. apktool_analyze("/tmp/app.apk")     ← decompile resources
3. jadx_decompile("/tmp/app.apk")      ← readable Java source
4. frida_instrument(mode="ps")         ← list running processes
```

---

## Advanced Configuration

### Running with Custom Port

```bash
python3 hexstrike_server.py --port 9999
# Update your MCP config: "--server", "http://127.0.0.1:9999"
```

### Debug Mode

```bash
python3 hexstrike_server.py --debug
python3 hexstrike_mcp.py --server http://127.0.0.1:8888 --debug
```

### Running as a systemd Service (Kali/Ubuntu)

```bash
sudo nano /etc/systemd/system/hexstrike.service
```

```ini
[Unit]
Description=HexStrike AI Server
After=network.target

[Service]
Type=simple
User=kali
WorkingDirectory=/home/kali/hexstrike-ai
ExecStart=/home/kali/hexstrike-ai/hexstrike_env/bin/python3 hexstrike_server.py
Restart=on-failure
Environment=HEXSTRIKE_API_KEY=your-key-here

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable hexstrike
sudo systemctl start hexstrike
sudo systemctl status hexstrike
```

---

## Installing External Tools

Most tools are pre-installed on Kali Linux 2024+. For everything else:

### ProjectDiscovery Toolkit

```bash
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
go install -v github.com/projectdiscovery/asnmap/cmd/asnmap@latest
go install -v github.com/projectdiscovery/uncover/cmd/uncover@latest
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates
```

### Active Directory + NTLM Relay

```bash
# Impacket suite (includes ntlmrelayx, secretsdump, psexec, wmiexec)
pip install impacket

# mitm6 — IPv6 DNS poisoning
pip install mitm6

# Other AD tools
pip install bloodhound certipy-ad ldapdomaindump lsassy coercer

# Kerbrute
go install github.com/ropnop/kerbrute@latest

# Generate relay target list
nxc smb 192.168.1.0/24 --gen-relay-list /tmp/relay-targets.txt
```

### Metasploit RPC

```bash
# Metasploit is pre-installed on Kali. Install the Python RPC client:
pip install pymetasploit3

# Start msfrpcd before connecting:
msfrpcd -P msf -S -f
# or from msfconsole:
# load msgrpc Pass=msf ServerHost=127.0.0.1 ServerPort=55553
```

### Visual Recon

```bash
# gowitness
go install github.com/sensepost/gowitness@latest

# RustScan
cargo install rustscan
# or: apt install rustscan
```

### Source Exposure

```bash
pip install git-dumper
```

### Web App Tools

```bash
go install github.com/hahwul/dalfox/v2@latest
pip install ghauri
go install github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest
go install github.com/LukaSikic/subzy@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/sensepost/gowitness@latest
go install github.com/devploit/nomore403@latest
git clone https://github.com/commixproject/commix.git /opt/commix
git clone https://github.com/s0md3v/Corsy.git /opt/Corsy && pip install -r /opt/Corsy/requirements.txt
git clone https://github.com/defparam/smuggler.git /opt/smuggler
git clone https://github.com/ticarpi/jwt_tool.git /opt/jwt_tool && pip install -r /opt/jwt_tool/requirements.txt
pip install graphql-cop
```

### Mobile Security

```bash
pip install frida-tools objection apkleaks
apt install apktool
# jadx: https://github.com/skylot/jadx/releases
```

### Secrets & SAST

```bash
pip install semgrep
apt install gitleaks
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin
```

### Cloud Tools

```bash
pip install s3scanner enumerate-iam
go install github.com/0xsha/cloudbrute@latest
```

### Pivoting

```bash
# ligolo-ng: https://github.com/nicocha30/ligolo-ng/releases
# chisel:    https://github.com/jpillora/chisel/releases
```

---

## API Reference

The Flask server exposes a REST API on `http://127.0.0.1:8888`. You can call it directly without the MCP layer.

> All POST/DELETE endpoints require `X-API-Key` header when `HEXSTRIKE_API_KEY` is set.

### Core Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Server health, scope info, nuclei template status |
| POST | `/api/command` | Execute any arbitrary command (requires API key) |
| GET | `/api/cache/stats` | Cache hit rate and stats |
| POST | `/api/cache/clear` | Clear command cache |
| GET | `/api/tools/status` | Tool availability inventory (80+ tools, per engagement type) |

### Scope

| Method | Endpoint | Body |
|--------|----------|------|
| POST | `/api/scope/set` | `{"targets": ["192.168.1.0/24"]}` |
| POST | `/api/scope/add` | `{"target": "10.10.10.1"}` |
| POST | `/api/scope/validate` | `{"target": "10.10.10.1"}` |
| POST | `/api/scope/remove` | `{"target": "10.10.10.1"}` |
| GET | `/api/scope/list` | — |
| POST | `/api/scope/clear` | — |

### Proxy Configuration

| Method | Endpoint | Body |
|--------|----------|------|
| GET | `/api/config/proxy` | — |
| POST | `/api/config/proxy` | `{"proxy_url": "http://127.0.0.1:8080", "enabled": true}` |
| POST | `/api/config/proxy/enable` | — |
| POST | `/api/config/proxy/disable` | — |
| POST | `/api/config/proxy/clear` | — |

### Webhooks

| Method | Endpoint | Body |
|--------|----------|------|
| POST | `/api/webhooks/add` | `{"url": "...", "platform": "slack\|discord\|generic", "min_severity": "high", "name": "..."}` |
| GET | `/api/webhooks/list` | — |
| POST | `/api/webhooks/test` | `{"webhook_id": "..."}` |
| DELETE | `/api/webhooks/remove` | `{"webhook_id": "..."}` |
| POST | `/api/webhooks/clear` | — |

### Reports & Findings

| Method | Endpoint | Body |
|--------|----------|------|
| POST | `/api/reports/add-finding` | `{"title", "severity", "target", "tool", "description", "evidence"}` |
| GET | `/api/reports/list-findings` | — |
| GET | `/api/reports/statistics` | — |
| POST | `/api/reports/auto-import` | `{"tool_name": "nmap\|nuclei\|nikto\|gobuster\|sqlmap\|hydra", "tool_output": "...", "target": "..."}` |
| POST | `/api/reports/generate-html` | `{"output_path": "/tmp/r.html", "engagement_name": "..."}` |
| POST | `/api/reports/generate-pdf` | `{"output_path": "/tmp/r.pdf"}` |
| POST | `/api/reports/export-json` | `{"output_path": "/tmp/findings.json"}` |
| POST | `/api/reports/export-sarif` | `{"output_path": "/tmp/findings.sarif"}` |
| POST | `/api/reports/set-engagement` | `{"name": "ClientX-2025"}` |
| GET | `/api/reports/list-engagements` | — |
| POST | `/api/reports/delete-engagement` | `{"name": "ClientX-2025"}` |
| POST | `/api/reports/clear-findings` | — |

### Workflows

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/workflows/fast-scan` | RustScan → Nmap two-phase pipeline |
| POST | `/api/workflows/password-policy` | Extract AD password policy (nxc → enum4linux-ng → rpcclient cascade) |
| POST | `/api/workflows/password-spray` | Lockout-safe multi-round password spray |
| POST | `/api/workflows/ntlm-relay` | impacket-ntlmrelayx + mitm6 staged workflow |

### Active Directory Workflows

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/ad/kerberoasting-workflow` | Full Kerberoasting attack chain |
| POST | `/api/ad/asreproasting-workflow` | AS-REP Roasting (no creds needed) |
| POST | `/api/ad/domain-enum-workflow` | BloodHound + LDAP domain enumeration |
| POST | `/api/ad/certificate-abuse-workflow` | Certipy ESC1/ESC8 abuse |

### Metasploit RPC

| Method | Endpoint | Body |
|--------|----------|------|
| POST | `/api/metasploit/connect` | `{"password": "msf", "host": "127.0.0.1", "port": 55553}` |
| GET | `/api/metasploit/sessions` | — |
| POST | `/api/metasploit/session-exec` | `{"session_id": "1", "command": "whoami"}` |
| POST | `/api/metasploit/run-module` | `{"module_type": "exploit", "module_name": "...", "options": {...}}` |
| GET | `/api/metasploit/search` | `?query=smb+type:exploit` |
| GET | `/api/metasploit/loot` | — |
| GET | `/api/metasploit/credentials` | — |
| POST | `/api/metasploit/kill-job` | `{"job_id": "0"}` |

### Tools

All tool endpoints follow the same pattern:

```bash
curl -X POST http://127.0.0.1:8888/api/tools/nmap \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-key" \
  -d '{"target": "192.168.1.1", "scan_type": "-sV", "ports": "80,443"}'
```

Notable endpoints: `/api/tools/nmap`, `/api/tools/nuclei`, `/api/tools/nuclei-update`, `/api/tools/ffuf`, `/api/tools/gowitness`, `/api/tools/git-dumper`, `/api/tools/dalfox`, `/api/tools/katana`, `/api/tools/netexec`, `/api/tools/bloodhound-python`, `/api/tools/certipy`, `/api/tools/trufflehog`, `/api/tools/semgrep`, `/api/tools/frida`, `/api/tools/ligolo-ng`, and 100+ more.

---

## Troubleshooting

### MCP server not showing in client

1. Verify server is running: `curl http://127.0.0.1:8888/health`
2. Use absolute path in your config — relative paths don't work
3. Verify Python is in PATH: `which python3`
4. Check client logs: Claude Code → `~/.claude/logs/` | Cursor → Help → Toggle Dev Tools

### Tool not found errors

```bash
# Check tool availability via status endpoint
curl http://127.0.0.1:8888/api/tools/status | python3 -m json.tool

# Or check specific tools
which gowitness git-dumper dalfox naabu nuclei certipy impacket-ntlmrelayx mitm6
```

### Scope blocking tools unexpectedly

```bash
# See current scope
curl http://127.0.0.1:8888/api/scope/list

# Clear scope (no restrictions)
curl -X POST http://127.0.0.1:8888/api/scope/clear

# Validate a specific target
curl -X POST http://127.0.0.1:8888/api/scope/validate \
  -H "Content-Type: application/json" \
  -d '{"target": "192.168.1.1"}'
```

### 401 Unauthorized errors

```bash
# Check if API key is required
curl http://127.0.0.1:8888/health   # public endpoint, should work without key

# Test with key
curl -X POST http://127.0.0.1:8888/api/command \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{"command": "whoami"}'

# If running with systemd, check the Environment= line in hexstrike.service
```

### ntlmrelayx fails to start

```bash
# Requires root for raw socket / port 445
sudo python3 hexstrike_server.py

# Or use authbind
apt install authbind
authbind --deep python3 hexstrike_server.py
```

### Metasploit RPC connection refused

```bash
# Verify msfrpcd is running
ps aux | grep msfrpcd

# Start it manually
msfrpcd -P msf -S -f

# Or from msfconsole:
# load msgrpc Pass=msf ServerHost=127.0.0.1 ServerPort=55553 SSL=false

# Verify the port
ss -tlnp | grep 55553

# If pymetasploit3 not installed:
pip install pymetasploit3
```

### Proxy not intercepting traffic

```bash
# Check current proxy status
curl http://127.0.0.1:8888/api/config/proxy

# Verify Burp/ZAP is listening
ss -tlnp | grep 8080

# Make sure the proxy is enabled
curl -X POST http://127.0.0.1:8888/api/config/proxy/enable

# If Burp rejects self-signed certs from tools:
# Burp → Proxy → Options → TLS → Install CA cert in system trust store
```

### PDF report fails

```bash
pip install weasyprint
# On Kali/Debian:
apt install libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz-subset0
```

### Port 8888 already in use

```bash
HEXSTRIKE_PORT=8889 python3 hexstrike_server.py
# Update --server in your MCP config to http://127.0.0.1:8889
```

### gowitness shows no screenshots

```bash
# Verify Chrome/Chromium is installed (required by gowitness)
apt install chromium
which gowitness    # verify binary is in PATH
```

---

## Ethical Use

HexStrike AI is built for **authorized security testing only**.

**Allowed:**
- Penetration testing with written authorization
- Bug bounty programs (within defined scope)
- CTF competitions
- Security research on systems you own
- Defensive security and vulnerability assessments

**Not allowed:**
- Unauthorized scanning or exploitation
- Testing systems without explicit permission
- Any activity that violates local laws or regulations

Always define your scope with `set_scope()` before starting an engagement.

---

<div align="center">

[![Discord](https://img.shields.io/badge/Discord-Join-7289DA?logo=discord&logoColor=white&style=for-the-badge)](https://discord.gg/BWnmrrSHbA)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Follow-0A66C2?logo=linkedin&logoColor=white&style=for-the-badge)](https://www.linkedin.com/company/hexstrike-ai)

**HexStrike AI v7.0** — MIT License

</div>
