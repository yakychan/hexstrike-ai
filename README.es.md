<div align="center">

<img src="assets/hexstrike-logo.png" alt="HexStrike AI Logo" width="220" style="margin-bottom: 20px;"/>

# HexStrike AI MCP v7.0
### Plataforma de Automatización de Pentesting con IA

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-Penetration%20Testing-red.svg)](https://github.com/0x4m4/hexstrike-ai)
[![MCP](https://img.shields.io/badge/MCP-Compatible-purple.svg)](https://github.com/0x4m4/hexstrike-ai)
[![Version](https://img.shields.io/badge/Version-7.0.0-orange.svg)](https://github.com/0x4m4/hexstrike-ai/releases)
[![Tools](https://img.shields.io/badge/Security%20Tools-240%2B-brightgreen.svg)](https://github.com/0x4m4/hexstrike-ai)

**240+ herramientas de seguridad. Control de scope. Reportes HTML/PDF/SARIF. Módulo Active Directory. NTLM relay. Recon visual. Metasploit RPC. Proxy global Burp. Alertas webhook en tiempo real. Compatible con Claude Code, VSCode, Cursor y cualquier cliente MCP.**

[🚀 Inicio Rápido](#inicio-rápido) • [🔌 Conectar un cliente de IA](#conectar-un-cliente-de-ia) • [🛠️ Referencia de herramientas](#referencia-de-herramientas) • [📋 Ejemplos de flujo](#ejemplos-de-flujo) • [🔒 Configuración de seguridad](#configuración-de-seguridad)

> 📖 **English version:** [README.md](README.md)

</div>

---

## ¿Qué es HexStrike AI?

HexStrike AI es un **servidor MCP (Model Context Protocol)** que le da a cualquier asistente de IA acceso directo a más de 240 herramientas de pentesting. En lugar de ejecutar herramientas manualmente desde la terminal, describís lo que querés hacer y la IA orquesta todo el proceso — incluyendo validación de scope, persistencia de hallazgos, generación de reportes y notificaciones en tiempo real.

```
Vos: "Escaneá 192.168.1.0/24, encontrá servicios web, ruteá todo por Burp,
      sacá capturas, verificá configuraciones de AD, hacé spray de contraseñas
      y generá un reporte PDF + SARIF."

HexStrike: ✓ set_global_proxy("http://127.0.0.1:8080")  → Burp intercepta todo el tráfico
           ✓ fast_scan_pipeline     → 12 hosts, 47 puertos abiertos
           ✓ gowitness (modo nmap)  → 23 capturas guardadas
           ✓ get_password_policy    → umbral de bloqueo: 5, spray seguro: 3 intentos
           ✓ password_spray         → 2 credenciales válidas encontradas [hallazgo CRÍTICO]
           ✓ ad_domain_enum         → 3 usuarios de dominio, 2 SPNs encontrados
           ✓ Reporte PDF generado   → /tmp/engagement_report.pdf
           ✓ SARIF exportado        → /tmp/findings.sarif (subir a GitHub)
           ✓ Alerta Slack enviada   → hallazgo crítico notificado
```

### Arquitectura

```
┌─────────────────────────────────────────┐
│   Cliente IA (Claude / Cursor / VSCode) │
└──────────────────┬──────────────────────┘
                   │ Protocolo MCP (stdio)
┌──────────────────▼──────────────────────┐
│         hexstrike_mcp.py                │  ← Servidor MCP (FastMCP)
│         240 definiciones de tools       │
└──────────────────┬──────────────────────┘
                   │ API REST HTTP
┌──────────────────▼──────────────────────┐
│         hexstrike_server.py             │  ← Backend Flask
│         Puerto 8888 · localhost         │
│  ScopeManager · ProxyConfig             │
│  WebhookNotifier · MetasploitRPC        │
│  ReportEngine · BD SQLite · Caché       │
└──────────────────┬──────────────────────┘
                   │ subprocess
┌──────────────────▼──────────────────────┐
│         240+ Herramientas externas      │
│  nmap · nuclei · dalfox · bloodhound    │
│  impacket · certipy · frida · katana    │
│  gowitness · git-dumper · mitm6 …       │
└─────────────────────────────────────────┘
```

---

## Novedades en v7.0

| Funcionalidad | Descripción |
|---------------|-------------|
| 🔍 **Pipeline RustScan → Nmap** | Escaneo en dos fases: RustScan descubre puertos en segundos, Nmap detecta servicios solo en los encontrados |
| 📸 **gowitness** | Capturas de pantalla masivas — URL única, lista de URLs, o desde XML de Nmap |
| 🗂️ **git-dumper** | Extrae código fuente de directorios `.git` expuestos, ejecuta TruffleHog automáticamente |
| 🔑 **Extracción de política de contraseñas** | Cascada nxc → enum4linux-ng → rpcclient; calcula intentos seguros y alerta de bloqueo |
| 🔫 **Workflow de password spray** | Spray multi-ronda con protección contra bloqueo: extrae política automáticamente, calcula intentos seguros |
| ⚡ **Workflow NTLM relay** | impacket-ntlmrelayx + mitm6 en etapas (setup → relay → poison → revisar loot) |
| 🧠 **Auto-findings (7 parsers)** | Importación automática de hallazgos desde: nuclei, nmap, nikto, gobuster, sqlmap, hydra, medusa |
| 🌐 **ffuf reescrito** | Todos los modos: directory, vhost, parameter, POST body, header — con soporte de filtros |
| 🔄 **Auto-update de Nuclei** | Templates actualizados al iniciar el servidor (máximo una vez cada 24h) |
| 💾 **Persistencia SQLite** | Los hallazgos sobreviven reinicios del servidor; gestión completa de engagements |
| 📄 **Reportes HTML/PDF** | Templates Jinja2 + weasyprint; por engagement con breakdown de severidad |
| 📊 **Exportación SARIF v2.1.0** | GitHub Code Scanning, Azure DevOps, VS Code SARIF Viewer, SonarQube — un solo comando |
| 🛡️ **Control de scope** | Cada herramienta valida el target antes de ejecutarse; respuestas HTTP 403 fuera de scope |
| 🔒 **API key + rate limiting** | Variable de entorno `HEXSTRIKE_API_KEY`; `@require_api_key` en los 242 endpoints — incluyendo ejecución de comandos, operaciones de archivo, control de procesos, motor de inteligencia y workflows |
| 🔔 **Notificaciones webhook** | Alertas en tiempo real vía Slack / Discord / HTTP genérico al agregar hallazgos; severidad mínima configurable |
| 🔧 **Inventario de herramientas** | Registro de 80+ tools con comandos de instalación; score de preparación por tipo de engagement |
| 🎯 **Metasploit RPC** | MSF RPC completo: sesiones, ejecución de módulos, búsqueda, loot, credenciales — vía pymetasploit3 |
| 🔀 **Proxy global** | Un comando ruteá todo el tráfico HTTP por Burp Suite, OWASP ZAP o SOCKS5 |
| 🏢 **Módulo Active Directory** | bloodhound-python, kerbrute, certipy, ldapdomaindump, coercer, lsassy + 4 endpoints de workflow |
| 🌍 **Herramientas Web App** | dalfox, jwt_tool, ghauri, commix, corsy, crlfuzz, nomore403, smuggler, graphql-cop, subzy, gau |
| 🔗 **Descubrimiento de red** | naabu, dnsx, tlsx, uncover, asnmap, shuffledns, interactsh-client |
| 🔑 **Secrets & SAST** | trufflehog, gitleaks, semgrep |
| 📱 **Seguridad mobile** | frida, objection, apktool, apkleaks, jadx |
| ☁️ **Cloud** | cloudbrute, s3scanner, enumerate-iam |
| 🔀 **Pivoting** | ligolo-ng, chisel |

---

## Inicio Rápido

### 1. Requisitos

- **SO:** Kali Linux 2024+ (recomendado) · Ubuntu 22.04+ · Debian
- **Python:** 3.8 o superior
- **RAM:** 4 GB mínimo (8 GB recomendado para crawling headless + gowitness)

### 2. Clonar e instalar

```bash
git clone https://github.com/0x4m4/hexstrike-ai
cd hexstrike-ai

# Crear entorno virtual
python3 -m venv hexstrike_env
source hexstrike_env/bin/activate

# Instalar dependencias
pip install -r requirements.txt
```

### 3. Iniciar el servidor backend

```bash
python3 hexstrike_server.py
```

Salida esperada:
```
INFO - 🚀 Starting HexStrike AI Tools API Server
INFO - 🌐 Port: 8888
INFO - ✨ Enhanced Visual Engine: Active
INFO - 🔄 [startup] Updating nuclei templates in background...
```

Verificar que está corriendo:
```bash
curl http://127.0.0.1:8888/health | python3 -m json.tool
```

### 4. Conectar un cliente de IA

Dejá el servidor corriendo y seguí con la sección [Conectar un cliente de IA](#conectar-un-cliente-de-ia).

---

## Conectar un cliente de IA

### Claude Code (Recomendado)

Claude Code es el CLI oficial de Anthropic — la integración mejor soportada.

**Paso 1 — Agregar a `~/.claude/settings.json`:**

```json
{
  "mcpServers": {
    "hexstrike-ai": {
      "command": "python3",
      "args": [
        "/RUTA/ABSOLUTA/A/hexstrike_mcp.py",
        "--server",
        "http://127.0.0.1:8888"
      ],
      "timeout": 300
    }
  }
}
```

> Reemplazá `/RUTA/ABSOLUTA/A/` con la ruta real. Ejemplo: `/home/kali/hexstrike-ai/hexstrike_mcp.py`

**Paso 2 — Verificar:**

```bash
claude   # iniciá Claude Code
/mcp     # debería listar hexstrike-ai con 240 tools
```

**Paso 3 — Probar:**
```
Verificá el estado del servidor HexStrike
```

---

### Cursor

Cursor soporta MCP nativo desde la versión 0.43.

Editá `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "hexstrike-ai": {
      "command": "python3",
      "args": [
        "/RUTA/ABSOLUTA/A/hexstrike_mcp.py",
        "--server",
        "http://127.0.0.1:8888"
      ],
      "timeout": 300
    }
  }
}
```

Reiniciá Cursor → abrí el modo Agente (`Cmd/Ctrl + I`) → probá:
```
Use hexstrike to scan 127.0.0.1 with nmap
```

---

### VSCode — Extensión Continue

[Continue](https://continue.dev) es un asistente de IA open source para VSCode con soporte MCP.

**Instalar:** VSCode → Extensiones → buscar `Continue` → Instalar.

**Editar `~/.continue/config.json`:**

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
            "/RUTA/ABSOLUTA/A/hexstrike_mcp.py",
            "--server",
            "http://127.0.0.1:8888"
          ]
        }
      }
    ]
  }
}
```

Recargá VSCode → abrí la barra de Continue (`Cmd/Ctrl + L`).

---

### VSCode — GitHub Copilot Chat (Modo Agente)

Requiere VSCode 1.99+ con GitHub Copilot.

**Editar User Settings JSON** (`Ctrl+Shift+P` → `Open User Settings (JSON)`):

```json
{
  "github.copilot.chat.mcp.enabled": true,
  "mcp": {
    "servers": {
      "hexstrike-ai": {
        "type": "stdio",
        "command": "python3",
        "args": [
          "/RUTA/ABSOLUTA/A/hexstrike_mcp.py",
          "--server",
          "http://127.0.0.1:8888"
        ]
      }
    }
  }
}
```

Cambiá Copilot Chat al modo **Agent** → probá: `@hexstrike-ai verificá el estado del servidor`

---

### Windsurf

Editá `~/.codeium/windsurf/mcp_config.json`:

```json
{
  "mcpServers": {
    "hexstrike-ai": {
      "command": "python3",
      "args": [
        "/RUTA/ABSOLUTA/A/hexstrike_mcp.py",
        "--server",
        "http://127.0.0.1:8888"
      ],
      "timeout": 300
    }
  }
}
```

Reiniciá Windsurf → usá Cascade (modo agente).

---

### OpenCode

[OpenCode](https://github.com/opencode-ai/opencode) es un cliente de IA para terminal. Agregá el servidor MCP a su archivo de configuración (normalmente `~/.config/opencode/config.json`):

```json
{
  "mcpServers": {
    "hexstrike-ai": {
      "command": "python3",
      "args": [
        "/RUTA/ABSOLUTA/A/hexstrike_mcp.py",
        "--server",
        "http://127.0.0.1:8888"
      ],
      "timeout": 600
    }
  }
}
```

> **Nota:** El timeout es 600 segundos porque algunos escaneos (puertos, fuzzing, explotación) pueden tardar varios minutos. Asegurate de que `hexstrike_server.py` esté corriendo antes de iniciar OpenCode.

Reiniciá OpenCode — las herramientas `hexstrike-ai` aparecerán automáticamente.

---

### Servidor Remoto

Si HexStrike corre en una máquina Kali remota (VM, VPS, laboratorio):

```bash
# En el servidor Kali
HEXSTRIKE_HOST=0.0.0.0 python3 hexstrike_server.py

# Recomendado: túnel SSH (nunca exponer el puerto 8888 directamente)
ssh -L 8888:127.0.0.1:8888 usuario@kali-server
```

En tu config MCP usá `http://127.0.0.1:8888` (el endpoint del túnel).

> **Seguridad:** Nunca expongas el puerto 8888 a Internet sin autenticación por API key.

---

## Configuración de Seguridad

### Autenticación por API Key

```bash
export HEXSTRIKE_API_KEY="tu-clave-aleatoria-fuerte"
python3 hexstrike_server.py
```

Todas las solicitudes deben incluir:
```
X-API-Key: tu-clave-aleatoria-fuerte
```

Para clientes MCP, agregala al bloque `env`:

```json
{
  "mcpServers": {
    "hexstrike-ai": {
      "command": "python3",
      "args": ["/ruta/hexstrike_mcp.py", "--server", "http://127.0.0.1:8888"],
      "env": {
        "HEXSTRIKE_API_KEY": "tu-clave-aleatoria-fuerte"
      }
    }
  }
}
```

> Los 242 endpoints requieren la API key cuando `HEXSTRIKE_API_KEY` está configurada — incluyendo `/api/command`, operaciones de archivo, control de procesos, motor de inteligencia y endpoints de workflows.

### Control de Scope

**La funcionalidad de seguridad más importante.** Cuando hay un scope activo, cada herramienta valida su target antes de ejecutarse. Las solicitudes fuera de scope devuelven HTTP 403.

```
# En el chat con la IA:
Definí el scope como 192.168.1.0/24 y *.lab.internal
```

Via API:
```bash
curl -X POST http://127.0.0.1:8888/api/scope/set \
  -H "Content-Type: application/json" \
  -d '{"targets": ["192.168.1.0/24", "*.lab.internal", "10.10.10.0/24"]}'
```

Formatos soportados:

| Formato | Ejemplo |
|---------|---------|
| IP única | `192.168.1.10` |
| Rango CIDR | `192.168.1.0/24` |
| Dominio | `target.com` |
| Wildcard | `*.target.com` |

### Proxy Global (Burp Suite / ZAP)

Un solo comando ruteá **todo** el tráfico HTTP por tu proxy interceptor:

```
# En el chat con la IA:
Configurá el proxy global como http://127.0.0.1:8080
```

Via API:
```bash
# Configurar proxy (lo habilita automáticamente)
curl -X POST http://127.0.0.1:8888/api/config/proxy \
  -H "Content-Type: application/json" \
  -d '{"proxy_url": "http://127.0.0.1:8080"}'

# Deshabilitar temporalmente (guarda la URL)
curl -X POST http://127.0.0.1:8888/api/config/proxy/disable

# Rehabilitar
curl -X POST http://127.0.0.1:8888/api/config/proxy/enable

# Eliminar completamente
curl -X POST http://127.0.0.1:8888/api/config/proxy/clear
```

Esquemas soportados: `http://`, `https://`, `socks5://`

Herramientas que reciben el flag de proxy automáticamente:
`httpx`, `nuclei`, `nikto`, `ffuf`, `sqlmap`, `dalfox`, `gobuster`, `feroxbuster`, `katana`, `ghauri`, `commix`, `whatweb`, `wafw00f`, `wfuzz`, `curl`, `wpscan`, `smuggler`, `crlfuzz`, `corsy` y más.

### Notificaciones Webhook

Alertas en tiempo real cuando se agregan hallazgos:

```bash
# Slack
curl -X POST http://127.0.0.1:8888/api/webhooks/add \
  -H "Content-Type: application/json" \
  -d '{"url": "https://hooks.slack.com/services/T.../B.../...",
       "platform": "slack", "min_severity": "high", "name": "AlertasSlack"}'

# Discord
curl -X POST http://127.0.0.1:8888/api/webhooks/add \
  -H "Content-Type: application/json" \
  -d '{"url": "https://discord.com/api/webhooks/...",
       "platform": "discord", "min_severity": "critical"}'
```

Umbrales de severidad: `info` · `low` · `medium` · `high` · `critical`

---

## Referencia de Herramientas

### Categorías

| Categoría | Herramientas | Nuevo en v7.0 |
|-----------|--------------|---------------|
| **Recon de Red** | nmap, masscan, rustscan, naabu, dnsx, tlsx, asnmap, shuffledns, uncover, interactsh | naabu, dnsx, tlsx, asnmap, shuffledns, uncover, interactsh |
| **Pipelines** | fast_scan_pipeline (RustScan→Nmap), password_policy, password_spray, ntlm_relay | **Todos nuevos** |
| **Aplicaciones Web** | gobuster, ffuf (todos los modos), nuclei, nikto, sqlmap, dalfox, katana, gau, jwt_tool, ghauri, commix, corsy, crlfuzz, nomore403, smuggler, graphql-cop, subzy | jwt_tool, ghauri, commix, corsy, crlfuzz, nomore403, smuggler, graphql-cop, subzy |
| **Recon Visual** | gowitness | **Nuevo** |
| **Exposición de Fuente** | git-dumper | **Nuevo** |
| **Active Directory** | bloodhound-python, kerbrute, certipy, ldapdomaindump, coercer, lsassy, impacket suite, ntlmrelayx, mitm6 | **Todos nuevos** |
| **Post-Explotación** | ligolo-ng, chisel, metasploit (RPC) | ligolo-ng, chisel, **Metasploit RPC nuevo** |
| **Cloud Security** | prowler, trivy, checkov, cloudbrute, s3scanner, enumerate-iam | cloudbrute, s3scanner, enumerate-iam |
| **Seguridad Mobile** | frida, objection, apktool, apkleaks, jadx | **Todos nuevos** |
| **Secrets & SAST** | trufflehog, gitleaks, semgrep | **Todos nuevos** |
| **Análisis Binario** | ghidra, radare2, gdb, binwalk, pwntools, angr | — |
| **Ataques de Contraseñas** | hydra, hashcat, john, medusa | — |
| **OSINT** | amass, subfinder, theharvester, sherlock | — |
| **Reportes** | HTML, PDF, JSON, SARIF v2.1.0, auto-import (7 parsers) | SARIF, parsers de auto-import, gestión de engagements |

---

### Tools MCP Principales — Referencia Rápida

```python
# ── Recon ──────────────────────────────────────────────────────────────────
fast_scan_pipeline(target)                          # RustScan → Nmap, más rápido
nmap_scan(target, scan_type="-sV -sC", ports="")
subfinder_scan(domain)
dnsx_dns_toolkit(domain, wordlist="/ruta/wordlist")
katana_crawl(url, depth=3, js_crawl=True)
gau_url_discovery(domain)

# ── Recon visual ───────────────────────────────────────────────────────────
gowitness_screenshot(mode="nmap", nmap_xml="/tmp/scan.xml")   # capturas masivas
gowitness_screenshot(mode="file", url_file="/tmp/urls.txt")
gowitness_screenshot(mode="single", url="https://target.com")

# ── Exposición de código fuente ────────────────────────────────────────────
git_dumper(url="https://target.com/.git", output_dir="/tmp/dump")
# → vuelca el repo, ejecuta git log + trufflehog automáticamente

# ── Proxy global (Burp / ZAP / SOCKS5) ────────────────────────────────────
set_global_proxy("http://127.0.0.1:8080")          # todas las tools HTTP → Burp
disable_global_proxy()
enable_global_proxy()
clear_global_proxy()
get_global_proxy()

# ── Fuzzing web ────────────────────────────────────────────────────────────
ffuf_scan(url, mode="directory")                    # fuzz de rutas
ffuf_scan(url, mode="vhost", domain="target.com",  # descubrimiento de vhosts
          filter_size="<baseline>")
ffuf_scan(url, mode="parameter")                    # fuzz de parámetros GET
ffuf_scan(url, mode="post-data", post_data="user=FUZZ&pass=test")

# ── Escaneo de vulnerabilidades ────────────────────────────────────────────
nuclei_scan(target, severity="critical,high")
nuclei_update_templates()
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
get_password_policy(target)                         # SIEMPRE antes de un spray
password_spray(target, passwords=["Winter2024!"], userlist=["admin","user"])
ad_domain_enum_workflow(domain, dc_ip, username, password)
ad_kerberoasting_workflow(domain, dc_ip, username, password)
ad_asreproasting_workflow(domain, dc_ip)
ad_certificate_abuse_workflow(domain, dc_ip, username, password)
bloodhound_python_collect(domain, username, password, dc_ip)
kerbrute_scan(dc_ip, domain, wordlist, mode="userenum")
impacket_secretsdump(target, username, password, domain)

# ── NTLM Relay ─────────────────────────────────────────────────────────────
ntlm_relay_attack(stage="setup")                    # checklist de prereqs
ntlm_relay_attack(stage="relay", targets_file="/tmp/targets.txt", relay_mode="smb")
ntlm_relay_attack(stage="poison", domain="corp.local", interface="eth0")
ntlm_relay_attack(stage="check")                    # parsear loot, extraer hashes

# ── Metasploit RPC ─────────────────────────────────────────────────────────
msf_connect(password="msf", host="127.0.0.1", port=55553)
msf_sessions()
msf_run_module("exploit", "multi/handler", options={"LHOST": "10.0.0.1"})
msf_session_exec(session_id="1", command="whoami")
msf_search("type:exploit platform:windows smb")
msf_loot()
msf_credentials()

# ── Inventario de herramientas ─────────────────────────────────────────────
check_tool_status()                                 # registro completo de 80+ tools
check_tool_status(engagement_type="web")            # preparación para web pentest
check_tool_status(engagement_type="ad")             # preparación para AD pentest
check_tool_status(engagement_type="mobile")         # preparación para mobile
check_tool_status(engagement_type="cloud")          # preparación para cloud

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

# ── Reportes ───────────────────────────────────────────────────────────────
set_engagement("ClienteX-Interno-2025-04")
add_finding_to_report(title, severity, target, tool, description, evidence)
auto_import_findings("nuclei", nuclei_json_output)
generate_html_report("/tmp/reporte.html", "Nombre del Engagement")
generate_pdf_report("/tmp/reporte.pdf")
export_sarif_report("/tmp/findings.sarif")          # GitHub Code Scanning
```

---

## Ejemplos de Flujo

### Bug Bounty — Recon Web Completo con Burp

```
Vos: Estoy haciendo bug bounty en target.com (scope: *.target.com).
     Ruteá todo por Burp, hacé recon completo, sacá capturas,
     buscá vulns comunes y generá un PDF + SARIF.

HexStrike hace:
1.  set_scope(["*.target.com"])
2.  set_engagement("BugBounty-target.com-2025")
3.  set_global_proxy("http://127.0.0.1:8080")     → Burp intercepta todo
4.  subfinder_scan("target.com")                   → 47 subdominios
5.  httpx_probe(subdominios)                       → 23 hosts vivos
6.  gowitness_screenshot(mode="file", ...)          → 23 capturas
7.  katana_crawl(hosts_vivos, depth=3)             → 312 endpoints
8.  nuclei_scan(hosts_vivos)                       → 8 hallazgos
9.  auto_import_findings("nuclei", output)         → 8 hallazgos importados
10. dalfox_xss_scan(urls_con_params)               → 2 XSS encontrados
11. ghauri_sqli_scan(urls_con_params)              → 1 SQLi encontrado
12. generate_pdf_report("/tmp/reporte.pdf")
13. export_sarif_report("/tmp/findings.sarif")
```

### Pentest Interno — Active Directory

```
Vos: Estoy en la red interna (10.10.10.0/24). Sin credenciales aún.
     Encontrá el AD, extraé la política, relayá auth NTLM.

HexStrike hace:
1.  set_scope(["10.10.10.0/24"])
2.  fast_scan_pipeline("10.10.10.0/24")           → descubre hosts/servicios
3.  gowitness_screenshot(mode="nmap", ...)         → capturas de servicios web
4.  get_password_policy("10.10.10.1")              → umbral de bloqueo: 5
5.  password_spray("10.10.10.0/24",
       passwords=["Winter2024!","Spring2025!"],
       userfile="/tmp/usuarios.txt")               → 2 credenciales válidas (CRÍTICO)
6.  ntlm_relay_attack(stage="setup")               → checklist de prereqs
    → nxc smb 10.10.10.0/24 --gen-relay-list /tmp/targets.txt
7.  ntlm_relay_attack(stage="relay", ...)          → inicia ntlmrelayx
8.  ntlm_relay_attack(stage="poison", ...)         → inicia mitm6
9.  ntlm_relay_attack(stage="check")               → 3 hashes NTLM capturados
10. ad_kerberoasting_workflow(...)
11. ad_certificate_abuse_workflow(...)
12. generate_pdf_report("/tmp/reporte_ad.pdf")
```

### Repositorio .git Expuesto

```
Vos: Encontré que https://target.com/.git está accesible. Extraélo.

HexStrike hace:
1. git_dumper(url="https://target.com/.git", output_dir="/tmp/target-src")
   → Vuelca el código fuente completo
   → git log: 47 commits recuperados
   → TruffleHog: 3 secretos encontrados (AWS key, contraseña de BD, JWT secret)
2. auto_import_findings desde el output de TruffleHog
3. add_finding_to_report(...)
```

### Antes de un Spray — Política de Contraseñas

```
Vos: Antes de spraying, verificá la política de contraseñas en 10.10.10.1.

HexStrike hace:
1. get_password_policy("10.10.10.1")
   → Método: nxc
   → Umbral de bloqueo: 3
   → ⚠️  PELIGRO: limitarse a 1 intento por usuario por ventana
   → Ventana de observación: 30 minutos
   → Intentos seguros de spray: 1
```

### Metasploit — Post-Explotación

```
Vos: Tengo una shell Meterpreter en 10.10.10.5. Extraé credenciales y pivoteá.

HexStrike hace:
1. msf_connect(password="msf")
2. msf_sessions()                         → sesión 1: meterpreter x64/windows
3. msf_session_exec("1", "getuid")        → NT AUTHORITY\SYSTEM
4. msf_run_module("post", "multi/recon/local_exploit_suggester",
      options={"SESSION": "1"})
5. msf_loot()                             → 3 sets de credenciales recuperados
6. msf_credentials()                      → hash dump disponible
7. add_finding_to_report("Shell Meterpreter", "critical", "10.10.10.5", ...)
```

### SARIF — Integración con GitHub Code Scanning

```
Vos: Exportá los hallazgos a SARIF y subílos a GitHub.

HexStrike hace:
1. export_sarif_report("/tmp/findings.sarif")
   → 12 hallazgos exportados, 10 reglas únicas
   → SARIF v2.1.0 con taxa CVE vinculados a NVD

# En la terminal después de exportar:
gh code-scanning upload-results \
  --ref refs/heads/main \
  --commit $(git rev-parse HEAD) \
  --sarif /tmp/findings.sarif
```

### Auditoría de Secrets — Repositorio de Código

```
Vos: Escaneá /opt/proyecto en busca de secrets y bugs de seguridad.

HexStrike hace:
1. trufflehog_secrets_scan("/opt/proyecto", source="filesystem")
2. gitleaks_scan("/opt/proyecto")
3. semgrep_sast_scan("/opt/proyecto", config="p/owasp-top-ten")
4. auto_import_findings("trufflehog", output)
5. generate_html_report("/tmp/auditoria_secrets.html")
```

### Seguridad Mobile — APK

```
Vos: Analizá /tmp/app.apk

HexStrike hace:
1. apkleaks_scan("/tmp/app.apk")       ← secrets hardcodeados
2. apktool_analyze("/tmp/app.apk")     ← descompilar recursos
3. jadx_decompile("/tmp/app.apk")      ← código Java legible
4. frida_instrument(mode="ps")         ← listar procesos corriendo
```

---

## Configuración Avanzada

### Puerto Personalizado

```bash
python3 hexstrike_server.py --port 9999
# Actualizar en el config MCP: "--server", "http://127.0.0.1:9999"
```

### Modo Debug

```bash
python3 hexstrike_server.py --debug
python3 hexstrike_mcp.py --server http://127.0.0.1:8888 --debug
```

### Servicio systemd (Kali/Ubuntu)

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
Environment=HEXSTRIKE_API_KEY=tu-clave-aqui

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable hexstrike
sudo systemctl start hexstrike
sudo systemctl status hexstrike
```

---

## Instalación de Herramientas Externas

La mayoría están pre-instaladas en Kali Linux 2024+. Para el resto:

### Verificador e instalador de herramientas (`check_tools.py`)

`check_tools.py` escanea tu sistema en busca de las 159 herramientas que usa HexStrike e instala las que faltan.

**Verificar todas las herramientas:**
```bash
python3 check_tools.py
```

**Mostrar solo las faltantes:**
```bash
python3 check_tools.py --missing-only
```

**Verificar una categoría específica:**
```bash
python3 check_tools.py --category "Web Application"
```

**Instalar herramientas faltantes automáticamente:**
```bash
# Vista previa sin cambios
python3 check_tools.py --install --dry-run

# Instalar con confirmación
python3 check_tools.py --install

# Instalar sin preguntar (para scripts/automatización)
python3 check_tools.py --install --yes
```

**Salida en JSON (para scripting):**
```bash
python3 check_tools.py --json
python3 check_tools.py --missing-only --json | jq '.missing | keys'
```

**Comparar con el servidor en ejecución:**
```bash
python3 check_tools.py --server http://127.0.0.1:8888
```

El script agrupa todos los paquetes `apt` en un solo comando para mayor eficiencia, y maneja pip3, Go, gem y cargo por separado. Las herramientas que requieren pasos manuales (instaladores GUI, git clones) se reportan con instrucciones en lugar de instalarse automáticamente.

---

### ProjectDiscovery

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
# Impacket (incluye ntlmrelayx, secretsdump, psexec, wmiexec)
pip install impacket

# mitm6 — envenenamiento DNS IPv6
pip install mitm6

# Otras herramientas AD
pip install bloodhound certipy-ad ldapdomaindump lsassy coercer

# Kerbrute
go install github.com/ropnop/kerbrute@latest

# Generar lista de targets para relay
nxc smb 192.168.1.0/24 --gen-relay-list /tmp/relay-targets.txt
```

### Metasploit RPC

```bash
# Metasploit está pre-instalado en Kali. Instalar el cliente Python RPC:
pip install pymetasploit3

# Iniciar msfrpcd antes de conectar:
msfrpcd -P msf -S -f
# o desde msfconsole:
# load msgrpc Pass=msf ServerHost=127.0.0.1 ServerPort=55553
```

### Recon Visual

```bash
# gowitness
go install github.com/sensepost/gowitness@latest

# RustScan
cargo install rustscan
# o: apt install rustscan
```

### Exposición de Código Fuente

```bash
pip install git-dumper
```

### Herramientas Web

```bash
go install github.com/hahwul/dalfox/v2@latest
pip install ghauri
go install github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest
go install github.com/LukaSikic/subzy@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/devploit/nomore403@latest
git clone https://github.com/commixproject/commix.git /opt/commix
git clone https://github.com/s0md3v/Corsy.git /opt/Corsy && pip install -r /opt/Corsy/requirements.txt
git clone https://github.com/defparam/smuggler.git /opt/smuggler
git clone https://github.com/ticarpi/jwt_tool.git /opt/jwt_tool && pip install -r /opt/jwt_tool/requirements.txt
pip install graphql-cop
```

### Seguridad Mobile

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

### Cloud

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

## Referencia de API

El servidor Flask expone una API REST en `http://127.0.0.1:8888`. Podés llamarla directamente sin pasar por la capa MCP.

> Todos los endpoints POST/DELETE requieren el header `X-API-Key` cuando `HEXSTRIKE_API_KEY` está configurada.

### Endpoints Core

| Método | Endpoint | Descripción |
|--------|----------|-------------|
| GET | `/health` | Estado del servidor, info de scope, estado de templates nuclei |
| POST | `/api/command` | Ejecutar cualquier comando arbitrario (requiere API key) |
| GET | `/api/cache/stats` | Estadísticas del caché |
| POST | `/api/cache/clear` | Limpiar caché |
| GET | `/api/tools/status` | Inventario de tools (80+, por tipo de engagement) |

### Scope

| Método | Endpoint | Body |
|--------|----------|------|
| POST | `/api/scope/set` | `{"targets": ["192.168.1.0/24"]}` |
| POST | `/api/scope/add` | `{"target": "10.10.10.1"}` |
| POST | `/api/scope/validate` | `{"target": "10.10.10.1"}` |
| POST | `/api/scope/remove` | `{"target": "10.10.10.1"}` |
| GET | `/api/scope/list` | — |
| POST | `/api/scope/clear` | — |

### Configuración de Proxy

| Método | Endpoint | Body |
|--------|----------|------|
| GET | `/api/config/proxy` | — |
| POST | `/api/config/proxy` | `{"proxy_url": "http://127.0.0.1:8080", "enabled": true}` |
| POST | `/api/config/proxy/enable` | — |
| POST | `/api/config/proxy/disable` | — |
| POST | `/api/config/proxy/clear` | — |

### Webhooks

| Método | Endpoint | Body |
|--------|----------|------|
| POST | `/api/webhooks/add` | `{"url": "...", "platform": "slack\|discord\|generic", "min_severity": "high", "name": "..."}` |
| GET | `/api/webhooks/list` | — |
| POST | `/api/webhooks/test` | `{"webhook_id": "..."}` |
| DELETE | `/api/webhooks/remove` | `{"webhook_id": "..."}` |
| POST | `/api/webhooks/clear` | — |

### Reportes y Hallazgos

| Método | Endpoint | Body |
|--------|----------|------|
| POST | `/api/reports/add-finding` | `{"title", "severity", "target", "tool", "description", "evidence"}` |
| GET | `/api/reports/list-findings` | — |
| GET | `/api/reports/statistics` | — |
| POST | `/api/reports/auto-import` | `{"tool_name": "nmap\|nuclei\|nikto\|gobuster\|sqlmap\|hydra", "tool_output": "...", "target": "..."}` |
| POST | `/api/reports/generate-html` | `{"output_path": "/tmp/r.html", "engagement_name": "..."}` |
| POST | `/api/reports/generate-pdf` | `{"output_path": "/tmp/r.pdf"}` |
| POST | `/api/reports/export-json` | `{"output_path": "/tmp/findings.json"}` |
| POST | `/api/reports/export-sarif` | `{"output_path": "/tmp/findings.sarif"}` |
| POST | `/api/reports/set-engagement` | `{"name": "ClienteX-2025"}` |
| GET | `/api/reports/list-engagements` | — |
| POST | `/api/reports/delete-engagement` | `{"name": "ClienteX-2025"}` |
| POST | `/api/reports/clear-findings` | — |

### Workflows

| Método | Endpoint | Descripción |
|--------|----------|-------------|
| POST | `/api/workflows/fast-scan` | Pipeline RustScan → Nmap en dos fases |
| POST | `/api/workflows/password-policy` | Extraer política de contraseñas AD (cascada nxc → enum4linux-ng → rpcclient) |
| POST | `/api/workflows/password-spray` | Spray multi-ronda con protección contra bloqueo |
| POST | `/api/workflows/ntlm-relay` | Workflow ntlmrelayx + mitm6 en etapas |

### Workflows de Active Directory

| Método | Endpoint | Descripción |
|--------|----------|-------------|
| POST | `/api/ad/kerberoasting-workflow` | Cadena completa de ataque Kerberoasting |
| POST | `/api/ad/asreproasting-workflow` | AS-REP Roasting (sin credenciales) |
| POST | `/api/ad/domain-enum-workflow` | BloodHound + enumeración LDAP |
| POST | `/api/ad/certificate-abuse-workflow` | Abuso de certificados con Certipy ESC1/ESC8 |

### Metasploit RPC

| Método | Endpoint | Body |
|--------|----------|------|
| POST | `/api/metasploit/connect` | `{"password": "msf", "host": "127.0.0.1", "port": 55553}` |
| GET | `/api/metasploit/sessions` | — |
| POST | `/api/metasploit/session-exec` | `{"session_id": "1", "command": "whoami"}` |
| POST | `/api/metasploit/run-module` | `{"module_type": "exploit", "module_name": "...", "options": {...}}` |
| GET | `/api/metasploit/search` | `?query=smb+type:exploit` |
| GET | `/api/metasploit/loot` | — |
| GET | `/api/metasploit/credentials` | — |
| POST | `/api/metasploit/kill-job` | `{"job_id": "0"}` |

### Herramientas

Todos los endpoints de tools siguen el mismo patrón:

```bash
curl -X POST http://127.0.0.1:8888/api/tools/nmap \
  -H "Content-Type: application/json" \
  -H "X-API-Key: tu-clave" \
  -d '{"target": "192.168.1.1", "scan_type": "-sV", "ports": "80,443"}'
```

Endpoints destacados: `/api/tools/nmap`, `/api/tools/nuclei`, `/api/tools/nuclei-update`, `/api/tools/ffuf`, `/api/tools/gowitness`, `/api/tools/git-dumper`, `/api/tools/dalfox`, `/api/tools/katana`, `/api/tools/netexec`, `/api/tools/bloodhound-python`, `/api/tools/certipy`, `/api/tools/trufflehog`, `/api/tools/semgrep`, `/api/tools/frida`, `/api/tools/ligolo-ng`, y 100+ más.

---

## Solución de Problemas

### El servidor MCP no aparece en el cliente

1. Verificar que el servidor corre: `curl http://127.0.0.1:8888/health`
2. Usar ruta absoluta en la config — las rutas relativas no funcionan
3. Verificar que Python está en el PATH: `which python3`
4. Revisar los logs del cliente: Claude Code → `~/.claude/logs/` | Cursor → Help → Toggle Dev Tools

### Errores de herramienta no encontrada

```bash
# Escanear las 159 herramientas y mostrar las faltantes
python3 check_tools.py --missing-only

# Instalar las herramientas faltantes automáticamente
python3 check_tools.py --install --yes

# O verificar disponibilidad vía endpoint de status del servidor
curl http://127.0.0.1:8888/api/tools/status | python3 -m json.tool

# Verificar herramientas específicas manualmente
which gowitness git-dumper dalfox naabu nuclei certipy impacket-ntlmrelayx mitm6
```

### El scope bloquea herramientas inesperadamente

```bash
# Ver scope actual
curl http://127.0.0.1:8888/api/scope/list

# Limpiar scope (sin restricciones)
curl -X POST http://127.0.0.1:8888/api/scope/clear

# Validar un target específico
curl -X POST http://127.0.0.1:8888/api/scope/validate \
  -H "Content-Type: application/json" \
  -d '{"target": "192.168.1.1"}'
```

### Error 401 Unauthorized

```bash
# Endpoint público, debería funcionar sin key
curl http://127.0.0.1:8888/health

# Probar con key
curl -X POST http://127.0.0.1:8888/api/command \
  -H "X-API-Key: tu-clave" \
  -H "Content-Type: application/json" \
  -d '{"command": "whoami"}'

# Si usás systemd, revisar la línea Environment= en hexstrike.service
```

### ntlmrelayx no inicia

```bash
# Requiere root para sockets raw / puerto 445
sudo python3 hexstrike_server.py

# O usar authbind
apt install authbind
authbind --deep python3 hexstrike_server.py
```

### Metasploit RPC — conexión rechazada

```bash
# Verificar que msfrpcd está corriendo
ps aux | grep msfrpcd

# Iniciarlo manualmente
msfrpcd -P msf -S -f

# O desde msfconsole:
# load msgrpc Pass=msf ServerHost=127.0.0.1 ServerPort=55553 SSL=false

# Verificar el puerto
ss -tlnp | grep 55553

# Si pymetasploit3 no está instalado:
pip install pymetasploit3
```

### El proxy no intercepta el tráfico

```bash
# Verificar estado actual del proxy
curl http://127.0.0.1:8888/api/config/proxy

# Verificar que Burp/ZAP está escuchando
ss -tlnp | grep 8080

# Asegurarse que el proxy está habilitado
curl -X POST http://127.0.0.1:8888/api/config/proxy/enable

# Si Burp rechaza certificados de las tools:
# Burp → Proxy → Options → TLS → Instalar CA cert en el store del sistema
```

### El reporte PDF falla

```bash
pip install weasyprint
# En Kali/Debian:
apt install libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz-subset0
```

### Puerto 8888 en uso

```bash
HEXSTRIKE_PORT=8889 python3 hexstrike_server.py
# Actualizar --server en el config MCP a http://127.0.0.1:8889
```

### gowitness no genera capturas

```bash
# Verificar que Chromium está instalado (requerido por gowitness)
apt install chromium
which gowitness    # verificar que el binario está en el PATH
```

---

## Uso Ético

HexStrike AI está construido **exclusivamente para pruebas de seguridad autorizadas**.

**Permitido:**
- Pruebas de penetración con autorización escrita
- Programas de bug bounty (dentro del scope definido)
- Competencias CTF
- Investigación en seguridad en sistemas propios
- Evaluaciones de seguridad defensiva

**No permitido:**
- Escaneo o explotación sin autorización
- Pruebas en sistemas sin permiso explícito
- Cualquier actividad que viole leyes o regulaciones locales

Siempre definí tu scope con `set_scope()` antes de comenzar un engagement.

---

<div align="center">

[![Discord](https://img.shields.io/badge/Discord-Join-7289DA?logo=discord&logoColor=white&style=for-the-badge)](https://discord.gg/BWnmrrSHbA)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Follow-0A66C2?logo=linkedin&logoColor=white&style=for-the-badge)](https://www.linkedin.com/company/hexstrike-ai)

**HexStrike AI v7.0** — Licencia MIT

</div>
