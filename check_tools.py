#!/usr/bin/env python3
"""
HexStrike AI — Tool Availability Checker & Installer
Verifica e instala herramientas del MCP.
"""

import shutil
import subprocess
import sys
import json
import os
import argparse
from typing import Dict, List, Tuple, Optional

# ── Colors ────────────────────────────────────────────────────────────────────
R = "\033[38;5;196m"
G = "\033[38;5;46m"
Y = "\033[38;5;208m"
C = "\033[38;5;51m"
P = "\033[38;5;129m"
W = "\033[97m"
D = "\033[38;5;240m"
B = "\033[1m"
X = "\033[0m"

# ── Tool catalog ───────────────────────────────────────────────────────────────
CATEGORIES: Dict[str, List[str]] = {
    "🔴 Essential": [
        "nmap", "gobuster", "dirb", "nikto", "sqlmap", "hydra", "john", "hashcat",
    ],
    "🌐 Network": [
        "rustscan", "masscan", "autorecon", "nbtscan", "arp-scan", "responder",
        "nxc", "enum4linux-ng", "rpcclient", "enum4linux",
    ],
    "🌐 Network v7": [
        "naabu", "dnsx", "tlsx", "uncover", "asnmap", "shuffledns", "interactsh-client",
    ],
    "🕸️  Web Security": [
        "ffuf", "feroxbuster", "dirsearch", "dotdotpwn", "xsser", "wfuzz",
        "waybackurls", "arjun", "paramspider", "x8", "jaeles",
        "httpx", "wafw00f", "burpsuite", "zaproxy", "katana", "hakrawler",
    ],
    "🕸️  Web v7": [
        "dalfox", "ghauri", "commix", "crlfuzz", "subzy", "gau",
        "graphql-cop", "smuggler",
    ],
    "🔍 Vuln Scanning": [
        "nuclei", "wpscan", "graphql-scanner", "jwt-analyzer",
    ],
    "🔑 Password": [
        "medusa", "patator", "hash-identifier", "ophcrack", "hashcat-utils",
    ],
    "⚙️  Binary / Reversing": [
        "gdb", "radare2", "binwalk", "ropgadget", "checksec", "objdump",
        "ghidra", "pwntools", "one-gadget", "ropper", "angr", "libc-database", "pwninit",
    ],
    "🔬 Forensics": [
        "volatility3", "vol", "steghide", "hashpump", "foremost", "exiftool",
        "strings", "xxd", "file", "photorec", "testdisk", "scalpel",
        "bulk-extractor", "stegsolve", "zsteg", "outguess",
    ],
    "☁️  Cloud": [
        "prowler", "scout-suite", "trivy", "kube-hunter", "kube-bench",
        "docker-bench-security", "checkov", "terrascan", "falco", "clair",
        "s3scanner", "cloudbrute",
    ],
    "🕵️  OSINT": [
        "amass", "subfinder", "fierce", "dnsenum", "theharvester", "sherlock",
        "social-analyzer", "recon-ng", "maltego", "spiderfoot", "shodan-cli",
        "censys-cli", "have-i-been-pwned",
    ],
    "💥 Exploitation": [
        "metasploit", "searchsploit", "exploit-db",
    ],
    "🪟 Active Directory": [
        "bloodhound-python", "kerbrute", "certipy", "ldapdomaindump",
        "coercer", "lsassy", "impacket-secretsdump", "impacket-psexec", "impacket-wmiexec",
    ],
    "📡 Wireless": [
        "kismet", "wireshark", "tshark", "tcpdump",
        "airmon-ng", "airodump-ng", "aireplay-ng", "aircrack-ng",
    ],
    "🔐 Secrets / SAST": [
        "trufflehog", "gitleaks", "semgrep",
    ],
    "📱 Mobile": [
        "frida", "frida-ps", "objection", "apktool", "apkleaks", "jadx",
    ],
    "🚪 Post-Exploitation": [
        "ligolo-ng", "chisel",
    ],
    "🔌 API Tools": [
        "curl", "httpie", "anew", "qsreplace", "uro",
        "api-schema-analyzer", "postman", "insomnia",
    ],
    "🗂️  Additional": [
        "smbmap", "autopsy", "evil-winrm", "msfvenom", "msfconsole",
        "volatility", "sleuthkit",
    ],
}

ALIASES: Dict[str, List[str]] = {
    "metasploit":            ["msfconsole", "msfvenom"],
    "exploit-db":            ["searchsploit"],
    "hash-identifier":       ["hash-identifier", "hashid"],
    "hashcat-utils":         ["hashcat-utils", "cap2hccapx"],
    "pwntools":              ["python3 -c 'import pwn'"],
    "angr":                  ["python3 -c 'import angr'"],
    "libc-database":         ["libc-database", "find-libc.py"],
    "one-gadget":            ["one_gadget", "one-gadget"],
    "graphql-scanner":       ["graphql-scanner", "graphql_scanner"],
    "jwt-analyzer":          ["jwt_tool", "jwt-analyzer"],
    "api-schema-analyzer":   ["api-schema-analyzer", "openapi-schema-validator"],
    "graphql-cop":           ["graphql-cop"],
    "social-analyzer":       ["social-analyzer", "socialscan"],
    "shodan-cli":            ["shodan"],
    "censys-cli":            ["censys"],
    "have-i-been-pwned":     ["hibp", "haveibeenpwned"],
    "bloodhound-python":     ["bloodhound-python", "bloodhound"],
    "certipy":               ["certipy", "certipy-ad"],
    "interactsh-client":     ["interactsh-client", "interactsh"],
    "docker-bench-security": ["docker-bench-security", "docker-bench.sh"],
    "ligolo-ng":             ["ligolo-ng", "ligolo"],
    "smuggler":              ["smuggler", "smuggler.py"],
    "ropgadget":             ["ROPgadget", "ropgadget"],
    "vol":                   ["vol", "vol.py", "vol3"],
    "volatility3":           ["vol3", "volatility3", "vol"],
    "stegsolve":             ["stegsolve"],
    "bulk-extractor":        ["bulk_extractor", "bulk-extractor"],
    "sleuthkit":             ["mmls", "fls", "icat"],
    "scout-suite":           ["scout-suite", "scout"],
    "nxc":                   ["nxc", "netexec", "crackmapexec"],
}

# Comandos de instalación preferidos por tool.
# Formato: lista de strings, cada uno es un comando ejecutable.
# Cuando hay múltiples opciones se intentan en orden.
INSTALL_COMMANDS: Dict[str, List[str]] = {
    "nmap":               ["apt install -y nmap"],
    "gobuster":           ["apt install -y gobuster"],
    "dirb":               ["apt install -y dirb"],
    "nikto":              ["apt install -y nikto"],
    "sqlmap":             ["apt install -y sqlmap"],
    "hydra":              ["apt install -y hydra"],
    "john":               ["apt install -y john"],
    "hashcat":            ["apt install -y hashcat"],
    "masscan":            ["apt install -y masscan"],
    "rustscan":           ["apt install -y rustscan", "cargo install rustscan"],
    "nbtscan":            ["apt install -y nbtscan"],
    "arp-scan":           ["apt install -y arp-scan"],
    "responder":          ["apt install -y responder"],
    "enum4linux":         ["apt install -y enum4linux"],
    "enum4linux-ng":      ["pip3 install -q enum4linux-ng"],
    "rpcclient":          ["apt install -y samba-common-bin"],
    "ffuf":               ["apt install -y ffuf"],
    "feroxbuster":        ["apt install -y feroxbuster", "cargo install feroxbuster"],
    "dirsearch":          ["pip3 install -q dirsearch"],
    "wfuzz":              ["apt install -y wfuzz"],
    "xsser":              ["apt install -y xsser"],
    "dotdotpwn":          ["apt install -y dotdotpwn"],
    "waybackurls":        ["go install github.com/tomnomnom/waybackurls@latest"],
    "arjun":              ["pip3 install -q arjun"],
    "paramspider":        ["pip3 install -q paramspider"],
    "httpx":              ["go install github.com/projectdiscovery/httpx/cmd/httpx@latest"],
    "wafw00f":            ["pip3 install -q wafw00f"],
    "katana":             ["go install github.com/projectdiscovery/katana/cmd/katana@latest"],
    "hakrawler":          ["go install github.com/hakluke/hakrawler@latest"],
    "zaproxy":            ["apt install -y zaproxy"],
    "nuclei":             ["go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"],
    "wpscan":             ["apt install -y wpscan", "gem install wpscan"],
    "dalfox":             ["go install github.com/hahwul/dalfox/v2@latest"],
    "ghauri":             ["pip3 install -q ghauri"],
    "commix":             ["apt install -y commix"],
    "gau":                ["go install github.com/lc/gau/v2/cmd/gau@latest"],
    "subzy":              ["go install github.com/lukasikic/subzy@latest"],
    "crlfuzz":            ["go install github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest"],
    "medusa":             ["apt install -y medusa"],
    "patator":            ["apt install -y patator"],
    "hash-identifier":    ["apt install -y hash-identifier"],
    "ophcrack":           ["apt install -y ophcrack"],
    "gdb":                ["apt install -y gdb"],
    "radare2":            ["apt install -y radare2"],
    "binwalk":            ["apt install -y binwalk"],
    "ropgadget":          ["pip3 install -q ropgadget"],
    "checksec":           ["apt install -y checksec"],
    "objdump":            ["apt install -y binutils"],
    "ghidra":             ["apt install -y ghidra"],
    "pwntools":           ["pip3 install -q pwntools"],
    "ropper":             ["pip3 install -q ropper"],
    "angr":               ["pip3 install -q angr"],
    "pwninit":            ["cargo install pwninit"],
    "steghide":           ["apt install -y steghide"],
    "foremost":           ["apt install -y foremost"],
    "exiftool":           ["apt install -y exiftool"],
    "strings":            ["apt install -y binutils"],
    "xxd":                ["apt install -y xxd"],
    "file":               ["apt install -y file"],
    "photorec":           ["apt install -y testdisk"],
    "testdisk":           ["apt install -y testdisk"],
    "scalpel":            ["apt install -y scalpel"],
    "bulk-extractor":     ["apt install -y bulk-extractor"],
    "outguess":           ["apt install -y outguess"],
    "hashpump":           ["apt install -y hashpump"],
    "zsteg":              ["gem install zsteg"],
    "volatility3":        ["pip3 install -q volatility3"],
    "trivy":              ["apt install -y trivy"],
    "checkov":            ["pip3 install -q checkov"],
    "terrascan":          ["pip3 install -q terrascan"],
    "semgrep":            ["pip3 install -q semgrep"],
    "amass":              ["apt install -y amass"],
    "subfinder":          ["go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"],
    "fierce":             ["pip3 install -q fierce"],
    "dnsenum":            ["apt install -y dnsenum"],
    "theharvester":       ["apt install -y theharvester"],
    "sherlock":           ["pip3 install -q sherlock-project"],
    "recon-ng":           ["apt install -y recon-ng"],
    "maltego":            ["apt install -y maltego"],
    "spiderfoot":         ["pip3 install -q spiderfoot"],
    "shodan-cli":         ["pip3 install -q shodan"],
    "censys-cli":         ["pip3 install -q censys"],
    "searchsploit":       ["apt install -y exploitdb"],
    "msfconsole":         ["apt install -y metasploit-framework"],
    "msfvenom":           ["apt install -y metasploit-framework"],
    "bloodhound-python":  ["pip3 install -q bloodhound"],
    "kerbrute":           ["go install github.com/ropnop/kerbrute@latest"],
    "certipy":            ["pip3 install -q certipy-ad"],
    "ldapdomaindump":     ["pip3 install -q ldapdomaindump"],
    "lsassy":             ["pip3 install -q lsassy"],
    "impacket-secretsdump": ["pip3 install -q impacket"],
    "impacket-psexec":    ["pip3 install -q impacket"],
    "impacket-wmiexec":   ["pip3 install -q impacket"],
    "evil-winrm":         ["gem install evil-winrm"],
    "smbmap":             ["pip3 install -q smbmap"],
    "wireshark":          ["apt install -y wireshark"],
    "tshark":             ["apt install -y tshark"],
    "tcpdump":            ["apt install -y tcpdump"],
    "kismet":             ["apt install -y kismet"],
    "aircrack-ng":        ["apt install -y aircrack-ng"],
    "airmon-ng":          ["apt install -y aircrack-ng"],
    "airodump-ng":        ["apt install -y aircrack-ng"],
    "aireplay-ng":        ["apt install -y aircrack-ng"],
    "nxc":                ["pip3 install -q netexec"],
    "gitleaks":           ["go install github.com/gitleaks/gitleaks/v8@latest"],
    "trufflehog":         ["go install github.com/trufflesecurity/trufflehog/v3@latest"],
    "frida":              ["pip3 install -q frida-tools"],
    "frida-ps":           ["pip3 install -q frida-tools"],
    "objection":          ["pip3 install -q objection"],
    "apktool":            ["apt install -y apktool"],
    "apkleaks":           ["pip3 install -q apkleaks"],
    "jadx":               ["apt install -y jadx"],
    "naabu":              ["go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"],
    "dnsx":               ["go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest"],
    "tlsx":               ["go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest"],
    "shuffledns":         ["go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"],
    "asnmap":             ["go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest"],
    "httpie":             ["pip3 install -q httpie"],
    "curl":               ["apt install -y curl"],
    "anew":               ["go install github.com/tomnomnom/anew@latest"],
    "qsreplace":          ["go install github.com/tomnomnom/qsreplace@latest"],
    "uro":                ["pip3 install -q uro"],
    "chisel":             ["go install github.com/jpillora/chisel@latest"],
    "autopsy":            ["apt install -y autopsy"],
    "x8":                 ["cargo install x8"],
    "jaeles":             ["go install github.com/jaeles-project/jaeles@latest"],
}

# Tools que no se pueden instalar automáticamente (requieren pasos manuales / GUI)
MANUAL_INSTALL: Dict[str, str] = {
    "burpsuite":           "Descargar desde https://portswigger.net/burp",
    "metasploit":          "apt install metasploit-framework  (ya incluye msfconsole/msfvenom)",
    "exploit-db":          "Incluido en searchsploit: apt install exploitdb",
    "stegsolve":           "wget https://github.com/zardus/ctf-tools/raw/master/stegsolve/install",
    "graphql-cop":         "pip3 install graphql-cop",
    "smuggler":            "git clone https://github.com/defparam/smuggler",
    "social-analyzer":     "pip3 install social-analyzer  OR  socialscan",
    "have-i-been-pwned":   "pip3 install pwnedpasswords",
    "graphql-scanner":     "pip3 install graphql-map",
    "jwt-analyzer":        "pip3 install jwt_tool",
    "api-schema-analyzer": "pip3 install openapi-schema-validator",
    "postman":             "snap install postman  OR  https://www.postman.com",
    "insomnia":            "snap install insomnia  OR  https://insomnia.rest",
    "libc-database":       "git clone https://github.com/niklasb/libc-database",
    "one-gadget":          "gem install one_gadget",
    "volatility":          "pip3 install volatility  (v2, legacy)",
    "sleuthkit":           "apt install sleuthkit",
    "hashcat-utils":       "apt install hashcat-utils",
    "coercer":             "pip3 install coercer",
    "cloudbrute":          "go install github.com/d3mondev/puredns/v2@latest",
    "s3scanner":           "pip3 install s3scanner",
    "prowler":             "pip3 install prowler",
    "scout-suite":         "pip3 install scout-suite",
    "kube-hunter":         "pip3 install kube-hunter",
    "kube-bench":          "https://github.com/aquasecurity/kube-bench/releases",
    "docker-bench-security": "https://github.com/docker/docker-bench-security",
    "falco":               "apt install falco  (requiere kernel headers)",
    "clair":               "docker pull quay.io/projectquay/clair",
    "ligolo-ng":           "https://github.com/nicocha30/ligolo-ng/releases",
    "uncover":             "go install github.com/projectdiscovery/uncover/cmd/uncover@latest",
    "interactsh-client":   "go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest",
    "pwninit":             "cargo install pwninit",
}


def check_tool(name: str) -> Tuple[bool, str]:
    candidates = [name] + ALIASES.get(name, [])
    seen: List[str] = []
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.append(candidate)
        if candidate.startswith("python3 -c 'import "):
            module = candidate.split("'import ")[1].rstrip("'")
            try:
                __import__(module)
                return True, f"python module '{module}'"
            except ImportError:
                continue
        if shutil.which(candidate):
            return True, candidate
    return False, ""


def query_server(server_url: str) -> Dict[str, bool]:
    try:
        import urllib.request
        req = urllib.request.urlopen(f"{server_url}/health", timeout=3)
        data = json.loads(req.read())
        return data.get("tools_status", {})
    except Exception:
        return {}


# ── Install helpers ────────────────────────────────────────────────────────────

IS_ROOT = os.geteuid() == 0


def _needs_sudo(cmd: str) -> bool:
    return cmd.startswith("apt ") and not IS_ROOT


def _build_cmd(cmd_str: str) -> List[str]:
    """Convierte un string de comando en lista, añadiendo sudo si es necesario."""
    parts = cmd_str.split()
    if _needs_sudo(cmd_str):
        return ["sudo"] + parts
    return parts


def _pkg_manager_available(cmd_str: str) -> bool:
    """Verifica que el primer binario del comando esté disponible."""
    binary = cmd_str.split()[0]
    if binary == "sudo":
        binary = cmd_str.split()[1]
    return shutil.which(binary) is not None


def run_install(tool: str, dry_run: bool = False) -> Tuple[bool, str]:
    """
    Intenta instalar `tool`. Devuelve (success, message).
    Prueba cada comando en INSTALL_COMMANDS[tool] en orden hasta que uno funcione.
    """
    commands = INSTALL_COMMANDS.get(tool)

    if not commands:
        # Puede estar en manual
        hint = MANUAL_INSTALL.get(tool, "")
        if hint:
            return False, f"instalación manual requerida: {hint}"
        return False, "sin instrucciones de instalación"

    for cmd_str in commands:
        if not _pkg_manager_available(cmd_str):
            continue  # ese gestor no está disponible, prueba el siguiente

        cmd = _build_cmd(cmd_str)

        if dry_run:
            return True, f"[dry-run] {' '.join(cmd)}"

        print(f"    {C}$ {' '.join(cmd)}{X}")
        try:
            result = subprocess.run(
                cmd,
                text=True,
                capture_output=False,   # deja que el output fluya al terminal
                timeout=300,
            )
            if result.returncode == 0:
                return True, "ok"
            else:
                # Intentar el siguiente comando si este falló
                continue
        except subprocess.TimeoutExpired:
            return False, "timeout (>5 min)"
        except Exception as e:
            return False, str(e)

    return False, "ningún gestor de paquetes disponible para este tool"


def collect_missing(category_filter: str = "") -> Dict[str, List[str]]:
    """Devuelve dict {categoria: [tools_faltantes]}."""
    missing: Dict[str, List[str]] = {}
    for category, tools in CATEGORIES.items():
        if category_filter and category_filter.lower() not in category.lower():
            continue
        for tool in tools:
            if not check_tool(tool)[0]:
                missing.setdefault(category, []).append(tool)
    return missing


def install_missing(
    missing: Dict[str, List[str]],
    dry_run: bool = False,
    yes: bool = False,
) -> None:
    """Instala todas las herramientas faltantes del dict."""
    flat = [(cat, t) for cat, tools in missing.items() for t in tools]
    if not flat:
        print(f"\n{G}✓ No hay herramientas faltantes para instalar.{X}\n")
        return

    # Deduplicar comandos de apt para hacer un solo apt install
    apt_pkgs: List[str] = []
    non_apt: List[Tuple[str, str]] = []

    for _cat, tool in flat:
        cmds = INSTALL_COMMANDS.get(tool, [])
        if cmds and cmds[0].startswith("apt install"):
            # extrae el nombre del paquete
            pkg = cmds[0].replace("apt install -y", "").strip()
            if pkg not in apt_pkgs:
                apt_pkgs.append(pkg)
        else:
            non_apt.append((_cat, tool))

    # Mostrar plan
    print(f"\n{B}{'─'*55}{X}")
    print(f"{B}PLAN DE INSTALACIÓN  ({len(flat)} herramientas){X}\n")

    if apt_pkgs:
        sudo_prefix = "" if IS_ROOT else "sudo "
        print(f"  {Y}apt ({len(apt_pkgs)} paquetes):{X}")
        print(f"    {C}$ {sudo_prefix}apt install -y {' '.join(apt_pkgs)}{X}")

    for _cat, tool in non_apt:
        cmds = INSTALL_COMMANDS.get(tool, [])
        if cmds:
            cmd_str = cmds[0]
            prefix = "sudo " if _needs_sudo(cmd_str) else ""
            print(f"  {D}{tool}:{X} {C}{prefix}{cmd_str}{X}")
        else:
            hint = MANUAL_INSTALL.get(tool, "sin instrucciones")
            print(f"  {D}{tool}:{X} {Y}manual → {hint}{X}")

    print()

    if dry_run:
        print(f"{Y}[dry-run] Nada instalado. Usa sin --dry-run para instalar.{X}\n")
        return

    if not yes:
        try:
            resp = input(f"{Y}¿Proceder con la instalación? [s/N] {X}").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print(f"\n{R}Cancelado.{X}\n")
            return
        if resp not in ("s", "si", "sí", "y", "yes"):
            print(f"{R}Cancelado.{X}\n")
            return

    # ── Instalar apt batch primero ─────────────────────────────────────────────
    installed_ok: List[str] = []
    installed_fail: List[Tuple[str, str]] = []
    skipped_manual: List[Tuple[str, str]] = []

    if apt_pkgs:
        print(f"\n{B}[APT] Instalando {len(apt_pkgs)} paquetes...{X}")
        cmd = (["sudo"] if not IS_ROOT else []) + ["apt", "install", "-y"] + apt_pkgs
        try:
            result = subprocess.run(cmd, timeout=600)
            if result.returncode == 0:
                print(f"{G}✓ apt completado{X}")
                # Verificar cuáles realmente se instalaron
                for _cat, tool in flat:
                    cmds = INSTALL_COMMANDS.get(tool, [])
                    if cmds and cmds[0].startswith("apt install"):
                        if check_tool(tool)[0]:
                            installed_ok.append(tool)
                        else:
                            installed_fail.append((tool, "no encontrado tras apt install"))
            else:
                for _cat, tool in flat:
                    cmds = INSTALL_COMMANDS.get(tool, [])
                    if cmds and cmds[0].startswith("apt install"):
                        installed_fail.append((tool, f"apt salió con código {result.returncode}"))
        except Exception as e:
            for _cat, tool in flat:
                cmds = INSTALL_COMMANDS.get(tool, [])
                if cmds and cmds[0].startswith("apt install"):
                    installed_fail.append((tool, str(e)))

    # ── Instalar el resto uno por uno ─────────────────────────────────────────
    for _cat, tool in non_apt:
        cmds = INSTALL_COMMANDS.get(tool, [])
        if not cmds:
            hint = MANUAL_INSTALL.get(tool, "sin instrucciones")
            skipped_manual.append((tool, hint))
            continue

        print(f"\n{B}[{tool}]{X} instalando...")
        ok, msg = run_install(tool, dry_run=False)

        if ok:
            # Re-verificar
            if check_tool(tool)[0]:
                print(f"  {G}✓ {tool} instalado correctamente{X}")
                installed_ok.append(tool)
            else:
                print(f"  {Y}⚠ comando exitoso pero {tool} no aparece en PATH{X}")
                installed_fail.append((tool, "no encontrado en PATH tras instalación"))
        else:
            print(f"  {R}✗ {tool}: {msg}{X}")
            if tool in MANUAL_INSTALL:
                print(f"    {D}→ {MANUAL_INSTALL[tool]}{X}")
                skipped_manual.append((tool, MANUAL_INSTALL[tool]))
            else:
                installed_fail.append((tool, msg))

    # ── Resumen de instalación ─────────────────────────────────────────────────
    print(f"\n{B}{'─'*55}{X}")
    print(f"{B}RESULTADO{X}")
    if installed_ok:
        print(f"  {G}✓ Instalados ({len(installed_ok)}):{X} {', '.join(installed_ok)}")
    if installed_fail:
        print(f"  {R}✗ Fallaron ({len(installed_fail)}):{X}")
        for t, reason in installed_fail:
            print(f"      {t}: {reason}")
    if skipped_manual:
        print(f"  {Y}⚠ Requieren instalación manual ({len(skipped_manual)}):{X}")
        for t, hint in skipped_manual:
            print(f"      {t}: {hint}")
    print()


# ── Display helpers ────────────────────────────────────────────────────────────

def print_categories(
    server_status: Dict[str, bool],
    missing_only: bool,
    category_filter: str,
    output_json: bool,
) -> Tuple[int, int, Dict[str, List[str]]]:
    total_found = total_missing = 0
    all_missing: Dict[str, List[str]] = {}
    json_output: Dict[str, dict] = {}

    for category, tools in CATEGORIES.items():
        if category_filter and category_filter.lower() not in category.lower():
            continue

        found_list, missing_list = [], []

        for tool in tools:
            local_found, found_as = check_tool(tool)
            server_found = server_status.get(tool, None)

            if local_found:
                found_list.append((tool, found_as, server_found))
                total_found += 1
            else:
                missing_list.append((tool, server_found))
                total_missing += 1

            if output_json:
                json_output[tool] = {
                    "category": category,
                    "present": local_found,
                    "found_as": found_as if local_found else None,
                    "server_status": server_found,
                    "install_cmd": INSTALL_COMMANDS.get(tool, [None])[0] or MANUAL_INSTALL.get(tool, ""),
                    "needs_manual": tool in MANUAL_INSTALL and tool not in INSTALL_COMMANDS,
                }

        if missing_only and not missing_list:
            continue

        pct = int(len(found_list) / len(tools) * 100) if tools else 0
        bar_len = 20
        filled = int(bar_len * pct / 100)
        bc = G if pct >= 80 else (Y if pct >= 40 else R)
        bar = f"{bc}{'█' * filled}{D}{'░' * (bar_len - filled)}{X}"
        print(f"{B}{category}{X}  {bar}  {bc}{len(found_list)}/{len(tools)}{X} ({pct}%)")

        if not missing_only:
            for tool, found_as, srv in found_list:
                srv_icon = f" {Y}[server: no]{X}" if srv is False else ""
                alias_note = f" {D}→ {found_as}{X}" if found_as != tool else ""
                print(f"  {G}✓{X} {W}{tool}{X}{alias_note}{srv_icon}")

        for tool, srv in missing_list:
            cmds = INSTALL_COMMANDS.get(tool)
            hint = cmds[0] if cmds else MANUAL_INSTALL.get(tool, "")
            srv_icon = f" {Y}[server: sí]{X}" if srv is True else ""
            manual_icon = f" {P}[manual]{X}" if tool in MANUAL_INSTALL and not cmds else ""
            print(f"  {R}✗{X} {tool}{srv_icon}{manual_icon}")
            if hint:
                print(f"    {D}{hint}{X}")
            all_missing.setdefault(category, []).append(tool)

        print()

    if output_json:
        print(json.dumps(json_output, indent=2))

    return total_found, total_missing, all_missing


# ── Main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="HexStrike — verificador e instalador de herramientas del MCP",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
ejemplos:
  python3 check_tools.py                          # ver todo
  python3 check_tools.py --missing-only           # solo faltantes
  python3 check_tools.py --install                # instalar todas las faltantes
  python3 check_tools.py --install --yes          # sin pedir confirmación
  python3 check_tools.py --install --dry-run      # ver qué instalaría sin hacer nada
  python3 check_tools.py --install --category web # instalar solo las de categoría web
  python3 check_tools.py --category binary        # ver solo binary/reversing
  python3 check_tools.py --json                   # salida JSON
""",
    )
    parser.add_argument("--server", default="http://127.0.0.1:8888")
    parser.add_argument("--missing-only", action="store_true",
                        help="Mostrar solo herramientas faltantes")
    parser.add_argument("--category", default="",
                        help="Filtrar por categoría (ej: 'web', 'binary', 'cloud')")
    parser.add_argument("--install", action="store_true",
                        help="Instalar herramientas faltantes")
    parser.add_argument("--yes", "-y", action="store_true",
                        help="No pedir confirmación antes de instalar")
    parser.add_argument("--dry-run", action="store_true",
                        help="Mostrar qué se instalaría sin ejecutar nada")
    parser.add_argument("--json", dest="output_json", action="store_true",
                        help="Salida en JSON")
    parser.add_argument("--no-color", action="store_true")
    args = parser.parse_args()

    if args.no_color:
        global R, G, Y, C, P, W, D, B, X
        R = G = Y = C = P = W = D = B = X = ""

    if not args.output_json:
        print(f"\n{R}{B}╔═══════════════════════════════════════════════════╗{X}")
        print(f"{R}{B}║   HexStrike AI — Tool Checker & Installer         ║{X}")
        print(f"{R}{B}╚═══════════════════════════════════════════════════╝{X}\n")

    server_status = query_server(args.server)
    if not args.output_json:
        if server_status:
            print(f"{G}✓ Servidor disponible en {args.server}{X}\n")
        else:
            print(f"{D}⚠ Servidor no disponible — usando PATH local{X}\n")

    total_found, total_missing, all_missing = print_categories(
        server_status,
        missing_only=args.missing_only or args.install,
        category_filter=args.category,
        output_json=args.output_json,
    )

    if args.output_json:
        return

    # ── Summary ────────────────────────────────────────────────────────────────
    grand = total_found + total_missing
    pct = int(total_found / grand * 100) if grand else 0
    sc = G if pct >= 80 else (Y if pct >= 50 else R)

    print(f"{B}{'─'*55}{X}")
    print(f"{B}RESUMEN{X}  {sc}{total_found}/{grand} instaladas ({pct}%){X}")

    if all_missing:
        flat = [t for tools in all_missing.values() for t in tools]
        can_auto = [t for t in flat if t in INSTALL_COMMANDS]
        needs_manual = [t for t in flat if t not in INSTALL_COMMANDS]

        print(f"\n{R}{B}Faltantes ({len(flat)}):{X}")
        for cat, tools in all_missing.items():
            print(f"  {D}{cat}:{X} {', '.join(tools)}")

        if can_auto:
            print(f"\n{C}→ {len(can_auto)} se pueden instalar automáticamente.{X}")
            print(f"  {D}Ejecuta:{X} python3 check_tools.py --install{X}")
        if needs_manual:
            print(f"{Y}→ {len(needs_manual)} requieren instalación manual:{X} {', '.join(needs_manual)}")

    essential = CATEGORIES.get("🔴 Essential", [])
    missing_ess = [t for t in essential if not check_tool(t)[0]]
    if missing_ess:
        print(f"\n{R}{B}⚠  ESENCIALES FALTANTES:{X} {', '.join(missing_ess)}")
    else:
        print(f"\n{G}✓ Todas las herramientas esenciales están instaladas.{X}")

    print()

    # ── Install ────────────────────────────────────────────────────────────────
    if args.install:
        missing = collect_missing(args.category)
        install_missing(missing, dry_run=args.dry_run, yes=args.yes)


if __name__ == "__main__":
    main()
