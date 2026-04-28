"""Suspicious patterns to look for in extracted document content.

Each indicator has a name, a regex pattern, a weight that contributes to the
total risk score, and a one-line explanation of why it's flagged.
"""

from __future__ import annotations

import re

# (name, pattern, weight, explanation)
VBA_INDICATORS: list[tuple[str, re.Pattern, int, str]] = [
    # Auto-execute hooks
    ("vba_autoopen", re.compile(r"\bAuto[_]?Open\b", re.IGNORECASE), 25, "macro auto-runs on document open"),
    ("vba_autoclose", re.compile(r"\bAuto[_]?Close\b", re.IGNORECASE), 15, "macro auto-runs on document close"),
    ("vba_document_open", re.compile(r"\bDocument_Open\b", re.IGNORECASE), 25, "Word auto-execute hook"),
    ("vba_workbook_open", re.compile(r"\bWorkbook_Open\b", re.IGNORECASE), 25, "Excel auto-execute hook"),
    ("vba_autoexec", re.compile(r"\bAutoExec\b", re.IGNORECASE), 25, "legacy auto-execute hook"),
    # Shell / process execution
    ("vba_shell", re.compile(r"\bShell\s*\(", re.IGNORECASE), 25, "Shell() call — process execution"),
    ("vba_wscript_shell", re.compile(r"WScript\.Shell", re.IGNORECASE), 25, "WScript.Shell — runs commands"),
    ("vba_powershell_string", re.compile(r"powershell(?:\.exe)?", re.IGNORECASE), 25, "PowerShell invocation reference"),
    ("vba_iex", re.compile(r"\b(?:IEX|Invoke-Expression)\b", re.IGNORECASE), 30, "PowerShell Invoke-Expression — runs strings as code"),
    ("vba_createobject", re.compile(r"CreateObject\s*\(", re.IGNORECASE), 10, "CreateObject — late-bound COM, often used to dodge static analysis"),
    # Network / download
    ("vba_xmlhttp", re.compile(r"(?:MSXML2|Microsoft)\.XMLHTTP", re.IGNORECASE), 25, "XMLHTTP — used to download payloads"),
    ("vba_winhttp", re.compile(r"WinHttp\.WinHttpRequest", re.IGNORECASE), 25, "WinHttp — HTTP download primitive"),
    ("vba_urldownload", re.compile(r"URLDownloadToFile", re.IGNORECASE), 30, "URLDownloadToFile — direct payload download"),
    ("vba_webclient", re.compile(r"Net\.WebClient|DownloadString|DownloadFile", re.IGNORECASE), 30, "PowerShell WebClient pattern — download cradle"),
    # Process injection / memory
    ("vba_virtualalloc", re.compile(r"VirtualAlloc(?:Ex)?", re.IGNORECASE), 35, "VirtualAlloc — shellcode allocation"),
    ("vba_rtlmove", re.compile(r"RtlMoveMemory|MemCopy", re.IGNORECASE), 35, "memory copy primitive used for shellcode injection"),
    ("vba_createremotethread", re.compile(r"CreateRemoteThread", re.IGNORECASE), 40, "CreateRemoteThread — process injection"),
    # Persistence
    ("vba_run_key", re.compile(r"HKCU\\.*Run\b", re.IGNORECASE), 25, "registry Run key — persistence"),
    ("vba_schtasks", re.compile(r"\bschtasks\b", re.IGNORECASE), 25, "scheduled task creation — persistence"),
    # Obfuscation
    ("vba_chr_obfuscation", re.compile(r"(?:Chr\s*\(\s*\d+\s*\)\s*&\s*){3,}"), 15, "Chr()-based string concatenation — obfuscation"),
    ("vba_strreverse", re.compile(r"\bStrReverse\b", re.IGNORECASE), 10, "StrReverse — string reversal obfuscation"),
    ("vba_hex_string", re.compile(r"\"&H[0-9A-Fa-f]{2,}"), 10, "hex literal sprinkles in source — likely encoded payload"),
    # Anti-analysis
    ("vba_sleep", re.compile(r"\bSleep\s*\(\s*\d{4,}\s*\)", re.IGNORECASE), 10, "long Sleep — sandbox evasion"),
    ("vba_winmgmts_query", re.compile(r"WinMgmts:.*VirtualBox|WinMgmts:.*VMware", re.IGNORECASE), 20, "WMI query for VM presence — sandbox detection"),
]

PDF_INDICATORS: list[tuple[str, re.Pattern, int, str]] = [
    ("pdf_javascript", re.compile(r"/JavaScript|/JS\b"), 30, "embedded JavaScript"),
    ("pdf_launch", re.compile(r"/Launch\b"), 35, "/Launch action — runs an external program"),
    ("pdf_openaction", re.compile(r"/OpenAction\b"), 20, "/OpenAction — runs on document open"),
    ("pdf_aa", re.compile(r"/AA\b"), 15, "/AA — additional action triggered by user interaction"),
    ("pdf_embeddedfile", re.compile(r"/EmbeddedFile\b"), 25, "/EmbeddedFile — binary attachment"),
    ("pdf_xfa", re.compile(r"/XFA\b"), 20, "/XFA forms — historically associated with exploits"),
    ("pdf_uri_http", re.compile(r"/URI\s*\(\s*http://"), 15, "/URI to non-HTTPS URL"),
    ("pdf_uri_data", re.compile(r"/URI\s*\(\s*data:"), 25, "/URI with data: scheme — embedded inline payload"),
    ("pdf_acroform", re.compile(r"/AcroForm\b"), 5, "AcroForm — common in benign docs but combined with JS is suspicious"),
    ("pdf_encrypt", re.compile(r"/Encrypt\b"), 10, "encrypted PDF — could hide payload from inspection"),
]
