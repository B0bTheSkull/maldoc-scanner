# MalDoc Scanner

> **Static analyzer for malicious Office docs and PDFs — extracts and scores VBA macros, embedded JavaScript, suspicious actions, and IOCs without ever opening the file in Office or a viewer.**

![Python](https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/status-alpha-orange?style=flat-square)

---

## What It Does

You receive a suspicious attachment — a `.xlsm`, `.docm`, or `.pdf`. MalDoc Scanner extracts the parts attackers actually use (VBA source, PDF actions, embedded JavaScript) and scores them against a catalog of indicators drawn from real malware families.

**Two extraction backends:**

- **Office** (`.doc`, `.docx`, `.docm`, `.xls`, `.xlsm`, `.ppt`, etc.) — uses [oletools / olevba](https://github.com/decalage2/oletools) to pull every macro stream
- **PDF** — uses [pypdf](https://github.com/py-pdf/pypdf) to walk the catalog and dump every object string

**One scoring engine:**

- 24 VBA indicators across auto-execute hooks, shell/process execution, network downloads, process injection, persistence, obfuscation, and anti-analysis
- 10 PDF indicators across `/JavaScript`, `/Launch`, `/OpenAction`, `/AA`, `/EmbeddedFile`, `/XFA`, `/URI`, and encryption flags
- IOC extraction: URLs and IPs from extracted content

---

## Installation

```bash
git clone https://github.com/B0bTheSkull/maldoc-scanner.git
cd maldoc-scanner
pip install -e .
```

---

## Usage

### Analyze an Office document

```bash
maldoc --file suspicious.docm
```

### Analyze a PDF

```bash
maldoc --file suspicious.pdf
```

### Analyze pre-extracted text (no oletools / pypdf needed)

Use this when you already have the macro source dumped (e.g., from olevba in another environment), or when you're testing the scoring engine on a synthetic sample:

```bash
maldoc --file extracted_macro.txt --from-text --type office
```

### JSON output

```bash
maldoc --file sample.docm --json > report.json
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Low or medium severity |
| `1` | High severity — file very likely malicious |
| `2` | Could not read or classify the file |

---

## Example Output

```
MalDoc Scanner
Source: examples/sample_macro.txt  |  Type: office  |  Score: 100/100  |  Severity: HIGH

────────────────────────────────────────────────────────────────────────
[  HIGH] + 30  vba_iex
        PowerShell Invoke-Expression — runs strings as code
[  HIGH] + 30  vba_webclient
        PowerShell WebClient pattern — download cradle
[  HIGH] + 25  vba_autoopen
        macro auto-runs on document open
[  HIGH] + 25  vba_wscript_shell
        WScript.Shell — runs commands
[  HIGH] + 25  vba_powershell_string
        PowerShell invocation reference
[  HIGH] + 25  vba_xmlhttp
        XMLHTTP — used to download payloads
[  HIGH] + 25  vba_schtasks
        scheduled task creation — persistence
... (truncated)
────────────────────────────────────────────────────────────────────────

URLs (1):
  http://attacker.example/payload.bin
```

---

## Why I Built This

Malware analysis is hard. Even basic static analysis is a wall of `olevba`, `peepdf`, `pdf-parser`, `xorsearch` output that takes a while to internalize. MalDoc Scanner takes one of the dimensions of that workflow — "is this dangerous, and why?" — and gives a 5-second answer that you can act on.

It's deliberately not a sandbox, not a deobfuscator, not a decoder. Those are different skills and different tools (CAPE, [VirusTotal](https://www.virustotal.com), Box-of-Doom). MalDoc Scanner is the front-line triage that tells you whether the artifact deserves them.

The IOC extraction step pairs with [ThreatPulse](https://github.com/B0bTheSkull/threatpulse) — drop the URLs into a ThreatPulse lookup pipeline and you have IOC enrichment immediately.

---

## Safety Notes

- The tool only *parses* documents — it never opens them in Office or a renderer. But you should still handle suspicious files in an isolated VM/container.
- `oletools` does its own VBA decompilation; the source it returns can include obfuscated strings that you should not paste into a place that auto-renders or executes them.

---

## Roadmap

- [ ] RTF document support (different parsing path than DOCX)
- [ ] OOXML relationship analysis (external image / template references)
- [ ] Full HTML report mode for engagement deliverables
- [ ] Sigma rule output describing the matched indicators (so [SigmaForge](https://github.com/B0bTheSkull/sigmaforge) can convert)
- [ ] Bulk mode: scan a directory, emit one row per file
- [ ] Hash-based VirusTotal lookup (optional, requires API key)

---

## License

MIT — see [LICENSE](LICENSE)
