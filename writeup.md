# Triaging suspicious attachments without detonating them

> "The first question in a phishing investigation isn't 'what did this do?' — it's 'should I open it to find out?' MalDoc Scanner answers that before you ever touch the file."

## TL;DR

I built a Python CLI that statically analyzes Office documents and PDFs against a catalog of 34 malware indicators — auto-execute hooks, shell/download primitives, process injection APIs, persistence mechanisms, obfuscation patterns, and risky PDF actions. It scores a file in under a second, emits a severity verdict, and pulls IOCs (URLs and IPs) from the extracted content. No Office, no renderer, no detonation.

---

## Why static analysis before anything else

The standard way a SOC analyst encounters a suspicious doc: someone reported a phishing email, someone clicked it, something happened, now you have a ticket. You pull the attachment. What do you do next?

Opening it in Office to see what happens is the wrong call for two reasons. First, that's detonation — you're handing the attacker exactly the execution environment they wrote for. Second, even if you have a sandbox, submission takes time. You need a preliminary yes/no before you queue a full dynamic analysis job.

Static analysis fills that gap. Parse the structure. Extract the parts that do things. Check them against patterns. Return an answer. The whole thing runs offline, in milliseconds, on a file you never have to touch in a live environment.

That's what MalDoc Scanner does.

---

## What I actually built

Two extraction backends feed one scoring engine.

**Office documents** (`.doc`, `.docm`, `.xls`, `.xlsm`, `.pptm`, and variants) are handled by [oletools / olevba](https://github.com/decalage2/oletools), which decompiles every VBA macro stream from the OLE container. The raw source text comes back to the scoring engine.

**PDFs** are handled by [pypdf](https://github.com/py-pdf/pypdf), which walks the catalog object tree and dumps every string it encounters — action entries, annotation dictionaries, embedded object headers.

The scoring engine runs a regex catalog against whatever text it received. Matches add to a cumulative score, capped at 100. Score below 25 is LOW; 25–59 is MEDIUM; 60+ is HIGH. HIGH exits with code 1 so CI pipelines and triage scripts can act on it directly.

IOC extraction runs as a second pass: URLs matching `https?://` and bare IPv4 addresses are pulled from the same text. Those feed directly into threat-intel lookup pipelines — I pair them with [ThreatPulse](https://github.com/B0bTheSkull/threatpulse) in my own workflow.

---

## The 34 indicators

### VBA / Office (24 indicators)

**Auto-execute hooks** — the entry points attackers use so macros fire without user interaction beyond opening the document:

| Indicator | Weight | What it flags |
|---|---|---|
| `vba_autoopen` | 25 | `AutoOpen()` — fires on doc open |
| `vba_autoclose` | 15 | `AutoClose()` — fires on doc close |
| `vba_document_open` | 25 | `Document_Open` — Word-specific hook |
| `vba_workbook_open` | 25 | `Workbook_Open` — Excel-specific hook |
| `vba_autoexec` | 25 | `AutoExec` — legacy Word hook |

**Shell / process execution** — how macros run external commands:

| Indicator | Weight | What it flags |
|---|---|---|
| `vba_shell` | 25 | `Shell()` call |
| `vba_wscript_shell` | 25 | `WScript.Shell` object |
| `vba_powershell_string` | 25 | Any `powershell.exe` reference |
| `vba_iex` | 30 | `IEX` / `Invoke-Expression` — executes strings as code |
| `vba_createobject` | 10 | Late-bound `CreateObject()` — common obfuscation path |

**Network / payload download** — the delivery mechanism for second-stage malware:

| Indicator | Weight | What it flags |
|---|---|---|
| `vba_xmlhttp` | 25 | `MSXML2.XMLHTTP` |
| `vba_winhttp` | 25 | `WinHttp.WinHttpRequest` |
| `vba_urldownload` | 30 | `URLDownloadToFile` |
| `vba_webclient` | 30 | PowerShell `Net.WebClient` / `DownloadString` / `DownloadFile` |

**Process injection / memory** — shellcode staging primitives:

| Indicator | Weight | What it flags |
|---|---|---|
| `vba_virtualalloc` | 35 | `VirtualAlloc` / `VirtualAllocEx` |
| `vba_rtlmove` | 35 | `RtlMoveMemory` / `MemCopy` |
| `vba_createremotethread` | 40 | `CreateRemoteThread` — cross-process injection |

**Persistence** — mechanisms to survive reboot:

| Indicator | Weight | What it flags |
|---|---|---|
| `vba_run_key` | 25 | `HKCU\...\Run` registry key |
| `vba_schtasks` | 25 | `schtasks` — scheduled task creation |

**Obfuscation** — how attackers hide strings from basic grep:

| Indicator | Weight | What it flags |
|---|---|---|
| `vba_chr_obfuscation` | 15 | Three or more chained `Chr()` calls |
| `vba_strreverse` | 10 | `StrReverse()` |
| `vba_hex_string` | 10 | `"&H...` hex literals |

**Anti-analysis / sandbox evasion:**

| Indicator | Weight | What it flags |
|---|---|---|
| `vba_sleep` | 10 | `Sleep()` with a 4-digit or longer delay (sandbox timeout evasion) |
| `vba_winmgmts_query` | 20 | WMI query for VirtualBox or VMware — VM detection |

### PDF (10 indicators)

| Indicator | Weight | What it flags |
|---|---|---|
| `pdf_javascript` | 30 | `/JavaScript` or `/JS` action |
| `pdf_launch` | 35 | `/Launch` — runs an external process |
| `pdf_openaction` | 20 | `/OpenAction` — runs automatically on open |
| `pdf_aa` | 15 | `/AA` — additional actions on user interaction |
| `pdf_embeddedfile` | 25 | `/EmbeddedFile` — binary attachment |
| `pdf_xfa` | 20 | `/XFA` forms — associated with historical exploits |
| `pdf_uri_http` | 15 | `/URI` pointing to a plain `http://` URL |
| `pdf_uri_data` | 25 | `/URI` with `data:` scheme — inline payload |
| `pdf_acroform` | 5 | `/AcroForm` — benign alone, suspicious with JS |
| `pdf_encrypt` | 10 | `/Encrypt` — encrypted PDF hides content from inspection |

---

## Demo

The repo ships two synthetic samples in `examples/` — plain text representing extracted macro source and PDF catalog content respectively. They're modeled on real downloader patterns but contain no functional code or live infrastructure.

```
$ maldoc --file examples/sample_macro.txt --from-text --type office

MalDoc Scanner
Source: examples/sample_macro.txt  |  Type: office  |  Score: 100/100  |  Severity: HIGH

────────────────────────────────────────────────────────────────────────
[  HIGH] + 25  vba_autoopen        macro auto-runs on document open
[  HIGH] + 25  vba_wscript_shell   WScript.Shell — runs commands
[  HIGH] + 25  vba_powershell_string  PowerShell invocation reference
[  HIGH] + 25  vba_xmlhttp         XMLHTTP — used to download payloads
[  HIGH] + 25  vba_schtasks        scheduled task creation — persistence
[  HIGH] + 15  vba_chr_obfuscation Chr()-based string concatenation — obfuscation
[  HIGH] + 10  vba_createobject    CreateObject — late-bound COM
────────────────────────────────────────────────────────────────────────

URLs (1):
  http://attacker.example/payload.bin
```

That's AutoOpen + WScript.Shell + PowerShell + XMLHTTP download + schtasks persistence + Chr() obfuscation. In a real triage, this file goes straight to sandbox and the sender domain gets pivoted on — no need to open it first.

Full output for both samples (Office and PDF) is in `screenshots/sample-scan.txt`.

---

## How it fits into a SOC workflow

```
[Email gateway alert]
        |
        v
  maldoc --file attachment.xlsm
        |
   severity == HIGH?
        |
    yes |                no
        v                v
  Queue to sandbox    Log + close ticket
  Pivot on IOCs       (or recheck manually)
  Escalate to IR
```

The `--json` flag makes this scriptable. Drop it in a Python triage wrapper, pass it a directory of attachments, and you have a severity-sorted queue before a sandbox has processed a single file. The exit code (1 = HIGH) means shell pipelines and CI jobs can gate on it directly.

The IOC output pairs naturally with threat-intel enrichment. URLs extracted from macros or PDF catalogs get passed to [ThreatPulse](https://github.com/B0bTheSkull/threatpulse) for reputation lookups. Same artifact, two analysis steps, no manual copy-paste.

---

## What it doesn't catch

Honesty about limits matters here.

**Encrypted documents.** A password-protected `.docm` or an `/Encrypt`-flagged PDF hides its content from the parser. MalDoc Scanner flags the encryption indicator but can't score what it can't read. For those, you need the password or a tool with known-password brute-force capability.

**Heavily obfuscated payloads.** The indicator catalog catches common obfuscation patterns — `Chr()` chains, hex literals, `StrReverse`. It won't catch a macro that builds its payload from base64-decoded chunks across 50 functions, or one that pulls its command string from a remote template. Obfuscation buys the attacker some indicator coverage; it doesn't buy full evasion from a sandbox, but it does from a regex.

**Novel PDF exploits.** The PDF catalog covers the known action types. A spec-abusing exploit that uses a valid but unusual object graph to trigger a reader vulnerability may not hit any indicator. MalDoc Scanner can't detect what it hasn't seen a pattern for.

**No behavioral analysis.** This is by design. Static analysis is a triage layer — it tells you whether to escalate, not what happened. For behavioral analysis, the tool feeds CAPE, VirusTotal, or a Box-of-Doom.

---

## What's next

- **RTF support** — different parsing path, significant attack surface, frequently abused in spearphishing
- **OOXML relationship analysis** — external image and template references in `.docx` files that phone home without executing macros
- **Sigma rule output** — each matched indicator generates a Sigma rule, compatible with [SigmaForge](https://github.com/B0bTheSkull/sigmaforge) for SIEM deployment
- **Bulk mode** — scan a directory, emit one row per file, sortable by score
- **VirusTotal hash lookup** — optional enrichment step with a user-supplied API key

---

## Resources

- [oletools / olevba](https://github.com/decalage2/oletools) — the OLE/VBA extraction engine underneath the Office backend
- [pypdf](https://github.com/py-pdf/pypdf) — the PDF parsing library
- [CAPE Sandbox](https://capesandbox.com) — where HIGH-scoring files go next
- [Didier Stevens' PDF tools](https://blog.didierstevens.com/programs/pdf-tools/) — if you want to go deeper into PDF structure analysis
- The repo: [github.com/B0bTheSkull/maldoc-scanner](https://github.com/B0bTheSkull/maldoc-scanner)
