# Taraf
Taraf is a coalition of Enumeration tools, nothing new or novel, I was just too stressed to always know what tool to use on a pentest engagement, so this is more like run and forget enum script

> **map the edge**: attack surface enumeration pipeline

`taraf` is a single file bash orchestrator that chains the ProjectDiscovery stack (subfinder, dnsx, naabu, httpx, nuclei, tlsx, …) together with ffuf, nmap, WhatWeb, dalfox, gowitness and friends into one resumable, scope aware recon pipeline.

Feed it anything, it could be a domain, a URL, a CIDR, an IP list, a directory of target files, or an existing nmap scan, and it walks five phases (passive → discovery → active → deep → report) and drops a timestamped output directory with structured results, an engagement metadata file, a Markdown/CSV report, and per-finding verification scripts.

I started this manually, it was a tad tedious then had an AI agent mix it all in, feel free to verify, fix any issues as you see fit, it was mostly tailored to my system configs in general but should work in all.

---

## Table of contents

- [Why taraf](#why-taraf)
- [Install](#install)
- [Quick start](#quick-start)
- [Input modes](#input-modes)
- [Engagement modes](#engagement-modes---mode)
- [Recon modes](#recon-modes---recon-mode)
- [Flags](#flags)
  - [Authentication](#authentication)
  - [Scope](#scope)
  - [Phase control](#phase-control)
  - [Disabling tests](#disabling-tests)
  - [Opt-in modules](#opt-in-modules)
  - [WAF / Cloudflare](#waf--cloudflare)
  - [Scan tuning](#scan-tuning)
  - [Other](#other)
- [Environment variables](#environment-variables)
- [Pause / resume](#pause--resume)
- [Resuming runs and failure handling](#resuming-runs-and-failure-handling)
- [Output layout](#output-layout)
- [OPSEC notes](#opsec-notes)
- [Examples](#examples)
- [Disclaimer](#disclaimer)

---

## Why taraf

- **One command, full surface.** CT logs → DNS → port scan → HTTP probe → vhosts → backups/sensitive files → endpoints → JS secrets → tech-mapped nuclei → XSS → screenshots → report.
- **Baseline-aware probing.** Every host gets a random-404 calibration; wildcard/catch-all responses are filtered out of backup and admin-panel hits instead of drowning you in false positives.
- **Tech-mapped nuclei.** httpx + WhatWeb fingerprints are mapped to nuclei template tags, so nuclei only fires templates relevant to what the target actually runs.
- **Resumable.** Sub-phase state tracking with `--resume`; failed sub-phases are recorded as failed and retried, not silently skipped.
- **Pausable.** Press **Enter** mid-run to SIGSTOP the in-flight scan; Enter again to resume exactly where it froze.
- **Scope-enforced.** Fixed-string include/exclude lists applied to raw inputs *and* enumerated hosts; the run aborts if filtering would leave zero targets.
- **OPSEC modes.** Stealth/internal presets, credential handling that keeps cookies out of the process list, and no third-party callouts on internal engagements.
- **Chain of custody.** Every run writes `engagement.json` (ID, operator, command line, tool versions, nuclei template SHA, timestamps) for reporting and repeatability.

## Install

Requires **bash 4+**, **python3**, and standard GNU userland (curl, awk, grep, sort). Built for Kali/Debian; works anywhere the tools run.

### Required tools

| Tool | Install |
|------|---------|
| [dnsx](https://github.com/projectdiscovery/dnsx) | `go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest` |
| [httpx](https://github.com/projectdiscovery/httpx) | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| [naabu](https://github.com/projectdiscovery/naabu) | `go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest` |
| [nuclei](https://github.com/projectdiscovery/nuclei) | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |

### Optional tools (auto-detected, features degrade gracefully)

| Tool | Used for | Install |
|------|----------|---------|
| [subfinder](https://github.com/projectdiscovery/subfinder) | CT-log subdomain enum | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| [assetfinder](https://github.com/tomnomnom/assetfinder) | subdomain enum | `go install github.com/tomnomnom/assetfinder@latest` |
| [amass](https://github.com/owasp-amass/amass) | subdomain enum | `go install github.com/owasp-amass/amass/v4/...@master` |
| [gau](https://github.com/lc/gau) | archive URLs | `go install github.com/lc/gau/v2/cmd/gau@latest` |
| [waybackurls](https://github.com/tomnomnom/waybackurls) | archive URLs | `go install github.com/tomnomnom/waybackurls@latest` |
| [unfurl](https://github.com/tomnomnom/unfurl) | param/path extraction | `go install github.com/tomnomnom/unfurl@latest` |
| [ffuf](https://github.com/ffuf/ffuf) | vhost fuzzing, dirbrute | `go install github.com/ffuf/ffuf/v2@latest` |
| [gowitness](https://github.com/sensepost/gowitness) | screenshots | `go install github.com/sensepost/gowitness@latest` |
| [tlsx](https://github.com/projectdiscovery/tlsx) | TLS analysis | `go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest` |
| [dalfox](https://github.com/hahwul/dalfox) | XSS | `go install github.com/hahwul/dalfox/v2@latest` |
| [mapcidr](https://github.com/projectdiscovery/mapcidr) | CIDR expansion | `go install github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest` |
| [subzy](https://github.com/PentestPad/subzy) / [subjack](https://github.com/haccer/subjack) | takeover checks | `go install github.com/PentestPad/subzy@latest` |
| [whatweb](https://github.com/urbanadventurer/WhatWeb) | fingerprinting | `apt install whatweb` |
| [theHarvester](https://github.com/laramies/theHarvester) | OSINT (opt-in) | `apt install theharvester` |
| [gitleaks](https://github.com/gitleaks/gitleaks) / [trufflehog](https://github.com/trufflesecurity/trufflehog) | JS secret scanning | `apt install gitleaks` |
| nmap, jq | port scan / JSON | `apt install nmap jq` |
| js-beautify / prettier | JS beautify | `npm i -g js-beautify` |

### Wordlists

taraf expects [SecLists](https://github.com/danielmiessler/SecLists) at `/usr/share/seclists` (`apt install seclists` on Kali). Override with `--wordlist-dir` or `$WORDLIST_DIR`.

Used lists (with automatic fallbacks):

- vhost fuzz: `Discovery/DNS/subdomains-top1million-5000.txt` → `namelist.txt`
- dirbrute: `Discovery/Web-Content/common.txt` → `raft-small-words.txt` → `directory-list-2.3-small.txt`

### taraf itself

```bash
git clone https://github.com/<you>/taraf.git
cd taraf
chmod +x taraf.sh
./taraf.sh --help
```

Go tools are resolved from `~/go/bin` first (override with `--tool-prefix`), then `$PATH`.

## Quick start

```bash
# Single domain, defaults (external pentest profile)
./taraf.sh --domain example.com

# Target list, bug bounty profile
./taraf.sh --file scope.txt --mode bugbounty

# Internal range from an existing nmap scan
sudo ./taraf.sh --nmap-file scan.nmap --recon-mode internal

# Web-only, authenticated, resumable
./taraf.sh --file urls.txt --recon-mode web --auth-cookie "PHPSESSID=abc123" --resume
```

Input files accept mixed content — IPs, CIDRs, domains, `host:port`, full URLs, blank lines and `# comments`:

```
# example targets.txt
example.com
10.0.0.0/24
https://app.example.com:8443/login
192.168.1.15
2001:db8::10
```

## Input modes

Exactly one is required:

| Flag | Description |
|------|-------------|
| `--file FILE` | Mixed target list (see format above) |
| `--target-dir DIR` | Run the pipeline once per `*.txt` file in DIR |
| `--domain DOMAIN` | Single domain |
| `--cidr CIDR` | CIDR range (expanded via mapcidr) |
| `--url URL` | Single URL |
| `--nmap-file FILE` | Existing nmap output; converts via `nmap_to_targets.py` and auto-skips the redundant naabu portscan + host discovery |

## Engagement modes (`--mode`)

Business context — sets coverage and aggressiveness:

| Mode | Behavior |
|------|----------|
| `pentest` *(default)* | Full coverage, moderate rate |
| `bugbounty` | Scope-aware; disables admin probing and default-credential checks |
| `redteam` | Stealth on; disables vhost fuzzing, dalfox, admin probing, default creds |
| `fast` | Nuclei-only (medium+ severity); skips passive enum, crawling, JS, screenshots, etc.; phases shrink to `discovery,deep,report` |

## Recon modes (`--recon-mode`)

Operational context — what kind of target you're facing:

| Mode | Behavior |
|------|----------|
| `external` *(default)* | Full attack surface: passive, active, deep |
| `internal` | RFC1918 focus: skips CT logs/archive/takeover/cloud (useless internally), enables nmap, internal port list |
| `web` | HTTP(S) only: no portscan, no host discovery — supply URLs |
| `network` | Infrastructure protocols (SMB/LDAP/RDP/MSSQL/Kerberos…): minimal web noise, nmap on |
| `stealth` | Slow + quiet (also enabled by `--stealth` and `--mode redteam`) |

**Flag precedence:** explicit CLI tuning flags always win over presets. `--stealth --rate 500` keeps your 500 pps; `--internal --ports 80,443` keeps your port list.

## Flags

### Authentication

| Flag | Description |
|------|-------------|
| `--auth-cookie "name=val; n2=v2"` | Cookie header injected into httpx, nuclei, ffuf, curl, dalfox |
| `--auth-header "Authorization: Bearer xxx"` | Arbitrary header, same coverage |
| `--auth-basic "user:pass"` | HTTP Basic auth |

curl-based probes read credentials from a `0600` temp config file so secrets never appear in `ps`. httpx/nuclei/ffuf/dalfox have no header-file option, so those still receive headers via argv — be aware on shared boxes. Credentials are **never** written into reports or the generated verify scripts.

### Scope

| Flag | Description |
|------|-------------|
| `--scope-file FILE` | Only scan hosts containing one of these strings (one per line, `#` comments allowed) |
| `--exclude-file FILE` | Never scan hosts containing these strings |
| `--max-targets N` | Hard cap on total inputs (default: 5000) |

Matching is **fixed-string**, not regex — `example.com` will not match `exampleXcom.attacker.tld`. Scope applies to raw inputs, enumerated subdomains, and final URL candidates. If filtering would leave zero targets, the run aborts instead of silently scanning nothing.

### Phase control

| Flag | Description |
|------|-------------|
| `--phase LIST` | Comma-separated subset of `passive,discovery,active,deep,report` (default: all) |
| `--resume` | Skip sub-phases already completed in this output directory |

### Disabling tests

```
--no-passive --no-subdom-enum --no-portscan --no-discovery
--no-vhost --no-backup-check --no-crawl --no-cors --no-tls
--no-archive --no-js --no-js-curl --no-param --no-nuclei
--no-dalfox --no-screenshots --no-whatweb --no-takeover
--no-cloud --no-admin-probe --no-default-creds --no-per-url-nuclei
--no-dirbrute --no-banner
```

### Opt-in modules

| Flag | Description |
|------|-------------|
| `--run-nmap` | Run nmap in addition to naabu (SYN if root, connect otherwise) |
| `--run-osint` | theHarvester + email/people OSINT query pack |
| `--network-targets FILE` | `host:port` list for nuclei's protocol templates (SMB/LDAP/RDP/…); also generates http/https web candidates. Falls back to naabu's `open_ports.txt` when portscanning is enabled |

### WAF / Cloudflare

| Flag | Description |
|------|-------------|
| `--cf-hosts FILE` | Hosts behind Cloudflare — skip portscan, probe http+https directly |
| `--httpx-delay N` | Delay between httpx probes in ms |

### Scan tuning

| Flag | Default | Description |
|------|---------|-------------|
| `--syn` / `--connect` / `--dual` / `--auto` | `auto` | naabu scan type. `auto` = dual as root, connect otherwise. SYN/dual require root |
| `--rate N` | 2000 | naabu packets/sec |
| `--concurrency N` | 300 | naabu goroutines |
| `--ports LIST` | 15 common web ports | Custom port list (comma-separated) |
| `--web-threads N` | 100 | httpx threads |
| `--web-rate N` | 150 | httpx requests/sec |
| `--probe-parallel N` | 20 | Parallel workers for backup/baseline/takeover/cloud/archive probes |

### Other

| Flag | Description |
|------|-------------|
| `--tool-prefix PATH` | Directory with Go binaries (default: `~/go/bin`) |
| `--wordlist-dir PATH` | SecLists root (default: `/usr/share/seclists`) |
| `--outdir PATH` | Base output directory (default: `taraf_<target>_<timestamp>` in CWD) |
| `--verbose` | Debug logging to `taraf.log` |
| `--dry-run` | Print every command without executing |
| `-h, --help` | Usage |

## Environment variables

Runtime limits:

| Variable | Default | Description |
|----------|---------|-------------|
| `PHASE_TIMEOUT` | 7200 | Per-phase command timeout (s) |
| `NUCLEI_TIMEOUT` | 3600 | Nuclei pass timeout (s) |
| `MAX_TARGETS` | 5000 | Hard input cap (see `--max-targets`) |
| `MAX_OUTFILE_MB` | 500 | Rotate output files larger than this |
| `NO_COLOR` | — | Disable colors (also auto-disabled when piped) |

Result-set caps:

| Variable | Default | Description |
|----------|---------|-------------|
| `PER_URL_NUCLEI_MAX` | 50 | Per-URL targeted nuclei scan cap |
| `DALFOX_MAX` | 100 | Parametric URLs fed to dalfox |
| `JS_CURL_MAX` | 500 | Pages fetched for curl-based JS extraction |
| `DIRBRUTE_MAX` | 30 | Live hosts dirbruted with ffuf |
| `WHATWEB_MAX_TARGETS` | 1000 | Cap for the discovery-phase WhatWeb pass |
| `HV_LIMIT` / `HV_ADMIN_CAP` / `HV_API_CAP` | 500 / 30 / 50 | High-value list caps for aggregate nuclei |

Nuclei tuning (three independent passes):

| Variable | Default | Pass |
|----------|---------|------|
| `NUCLEI_WEB_RECON_CONC` / `_RATE` | 10 / 30 | Web recon (exposure/config/tech tags) |
| `NUCLEI_WEB_TECH_CONC` / `_RATE` | 5 / 15 | Tech-mapped scan on high-value URLs |
| `NUCLEI_NET_CONC` / `_RATE` | 25 / 100 | Network protocols (SMB/LDAP/RDP/…) |
| `NUCLEI_WEB_RECON_SEVERITY` | `info,low,medium,high,critical` | Web recon |
| `NUCLEI_WEB_TECH_SEVERITY` | `info,low,medium,high,critical` | Tech pass |
| `NUCLEI_NET_SEVERITY` | `critical,high,medium` | Network pass |
| `NUCLEI_WEB_RECON_ETAGS` | `fuzz,dos,osint` | Excluded tags, recon |
| `NUCLEI_WEB_TECH_ETAGS` | `fuzz,dos,osint` | Excluded tags, tech |
| `NUCLEI_NET_EXCLUDE_TAGS` | `fuzz,dos` | Excluded tags, network |

Paths:

| Variable | Default | Description |
|----------|---------|-------------|
| `TOOL_PREFIX` | `~/go/bin` | Go tool directory |
| `SECLISTS` | `/usr/share/seclists` | SecLists root |
| `WORDLIST_DIR` | `$SECLISTS` | Wordlist root override |

Example — a hardened bug-bounty run against a WAF'd target:

```bash
HTTPX_DELAY=250 NUCLEI_WEB_TECH_CONC=2 NUCLEI_WEB_TECH_RATE=5 \
./taraf.sh --file scope.txt --mode bugbounty --stealth --rate 100
```

## Pause / resume

Press **Enter** at any time during a run: the in-flight command's whole process group is frozen with `SIGSTOP` (CPU, sockets and timers all suspended — not just silenced). Press Enter again and it continues with `SIGCONT` exactly where it stopped. Active only on an interactive terminal; ignored when piped or scripted.

## Resuming runs and failure handling

Every sub-phase (`passive.ct`, `discovery.httpx`, `deep.nuclei`, …) is recorded in `<outdir>/.taraf.state`. With `--resume`, completed sub-phases are skipped.

Crucially, **failures are not marked done**: if a wrapped command exits non-zero (crash, timeout), the sub-phase is recorded as `<name>.failed`, a warning is printed, and a later `--resume` will retry it. Explicitly disabled tests (`--no-*`) are marked done normally. To redo everything in an existing outdir, just rerun without `--resume`.

## Output layout

```
taraf_<target>_<YYYYMMDD_HHMMSS>/
├── engagement.json            # chain of custody: id, operator, cmdline, tool versions, template SHA
├── taraf.log                  # plain-text full log (colors are terminal-only)
├── .taraf.state               # resume bookkeeping
├── raw_ips.txt / raw_domains.txt / raw_urls.txt
├── passive/
│   ├── ct_subdomains.txt      # subfinder
│   ├── archive_urls.txt       # gau + waybackurls
│   ├── archive_params.txt / archive_paths.txt
│   ├── github_dorks.txt / google_dorks.txt / shodan_queries.txt
│   └── cloud_buckets_found.txt
├── discovery/
│   ├── dns_records.jsonl      # dnsx (A/AAAA/CNAME/MX/TXT/SOA)
│   ├── alive_ips.txt / hosts_down.txt
│   ├── subdomains.txt         # scope-filtered target hostnames
│   ├── open_ports.txt         # naabu (+ nmap_open_ports.txt if --run-nmap)
│   ├── httpx_live.jsonl       # full probe data (tech, titles, favicons, IPs, CNAMEs)
│   ├── live_urls.txt          # the master list for active/deep phases
│   └── tlsx.jsonl / tls_sans.txt
├── active/
│   ├── vhost_discovered.txt
│   ├── backup_hits.txt        # 404-baseline-validated
│   ├── git_confirmed.txt
│   ├── endpoints_discovered.txt / api_endpoints.txt / zip_files.txt
│   ├── js_files.txt
│   ├── cors_findings.txt
│   ├── takeover_candidates.txt
│   └── admin_panels_found.txt # baseline-filtered
├── deep/
│   ├── tech_profile.txt       # cleaned fingerprint list → nuclei tags
│   ├── js_secrets.txt / js_endpoints.txt / js_pretty/ / sourcemaps_found.txt
│   ├── nuclei_recon.txt       # exposure/config/tech pass
│   ├── nuclei_full.txt        # tech-mapped pass + merged per-URL results
│   ├── nuclei_network.txt     # SMB/LDAP/RDP/MSSQL/Kerberos/…
│   ├── default_creds.txt
│   ├── dalfox_results.txt
│   ├── screenshots/
│   └── verify/                # per-finding nuclei re-run scripts
└── report/
    ├── summary.md             # human report
    └── summary.csv            # metrics for tracking/diffing over time
```

## OPSEC notes

- **Stealth** (`--stealth`, `--mode redteam`, `--recon-mode stealth`) drops naabu to 100 pps/30 goroutines, httpx to 20 threads/30 rps with 500 ms delay, ffuf to 10 threads/50 rps, probes to 5 workers — unless you overrode those values explicitly.
- On **internal/stealth** runs taraf never calls out to IP-echo services; `scanner_ip` is recorded as `withheld`.
- nuclei runs with `-no-interactsh` by default; `fuzz`, `dos` and `osint` template tags are excluded from web passes.
- Auth cookies are kept in a `0600` curl config file and never written into reports, verify scripts, or `engagement.json` (only `auth_used: true/false`).
- `--dry-run` prints every command that would run — use it to audit traffic before firing.

## Examples

```bash
# Full external surface of one domain
./taraf.sh --domain example.com

# Fast nuclei-only sweep of a big list
./taraf.sh --file targets.txt --mode fast

# Red team: slow, quiet, minimal noise
./taraf.sh --file targets.txt --mode redteam

# Authenticated app testing with custom header
./taraf.sh --url https://app.example.com --auth-header "Authorization: Bearer eyJ..."

# Internal infrastructure sweep from nmap output
sudo ./taraf.sh --nmap-file internal.nmap --recon-mode internal

# Cloudflare-fronted targets, direct probing
./taraf.sh --file hosts.txt --cf-hosts cf.txt --no-portscan

# Resume an interrupted run (state lives in <outdir>/<name>/.taraf.state,
# so pass the same --outdir base you used originally)
./taraf.sh --file targets.txt --outdir runs/targets            # first run
./taraf.sh --file targets.txt --outdir runs/targets --resume   # resume

# Only the deep + report phases on that same output dir
./taraf.sh --file targets.txt --phase deep,report --resume --outdir runs/targets
```

## Disclaimer

taraf is an offensive security tool intended for **authorized** penetration tests, bug bounty programs and internal pentests engagements mainly. Active phases send non-trivial traffic; dirbrute, vhost fuzzing, and default-credential checks can trip WAFs, lock accounts, and generate logs. Always:

- respect program rules of engagement (rate limits, excluded tests),
- start with `--dry-run` and conservative rates on unfamiliar infrastructure.

You are responsible for how you use this tool.

