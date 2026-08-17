#!/bin/bash
# =============================================================================
# taraf.sh -- Attack Surface Enumeration Pipeline
# Tagline: "map the edge"
# =============================================================================

VERSION="0.6.0"

set -uo pipefail
shopt -s nullglob

START_TIME=$(date -Iseconds)
CMD_LINE="$0 $*"

# -- Pause/resume control (Enter key toggles pause on the active command) ----
TARAF_CTRL_DIR=$(mktemp -d -t taraf-ctrl-XXXXXX 2>/dev/null || echo "/tmp/taraf-ctrl-$$")
mkdir -p "$TARAF_CTRL_DIR" 2>/dev/null || true
PAUSE_FLAG="$TARAF_CTRL_DIR/paused"
CURRENT_PID_FILE="$TARAF_CTRL_DIR/current.pid"
WATCHER_PID_FILE="$TARAF_CTRL_DIR/watcher.pid"

# -- CPU-aware defaults -------------------------------------------------------
CPU_CORES=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)
JOBS_MAX=$(( CPU_CORES * 2 ))

# -- Tool paths ---------------------------------------------------------------
TOOL_PREFIX="${TOOL_PREFIX:-$HOME/go/bin}"
SECLISTS="${SECLISTS:-/usr/share/seclists}"
WORDLIST_DIR="${WORDLIST_DIR:-$SECLISTS}"

# -- Port lists ---------------------------------------------------------------
WEB_PORTS="80,443,8080,8443,7001,9000,8000,8888,3000,5000,9090,9200,9443,8081,8444"
DISCOVERY_PORTS="21,22,23,25,53,80,135,139,443,445,3389,5985,5986,8080,8443,9200,9300"
INTERNAL_PORTS="21,22,23,25,53,88,110,111,135,139,143,389,443,445,464,500,587,593,636,3268,3269,3306,3389,5432,5985,5986,8080,8443,9389"

# -- Scan tuning --------------------------------------------------------------
SCAN_MODE="auto"
NAABU_RATE="${NAABU_RATE:-2000}"
NAABU_CONCURRENCY="${NAABU_CONCURRENCY:-300}"
NAABU_RETRIES="${NAABU_RETRIES:-2}"
HTTPX_THREADS="${HTTPX_THREADS:-100}"
HTTPX_RATE="${HTTPX_RATE:-150}"
HTTPX_DELAY="${HTTPX_DELAY:-0}"
FFUF_THREADS="${FFUF_THREADS:-100}"
FFUF_RATE="${FFUF_RATE:-300}"
JS_CURL_MAX="${JS_CURL_MAX:-500}"
DALFOX_MAX="${DALFOX_MAX:-100}"
PROBE_PARALLEL="${PROBE_PARALLEL:-20}"
PHASE_TIMEOUT="${PHASE_TIMEOUT:-7200}"
NUCLEI_TIMEOUT="${NUCLEI_TIMEOUT:-3600}"
MAX_TARGETS="${MAX_TARGETS:-5000}"
MAX_OUTFILE_MB="${MAX_OUTFILE_MB:-500}"

# -- Recon mode (operational context) -----------------------------------------
RECON_MODE="external"   # external | internal | web | network | stealth

# -- User-specified flag tracking (CLI must win over presets) ------------------
USER_SET_NAABU_RATE=false; USER_SET_NAABU_CONCURRENCY=false
USER_SET_HTTPX_THREADS=false; USER_SET_HTTPX_RATE=false
USER_SET_HTTPX_DELAY=false; USER_SET_PROBE_PARALLEL=false
USER_SET_WEB_PORTS=false; USER_SET_FFUF_THREADS=false
USER_SET_FFUF_RATE=false

# -- Execution flags ----------------------------------------------------------
PHASES="passive,discovery,active,deep,report"
PHASES_SET=false
RESUME=false
ENGAGEMENT_MODE="pentest"
STEALTH=false
INTERNAL_MODE=false

NO_PASSIVE=false; NO_SUBDOM_ENUM=false; NO_PORTSCAN=false; NO_DISCOVERY=false
NO_VHOST=false; NO_BACKUP_CHECK=false; NO_CRAWL=false; NO_CORS=false
NO_TLS=false; NO_ARCHIVE=false; NO_JS=false; NO_JS_CURL=false
NO_PARAM=false; NO_NUCLEI=false; NO_DALFOX=false; NO_SCREENSHOTS=false
NO_WHATWEB=false; NO_TAKEOVER=false; NO_CLOUD=false; NO_ADMIN_PROBE=false
NO_DEFAULT_CREDS=false; NO_PER_URL_NUCLEI=false; NO_BANNER=false
NO_DIRBRUTE=false

RUN_NMAP=false; RUN_OSINT=false
VERBOSE=false; DRY_RUN=false
CF_HOSTS_FILE=""
SCOPE_FILE=""; EXCLUDE_FILE=""
AUTH_COOKIE=""; AUTH_HEADER=""; AUTH_BASIC=""
NETWORK_TARGETS_FILE=""
PER_URL_NUCLEI_MAX="${PER_URL_NUCLEI_MAX:-50}"

OUTDIR_BASE=""; OUTDIR=""
TARAF_STAMP=$(date +%Y%m%d_%H%M%S)

# -- Colours ------------------------------------------------------------------
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    RED=$'\033[0;31m'; YELLOW=$'\033[1;33m'; GREEN=$'\033[0;32m'
    CYAN=$'\033[0;36m'; BLUE=$'\033[0;34m'; GREY=$'\033[0;90m'
    BOLD=$'\033[1m'; RESET=$'\033[0m'
else
    RED=''; YELLOW=''; GREEN=''; CYAN=''; BLUE=''; GREY=''; BOLD=''; RESET=''
fi

# -- Logging ------------------------------------------------------------------
# Terminal output is colourised; the log file always gets plain text so it
# stays grep-able and does not fill up with ANSI escape sequences.
LOG_FILE="/dev/null"
_log_plain() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*" >> "$LOG_FILE"; }
log()  { echo -e "${GREEN}[$(date +%H:%M:%S)]${RESET} $*";    _log_plain "$*"; }
info() { echo -e "${CYAN}[$(date +%H:%M:%S)] [*]${RESET} $*"; _log_plain "[*] $*"; }
warn() { echo -e "${YELLOW}[$(date +%H:%M:%S)] [!]${RESET} $*" >&2; _log_plain "[!] $*"; }
die()  { echo -e "${RED}[$(date +%H:%M:%S)] [x]${RESET} $*" >&2; _log_plain "[x] $*"; exit 1; }
ok()   { echo -e "${GREEN}[$(date +%H:%M:%S)] [+]${RESET} $*"; _log_plain "[+] $*"; }
verb() { [[ "$VERBOSE" == true ]] && _log_plain "[DBG] $*"; return 0; }

# -- Banner -------------------------------------------------------------------
banner() {
    [[ "$NO_BANNER" == true || -n "${NO_COLOR:-}" || ! -t 1 ]] && return 0
    printf '%s' "$RED"
    cat <<'BANNER'
   //  ████████╗  █████╗  ██████╗   █████╗  ███████╗
   //  ╚══██╔══╝ ██╔══██╗ ██╔══██╗ ██╔══██╗ ██╔════╝
  //      ██║    ███████║ ██████╔╝ ███████║ █████╗
 //       ██║    ██╔══██║ ██╔══██╗ ██╔══██║ ██╔══╝
//        ██║    ██║  ██║ ██║  ██║ ██║  ██║ ██║
          ╚═╝    ╚═╝  ╚═╝ ╚═╝  ╚═╝ ╚═╝  ╚═╝ ╚═╝
BANNER
    printf "${GREY}         /// attack surface enumeration${RESET}\n"
    printf "${CYAN}   ___       _____  ____  ____${RESET}\n"
    printf "${CYAN}  / _ \\__ __/ ___/ / __ \\/ _ )${RESET}\n"
    printf "${CYAN} / // /\\ \\ /\\__ \\ / /_/ / _  |${RESET}\n"
    printf "${CYAN} \\___//_\\_\\/____/ \\____/____/${RESET}\n\n"
    printf "  ${BOLD}engine:${RESET} v%s   ${BOLD}mode:${RESET} %s   ${BOLD}stealth:${RESET} %s\n" \
        "$VERSION" "${ENGAGEMENT_MODE}" "${STEALTH}"
    printf "  ${BOLD}target:${RESET} %s\n" "${MODE_VAL:-?}"
    printf "  ${BOLD}started:${RESET} %s\n\n" "$(date -Iseconds)"
}

# -- Cleanup trap -------------------------------------------------------------
TARAF_TMPFILES=()
cleanup_exit() {
    local rc=$?
    local f
    for f in "${TARAF_TMPFILES[@]}"; do
        [[ -f "$f" ]] && rm -f "$f"
    done
    if [[ -n "${OUTDIR:-}" && -d "${OUTDIR:-}" ]]; then
        find "$OUTDIR" -name '.tmp_*' -type f -delete 2>/dev/null || true
    fi
    stop_pause_watcher 2>/dev/null
    [[ -n "${TARAF_CTRL_DIR:-}" && -d "${TARAF_CTRL_DIR:-}" ]] && rm -rf "$TARAF_CTRL_DIR" 2>/dev/null
    if [[ $rc -ne 0 && $rc -ne 1 && $rc -ne 2 && $rc -ne 130 ]]; then
        warn "Exited with code $rc"
    fi
    exit $rc
}
trap cleanup_exit EXIT
trap 'echo; warn "Interrupted (SIGINT)"; exit 130' INT
trap 'warn "Terminated (SIGTERM)"; exit 143' TERM

# -- Pause/resume watcher ------------------------------------------------------
start_pause_watcher() {
    [[ "$DRY_RUN" == true ]] && return 0
    [[ -t 0 && -r /dev/tty ]] || return 0
    (
        local paused=false
        while IFS= read -r _ < /dev/tty; do
            if [[ "$paused" == false ]]; then
                paused=true
                touch "$PAUSE_FLAG" 2>/dev/null
                warn "PAUSED -- press Enter to resume"
                if [[ -f "$CURRENT_PID_FILE" ]]; then
                    local cpgid
                    cpgid=$(cat "$CURRENT_PID_FILE" 2>/dev/null)
                    [[ -n "$cpgid" ]] && kill -STOP -"$cpgid" 2>/dev/null
                fi
            else
                paused=false
                rm -f "$PAUSE_FLAG" 2>/dev/null
                if [[ -f "$CURRENT_PID_FILE" ]]; then
                    local cpgid
                    cpgid=$(cat "$CURRENT_PID_FILE" 2>/dev/null)
                    [[ -n "$cpgid" ]] && kill -CONT -"$cpgid" 2>/dev/null
                fi
                ok "RESUMED"
            fi
        done
    ) &
    echo $! > "$WATCHER_PID_FILE" 2>/dev/null
    info "Pause/resume active -- press Enter at any time to pause, Enter again to resume"
}

stop_pause_watcher() {
    if [[ -f "$WATCHER_PID_FILE" ]]; then
        local wpid
        wpid=$(cat "$WATCHER_PID_FILE" 2>/dev/null)
        [[ -n "$wpid" ]] && kill "$wpid" 2>/dev/null
    fi
}

# -- State management ---------------------------------------------------------
# state_check matches only exact "<name>" entries. Entries recorded as
# "<name>.failed" (sub-phase had a command failure) are NOT treated as done,
# so --resume retries them. Explicit skips (--no-*) are marked done normally.
STATE_FILE=""
SUBPHASE_FAILED=false
state_init()  { STATE_FILE="$1/.taraf.state"; touch "$STATE_FILE"; }
state_check() { [[ "$RESUME" == true ]] && grep -qx "$1" "$STATE_FILE" 2>/dev/null; }
state_mark()  {
    if [[ "$SUBPHASE_FAILED" == true ]]; then
        echo "${1}.failed" >> "$STATE_FILE"
        sort -u "$STATE_FILE" -o "$STATE_FILE"
        warn "Sub-phase '$1' had command failures -- recorded as FAILED; --resume will retry it"
        SUBPHASE_FAILED=false
    else
        echo "$1" >> "$STATE_FILE"
        sort -u "$STATE_FILE" -o "$STATE_FILE"
    fi
}
state_reset_failures() {
    # Drop all *.failed entries so a fresh (non-resume) run is truly fresh.
    [[ -f "$STATE_FILE" ]] && sed -i '/\.failed$/d' "$STATE_FILE" 2>/dev/null || true
}

# -- URL resolution -----------------------------------------------------------
resolve_url() {
    local base="$1" rel="$2"
    if [[ "$rel" =~ ^https?:// ]]; then echo "$rel"; return; fi
    if [[ "$rel" =~ ^// ]]; then echo "https:${rel}"; return; fi
    if [[ "$rel" =~ ^/ ]]; then
        local origin
        origin=$(echo "$base" | grep -oP '^https?://[^/]+')
        echo "${origin}${rel}"; return
    fi
    local base_clean base_dir resolved
    base_clean=$(echo "$base" | sed 's|[?#].*||')
    if [[ "$base_clean" =~ /[^/]+\.[^/]+$ ]]; then
        base_dir=$(echo "$base_clean" | sed -E 's|/[^/]+$|/|')
    else
        base_dir="${base_clean%/}/"
    fi
    resolved="${base_dir}${rel}"
    while [[ "$resolved" =~ /[^/]+/\.\./ ]]; do
        resolved=$(echo "$resolved" | sed -E 's|/[^/]+/\.\./|/|')
    done
    resolved=$(echo "$resolved" | sed 's|/\./|/|g')
    echo "$resolved"
}

# -- Tool resolution ----------------------------------------------------------
resolve_tool() {
    local name="$1"
    local custom="$TOOL_PREFIX/$name"
    if   [[ -x "$custom"              ]]; then echo "$custom"
    elif command -v "$name" &>/dev/null; then command -v "$name"
    else echo ""
    fi
}

declare -g SUBFINDER ASSETFINDER AMASS DNSX MAPCIDR NAABU HTTPX TLSX GAU \
           WAYBACKURLS UNFURL FFUF GOWITNESS NUCLEI DALFOX JQ NMAP WHATWEB \
           SUBZY SUBJACK THEHARVESTER GITLEAKS TRUFFLEHOG

resolve_all_tools() {
    SUBFINDER=$(resolve_tool subfinder)
    ASSETFINDER=$(resolve_tool assetfinder)
    AMASS=$(resolve_tool amass)
    DNSX=$(resolve_tool dnsx)
    MAPCIDR=$(resolve_tool mapcidr)
    NAABU=$(resolve_tool naabu)
    HTTPX=$(resolve_tool httpx)
    TLSX=$(resolve_tool tlsx)
    GAU=$(resolve_tool gau)
    WAYBACKURLS=$(resolve_tool waybackurls)
    UNFURL=$(resolve_tool unfurl)
    FFUF=$(resolve_tool ffuf)
    GOWITNESS=$(resolve_tool gowitness)
    NUCLEI=$(resolve_tool nuclei)
    DALFOX=$(resolve_tool dalfox)
    JQ=$(resolve_tool jq)
    NMAP=$(resolve_tool nmap)
    WHATWEB=$(resolve_tool whatweb)
    SUBZY=$(resolve_tool subzy)
    SUBJACK=$(resolve_tool subjack)
    THEHARVESTER=$(resolve_tool theHarvester)
    GITLEAKS=$(resolve_tool gitleaks)
    TRUFFLEHOG=$(resolve_tool trufflehog)
}

# -- Usage --------------------------------------------------------------------
usage() {
    banner
    cat <<EOF
 ${BOLD}taraf${RESET} -- map the edge

 ${BOLD}Usage:${RESET}
  $0 [options] --file <FILE>
  $0 [options] --target-dir <DIR>
  $0 [options] --domain <DOMAIN>
  $0 [options] --cidr <CIDR>
  $0 [options] --url <URL>
  $0 [options] --nmap-file <NMAP_FILE>   (requires nmap_to_targets.py)

 ${BOLD}Recon mode:${RESET}
  --recon-mode external|internal|web|network|stealth   Default: external

 ${BOLD}Engagement mode:${RESET}
  --mode pentest|bugbounty|redteam|fast   Default: pentest
  --stealth                           Slow + randomized (for WAF/SOC envs)
  --internal                          Internal network port list

 ${BOLD}Authentication:${RESET}
  --auth-cookie "name=val; n2=v2"
  --auth-header "Authorization: Bearer xxx"
  --auth-basic  "user:pass"

 ${BOLD}Scope:${RESET}
  --scope-file FILE      Only scan hosts containing these strings (one per line)
  --exclude-file FILE    Never scan hosts containing these strings (one per line)
  --max-targets N        Hard cap (default: 5000)

 ${BOLD}Phase control:${RESET}
  --phase LIST           Comma-separated (default: all)
  --resume               Skip completed sub-phases

 ${BOLD}Disable tests:${RESET}
  --no-passive --no-subdom-enum --no-portscan --no-discovery
  --no-vhost --no-backup-check --no-crawl --no-cors --no-tls
  --no-archive --no-js --no-js-curl --no-param --no-nuclei
  --no-dalfox --no-screenshots --no-whatweb --no-takeover
  --no-cloud --no-admin-probe --no-default-creds --no-per-url-nuclei
  --no-dirbrute --no-banner

 ${BOLD}Opt-in:${RESET}
  --run-nmap             Run nmap (in addition to naabu)
  --run-osint             Run theHarvester

 ${BOLD}WAF / CF:${RESET}
  --cf-hosts FILE        Hosts behind CF -- skip portscan, probe directly
  --httpx-delay N        Delay between httpx probes (ms)

 ${BOLD}Scan tuning:${RESET}
  --syn | --connect | --dual | --auto
  --rate N               naabu packets/sec (default: 2000)
  --concurrency N        naabu goroutines (default: 300)
  --ports LIST           custom port list
  --web-threads N        httpx threads (default: 100)
  --web-rate N           httpx rate/s (default: 150)
  --probe-parallel N     backup-probe workers (default: 20)

 ${BOLD}Other:${RESET}
  --tool-prefix PATH     go/bin dir (default: ~/go/bin)
  --wordlist-dir PATH    seclists root
  --outdir PATH          base output dir
  --verbose
  --dry-run
  -h, --help

 ${BOLD}Env vars:${RESET}
  PHASE_TIMEOUT, NUCLEI_TIMEOUT, MAX_TARGETS, NO_COLOR, MAX_OUTFILE_MB
  PER_URL_NUCLEI_MAX          per-URL nuclei cap (default: 50)
  DALFOX_MAX                  dalfox target cap (default: 100)
  JS_CURL_MAX                 curl-based JS extraction cap (default: 500)
  DIRBRUTE_MAX                ffuf dirbrute target cap (default: 30)
  WHATWEB_MAX_TARGETS         WhatWeb quick-overview target cap (default: 1000)
  HV_LIMIT / HV_ADMIN_CAP / HV_API_CAP   high-value nuclei list caps (500/30/50)
  NUCLEI_WEB_RECON_CONC/RATE  web recon-pass tuning (default: 10 / 30)
  NUCLEI_WEB_TECH_CONC/RATE   web tech-pass tuning  (default: 5 / 15)
  NUCLEI_NET_CONC/RATE        network-pass tuning   (default: 25 / 100)
  NUCLEI_WEB_RECON_SEVERITY   severity for recon pass (default: info,low,medium,high,critical)
  NUCLEI_WEB_RECON_ETAGS      exclude tags for recon pass (default: fuzz,dos,osint)
  NUCLEI_WEB_TECH_SEVERITY    severity for tech pass (default: info,low,medium,high,critical)
  NUCLEI_WEB_TECH_ETAGS       exclude tags for tech pass (default: fuzz,dos,osint)
  NUCLEI_NET_SEVERITY         severity for network pass (default: critical,high,medium)
  NUCLEI_NET_EXCLUDE_TAGS     exclude tags for network pass (default: fuzz,dos)

 ${BOLD}Network-protocol scanning (SMB/LDAP/RDP/MSSQL/Kerberos/etc.):${RESET}
  --network-targets FILE  host:port list (no scheme) for nuclei's protocol
                          templates. Also automatically generates http/https
                          candidates for web scanning. Falls back to naabu's
                          open_ports.txt if not given and portscan wasn't skipped.

 ${BOLD}Pause / resume:${RESET}
  Press Enter at any time during a run to pause -- the in-flight command is
  frozen via SIGSTOP (CPU, sockets, timers all suspended, not just silenced).
  Press Enter again to resume exactly where it left off via SIGCONT. Only
  active on an interactive terminal; has no effect when piped/scripted.

 ${BOLD}Examples:${RESET}
  $0 --file targets.txt
  $0 --file targets.txt --mode fast
  $0 --file targets.txt --mode redteam --stealth
  $0 --file targets.txt --auth-cookie "PHPSESSID=abc"
  $0 --file targets.txt --phase discovery
  $0 --nmap-file scan.nmap --internal
EOF
    exit "${1:-2}"
}

# -- Arg parsing --------------------------------------------------------------
parse_args() {
MODE=""
MODE_VAL=""
[[ $# -lt 1 ]] && usage 2

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target-dir)        MODE="target-dir";   MODE_VAL="$2"; shift 2 ;;
        --file)              MODE="file";         MODE_VAL="$2"; shift 2 ;;
        --domain)            MODE="domain";       MODE_VAL="$2"; shift 2 ;;
        --cidr)              MODE="cidr";         MODE_VAL="$2"; shift 2 ;;
        --url)               MODE="url";          MODE_VAL="$2"; shift 2 ;;
        --nmap-file)         MODE="nmap";         MODE_VAL="$2"; shift 2 ;;
        --mode)              ENGAGEMENT_MODE="$2"; shift 2 ;;
        --recon-mode)        RECON_MODE="$2";     shift 2 ;;
        --stealth)           STEALTH=true;        shift ;;
        --internal)          INTERNAL_MODE=true;  shift ;;
        --auth-cookie)       AUTH_COOKIE="$2";    shift 2 ;;
        --auth-header)       AUTH_HEADER="$2";    shift 2 ;;
        --auth-basic)        AUTH_BASIC="$2";     shift 2 ;;
        --scope-file)        SCOPE_FILE="$2";     shift 2 ;;
        --exclude-file)      EXCLUDE_FILE="$2";   shift 2 ;;
        --max-targets)       MAX_TARGETS="$2";    shift 2 ;;
        --phase)             PHASES="$2"; PHASES_SET=true; shift 2 ;;
        --resume)            RESUME=true;         shift ;;
        --no-passive)        NO_PASSIVE=true;     shift ;;
        --no-subdom-enum)    NO_SUBDOM_ENUM=true; shift ;;
        --no-portscan)       NO_PORTSCAN=true;    shift ;;
        --no-discovery)      NO_DISCOVERY=true;   shift ;;
        --no-vhost)          NO_VHOST=true;       shift ;;
        --no-backup-check)   NO_BACKUP_CHECK=true; shift ;;
        --no-crawl)          NO_CRAWL=true;       shift ;;
        --no-cors)           NO_CORS=true;        shift ;;
        --no-tls)            NO_TLS=true;         shift ;;
        --no-archive)        NO_ARCHIVE=true;     shift ;;
        --no-js)             NO_JS=true;          shift ;;
        --no-js-curl)        NO_JS_CURL=true;     shift ;;
        --no-param)          NO_PARAM=true;       shift ;;
        --no-nuclei)         NO_NUCLEI=true;      shift ;;
        --no-dalfox)         NO_DALFOX=true;      shift ;;
        --no-screenshots)    NO_SCREENSHOTS=true; shift ;;
        --no-whatweb)        NO_WHATWEB=true;     shift ;;
        --no-takeover)       NO_TAKEOVER=true;    shift ;;
        --no-cloud)          NO_CLOUD=true;       shift ;;
        --no-admin-probe)    NO_ADMIN_PROBE=true; shift ;;
        --no-default-creds)  NO_DEFAULT_CREDS=true; shift ;;
        --no-per-url-nuclei) NO_PER_URL_NUCLEI=true; shift ;;
        --no-dirbrute)       NO_DIRBRUTE=true;    shift ;;
        --no-banner)         NO_BANNER=true;      shift ;;
        --network-targets)   NETWORK_TARGETS_FILE="$2"; shift 2 ;;
        --run-nmap)          RUN_NMAP=true;       shift ;;
        --run-osint)         RUN_OSINT=true;      shift ;;
        --cf-hosts)          CF_HOSTS_FILE="$2";  shift 2 ;;
        --syn)               SCAN_MODE="syn";     shift ;;
        --connect)           SCAN_MODE="connect"; shift ;;
        --dual)              SCAN_MODE="dual";    shift ;;
        --auto)              SCAN_MODE="auto";    shift ;;
        --rate)              NAABU_RATE="$2";     USER_SET_NAABU_RATE=true; shift 2 ;;
        --concurrency)       NAABU_CONCURRENCY="$2"; USER_SET_NAABU_CONCURRENCY=true; shift 2 ;;
        --ports)             WEB_PORTS="$2";      USER_SET_WEB_PORTS=true; shift 2 ;;
        --web-threads)       HTTPX_THREADS="$2";  USER_SET_HTTPX_THREADS=true; shift 2 ;;
        --web-rate)          HTTPX_RATE="$2";     USER_SET_HTTPX_RATE=true; shift 2 ;;
        --httpx-delay)       HTTPX_DELAY="$2";    USER_SET_HTTPX_DELAY=true; shift 2 ;;
        --probe-parallel)    PROBE_PARALLEL="$2"; USER_SET_PROBE_PARALLEL=true; shift 2 ;;
        --tool-prefix)       TOOL_PREFIX="$2";    shift 2 ;;
        --wordlist-dir)      WORDLIST_DIR="$2";   shift 2 ;;
        --outdir)            OUTDIR_BASE="$2";    shift 2 ;;
        --verbose)           VERBOSE=true;        shift ;;
        --dry-run)           DRY_RUN=true;        shift ;;
        -h|--help)           usage 0 ;;
        *)                   warn "Unknown flag: $1"; usage 2 ;;
    esac
done

[[ -z "$MODE" ]]     && { warn "No mode specified"; usage 2; }
[[ -z "$MODE_VAL" ]] && { warn "No value for mode"; usage 2; }
}  # end parse_args

# -- Engagement presets -------------------------------------------------------
apply_mode_presets() {
    # --- Engagement type presets (business context) -----------------------------
    case "$ENGAGEMENT_MODE" in
        pentest)
            info "Engagement: PENTEST (authorized -- full coverage, moderate rate)"
            ;;
        bugbounty)
            info "Engagement: BUG BOUNTY (scope-aware, dedupe-friendly, no internal probes)"
            NO_ADMIN_PROBE=true
            NO_DEFAULT_CREDS=true
            ;;
        redteam)
            info "Engagement: RED TEAM (stealth, slow, OPSEC-aware)"
            STEALTH=true
            NO_ADMIN_PROBE=true
            NO_DEFAULT_CREDS=true
            NO_VHOST=true
            NO_DALFOX=true
            ;;
        fast)
            info "Mode: FAST (nuclei-only, medium/high/critical -- minimal discovery)"
            NO_PASSIVE=true
            NO_SUBDOM_ENUM=true
            NO_VHOST=true
            NO_BACKUP_CHECK=true
            NO_CRAWL=true
            NO_CORS=true
            NO_TLS=true
            NO_ARCHIVE=true
            NO_JS=true
            NO_JS_CURL=true
            NO_PARAM=true
            NO_DALFOX=true
            NO_SCREENSHOTS=true
            NO_WHATWEB=true
            NO_TAKEOVER=true
            NO_CLOUD=true
            NO_ADMIN_PROBE=true
            NO_DIRBRUTE=true
            [[ "$PHASES_SET" != true ]] && PHASES="discovery,deep,report"
            export NUCLEI_WEB_RECON_SEVERITY="medium,high,critical"
            export NUCLEI_WEB_TECH_SEVERITY="medium,high,critical"
            export NUCLEI_NET_SEVERITY="critical,high,medium"
            ;;
        *)
            warn "Unknown engagement: $ENGAGEMENT_MODE. Falling back to pentest."
            ENGAGEMENT_MODE="pentest"
            ;;
    esac

    # --- Recon mode presets (operational context) -------------------------------
    case "$RECON_MODE" in
        external)
            info "Recon mode: EXTERNAL (full attack surface -- passive, active, deep)"
            ;;
        internal)
            info "Recon mode: INTERNAL (RFC1918 / internal network focus)"
            INTERNAL_MODE=true
            # External-only intelligence is useless on RFC1918
            NO_PASSIVE=true
            NO_SUBDOM_ENUM=true
            NO_ARCHIVE=true
            NO_TAKEOVER=true
            NO_CLOUD=true
            # Infra discovery is what matters
            RUN_NMAP=true
            ;;
        web)
            info "Recon mode: WEB-ONLY (HTTP(S) enumeration, no infra portscan)"
            # Expect the user to supply URLs; don't waste time on host discovery
            NO_PORTSCAN=true
            NO_DISCOVERY=true
            ;;
        network)
            info "Recon mode: NETWORK (infrastructure protocols, minimal web noise)"
            NO_CRAWL=true
            NO_JS=true
            NO_JS_CURL=true
            NO_PARAM=true
            NO_DALFOX=true
            NO_SCREENSHOTS=true
            NO_WHATWEB=true
            NO_TAKEOVER=true
            NO_CLOUD=true
            NO_ADMIN_PROBE=true
            NO_BACKUP_CHECK=true
            NO_CORS=true
            NO_ARCHIVE=true
            NO_VHOST=true
            RUN_NMAP=true
            ;;
        stealth)
            info "Recon mode: STEALTH (slow, quiet, OPSEC-aware)"
            STEALTH=true
            ;;
        *)
            warn "Unknown recon mode: $RECON_MODE. Falling back to external."
            RECON_MODE="external"
            ;;
    esac

    # --- Nmap-file auto-optimization -------------------------------------------
    # If we already have an nmap scan, don't redo host discovery or portscanning
    if [[ "$MODE" == "nmap" ]]; then
        if [[ "$NO_PORTSCAN" != true ]]; then
            info "Nmap-file mode: auto-skipping redundant naabu portscan"
            NO_PORTSCAN=true
        fi
        if [[ "$NO_DISCOVERY" != true ]]; then
            info "Nmap-file mode: auto-skipping redundant host discovery"
            NO_DISCOVERY=true
        fi
    fi

    if [[ "$STEALTH" == true ]]; then
        info "Stealth: rate-limiting active (explicit CLI tuning flags still win)"
        [[ "$USER_SET_NAABU_RATE" != true ]]        && NAABU_RATE=100
        [[ "$USER_SET_NAABU_CONCURRENCY" != true ]] && NAABU_CONCURRENCY=30
        [[ "$USER_SET_HTTPX_THREADS" != true ]]     && HTTPX_THREADS=20
        [[ "$USER_SET_HTTPX_RATE" != true ]]        && HTTPX_RATE=30
        [[ "$USER_SET_HTTPX_DELAY" != true ]]       && HTTPX_DELAY=500
        [[ "$USER_SET_FFUF_THREADS" != true ]]      && FFUF_THREADS=10
        [[ "$USER_SET_FFUF_RATE" != true ]]         && FFUF_RATE=50
        [[ "$USER_SET_PROBE_PARALLEL" != true ]]    && PROBE_PARALLEL=5
    fi

    if [[ "$INTERNAL_MODE" == true ]]; then
        if [[ "$USER_SET_WEB_PORTS" == true ]]; then
            info "Internal mode: keeping user-supplied --ports list"
        else
            info "Internal port list active"
            WEB_PORTS="$INTERNAL_PORTS"
            DISCOVERY_PORTS="$INTERNAL_PORTS"
        fi
    fi
}

# -- Auth args builder --------------------------------------------------------
declare -a AUTH_ARGS_HTTPX
declare -a AUTH_ARGS_NUCLEI
declare -a AUTH_ARGS_FFUF
declare -a AUTH_ARGS_CURL

# curl credentials go into a 0600 config file referenced with -K, so session
# cookies / basic-auth creds do not show up in the process list (ps aux).
# httpx/nuclei/ffuf/dalfox have no equivalent header-file option, so those
# still receive headers via argv -- noted in README/usage.
CURL_AUTH_FILE=""
build_auth_args() {
    AUTH_ARGS_HTTPX=()
    AUTH_ARGS_NUCLEI=()
    AUTH_ARGS_FFUF=()
    AUTH_ARGS_CURL=()
    local curl_cfg=()
    if [[ -n "$AUTH_COOKIE" ]]; then
        AUTH_ARGS_HTTPX+=(-H "Cookie: $AUTH_COOKIE")
        AUTH_ARGS_NUCLEI+=(-H "Cookie: $AUTH_COOKIE")
        AUTH_ARGS_FFUF+=(-H "Cookie: $AUTH_COOKIE")
        curl_cfg+=("header = \"Cookie: ${AUTH_COOKIE//\"/\\\"}\"")
        info "Auth: Cookie header set"
    fi
    if [[ -n "$AUTH_HEADER" ]]; then
        AUTH_ARGS_HTTPX+=(-H "$AUTH_HEADER")
        AUTH_ARGS_NUCLEI+=(-H "$AUTH_HEADER")
        AUTH_ARGS_FFUF+=(-H "$AUTH_HEADER")
        curl_cfg+=("header = \"${AUTH_HEADER//\"/\\\"}\"")
        info "Auth: Custom header set"
    fi
    if [[ -n "$AUTH_BASIC" ]]; then
        local b64
        b64=$(echo -n "$AUTH_BASIC" | base64)
        AUTH_ARGS_HTTPX+=(-H "Authorization: Basic $b64")
        AUTH_ARGS_NUCLEI+=(-H "Authorization: Basic $b64")
        AUTH_ARGS_FFUF+=(-H "Authorization: Basic $b64")
        curl_cfg+=("user = \"${AUTH_BASIC//\"/\\\"}\"")
        info "Auth: Basic auth set"
    fi
    if [[ ${#curl_cfg[@]} -gt 0 ]]; then
        CURL_AUTH_FILE=$(mktemp -t taraf-curl-auth-XXXXXX 2>/dev/null || echo "/tmp/taraf-curl-auth-$$")
        printf '%s\n' "${curl_cfg[@]}" > "$CURL_AUTH_FILE"
        chmod 600 "$CURL_AUTH_FILE" 2>/dev/null || true
        TARAF_TMPFILES+=("$CURL_AUTH_FILE")
        AUTH_ARGS_CURL=(-K "$CURL_AUTH_FILE")
        export CURL_AUTH_FILE
        verb "curl auth config written to $CURL_AUTH_FILE (mode 600)"
    fi
}

# -- Scope enforcement --------------------------------------------------------
# Scope/exclude files are FIXED STRINGS, one per line (grep -F). A scope entry
# "example.com" no longer regex-matches "exampleXcom.attacker.tld". Blank
# lines and #-comments inside the scope files are ignored.
enforce_scope() {
    local input="$1" output="$2"
    cp "$input" "$output" 2>/dev/null || : > "$output"

    if [[ -n "$SCOPE_FILE" && -f "$SCOPE_FILE" ]]; then
        grep -vE '^[[:space:]]*(#|$)' "$SCOPE_FILE" > "${output}.patterns" 2>/dev/null || : > "${output}.patterns"
        grep -Ff "${output}.patterns" "$output" > "${output}.scoped" 2>/dev/null || : > "${output}.scoped"
        mv "${output}.scoped" "$output"
        rm -f "${output}.patterns"
    fi

    if [[ -n "$EXCLUDE_FILE" && -f "$EXCLUDE_FILE" ]]; then
        grep -vE '^[[:space:]]*(#|$)' "$EXCLUDE_FILE" > "${output}.patterns" 2>/dev/null || : > "${output}.patterns"
        grep -vFf "${output}.patterns" "$output" > "${output}.scoped" 2>/dev/null || true
        # grep exits 1 when every line was filtered out; the (possibly empty)
        # output file is still valid, so keep it either way.
        mv "${output}.scoped" "$output"
        rm -f "${output}.patterns"
    fi
}

# -- Tool check ---------------------------------------------------------------
check_tools() {
    local required=("$DNSX" "$HTTPX" "$NAABU" "$NUCLEI")
    local optional=("$SUBFINDER" "$ASSETFINDER" "$GAU" "$WAYBACKURLS"
                    "$FFUF" "$GOWITNESS" "$TLSX" "$DALFOX" "$UNFURL" "$JQ"
                    "$NMAP" "$WHATWEB" "$SUBZY" "$SUBJACK" "$THEHARVESTER"
                    "$GITLEAKS" "$TRUFFLEHOG")
    # Core system utilities the pipeline cannot run without
    local sys_required=(python3 curl awk grep sort)
    local sys_optional=(openssl uuidgen js-beautify prettier setsid ps ping)
    local missing=false t
    for t in "${required[@]}"; do
        if [[ -z "$t" || ! -x "$t" ]]; then
            warn "MISSING (required): $(basename "${t:-unknown}")"
            missing=true
        fi
    done
    for t in "${sys_required[@]}"; do
        if ! command -v "$t" &>/dev/null; then
            warn "MISSING (required system tool): $t"
            missing=true
        fi
    done
    local missing_optional=()
    for t in "${optional[@]}"; do
        if [[ -z "$t" || ! -x "$t" ]]; then
            missing_optional+=("$(basename "${t:-unknown}")")
        fi
    done
    for t in "${sys_optional[@]}"; do
        command -v "$t" &>/dev/null || missing_optional+=("$t")
    done
    if [[ ${#missing_optional[@]} -gt 0 ]]; then
        warn "MISSING (optional, ${#missing_optional[@]}): ${missing_optional[*]}"
    fi
    [[ "$missing" == true ]] && die "Install missing required tools first."
    ok "Tool check passed"
}

# -- Scan mode resolution ------------------------------------------------------
resolve_scan_mode() {
    if [[ "$NO_PORTSCAN" == true ]]; then
        info "NO_PORTSCAN -- naabu scan mode/rate irrelevant, skipping resolution"
        return 0
    fi
    if [[ "$SCAN_MODE" == "auto" ]]; then
        if [[ "$(id -u)" -eq 0 ]]; then
            SCAN_MODE="dual"
            info "Root detected -- using dual scan (SYN + connect verify)"
        else
            SCAN_MODE="connect"
            info "Non-root -- using TCP connect scan"
        fi
    fi
    if [[ "$SCAN_MODE" =~ ^(syn|dual)$ ]] && [[ "$(id -u)" -ne 0 ]]; then
        die "SYN/dual requires root. Use: sudo $0 --${SCAN_MODE} ..."
    fi
    info "Scan: mode=$SCAN_MODE rate=${NAABU_RATE} conc=${NAABU_CONCURRENCY}"
}

# -- Output helper --------------------------------------------------------------
init_outdir() {
    local name="$1" dir
    if [[ -n "$OUTDIR_BASE" ]]; then
        dir="$OUTDIR_BASE/${name}"
    else
        local safe_name
        safe_name=$(echo "$name" | tr ' /' '__' | tr -cd '[:alnum:]_.-')
        dir="taraf_${safe_name}_${TARAF_STAMP}"
    fi
    mkdir -p "$dir"/{passive,discovery,active,deep,report}
    echo "$dir"
}

# -- Output rotation guard -----------------------------------------------------
rotate_if_large() {
    local file="$1"
    if [[ -f "$file" ]]; then
        local size_mb
        size_mb=$(du -m "$file" 2>/dev/null | cut -f1 || echo 0)
        if [[ "$size_mb" -gt "$MAX_OUTFILE_MB" ]]; then
            warn "Rotating $file (${size_mb}MB > ${MAX_OUTFILE_MB}MB limit)"
            mv "$file" "${file}.$(date +%s).bak"
            touch "$file"
        fi
    fi
}

# -- run_cmd wrapper ----------------------------------------------------------
# Returns the wrapped command's real exit code and flags the current sub-phase
# as failed (consumed by state_mark) so --resume retries failed work instead
# of silently skipping it.
run_cmd() {
    local desc="$1"; shift
    if [[ "$DRY_RUN" == true ]]; then
        echo -e "${YELLOW}[DRY-RUN]${RESET} $desc"
        echo "    $*"
        return 0
    fi
    verb "EXEC: $*"

    # Block here if a pause was requested while nothing was running
    while [[ -f "${PAUSE_FLAG:-/nonexistent}" ]]; do
        sleep 0.3
    done

    local rc=0
    if command -v setsid &>/dev/null; then
        if [[ -n "${TIMEOUT:-}" ]]; then
            setsid timeout "$TIMEOUT" "$@" >>"$LOG_FILE" 2>>"$LOG_FILE" &
        else
            setsid "$@" >>"$LOG_FILE" 2>>"$LOG_FILE" &
        fi
        local cpid=$!
        # Record the child's process GROUP id (not its PID): pause/resume
        # signals the whole group. setsid only forks when it is already a
        # process-group leader, so derive the PGID instead of assuming cpid.
        local pgid
        pgid=$(ps -o pgid= -p "$cpid" 2>/dev/null | tr -d ' ')
        echo "${pgid:-$cpid}" > "$CURRENT_PID_FILE" 2>/dev/null
        wait "$cpid" && rc=0 || rc=$?
        rm -f "$CURRENT_PID_FILE" 2>/dev/null
    else
        if [[ -n "${TIMEOUT:-}" ]]; then
            timeout "$TIMEOUT" "$@" >>"$LOG_FILE" 2>>"$LOG_FILE" && rc=0 || rc=$?
        else
            "$@" >>"$LOG_FILE" 2>>"$LOG_FILE" && rc=0 || rc=$?
        fi
    fi
    if [[ $rc -ne 0 ]]; then
        SUBPHASE_FAILED=true
        warn "Command failed (rc=$rc): $desc -- see $LOG_FILE"
    fi
    return $rc
}

# -- Engagement metadata --------------------------------------------------------
write_engagement_metadata() {
    local outdir="$1"

    local engagement_id public_ip nuclei_templates_sha
    engagement_id=$(uuidgen 2>/dev/null || echo "manual-$(date +%s)-$RANDOM")

    # OPSEC: never phone out to an IP-echo service on internal or stealth
    # engagements -- that would announce the scan to a third party.
    if [[ "$INTERNAL_MODE" == true || "$STEALTH" == true ]]; then
        public_ip="withheld (internal/stealth mode)"
    else
        public_ip=$(curl -s --max-time 5 ifconfig.me 2>/dev/null || echo "unknown")
    fi

    nuclei_templates_sha="unknown"
    if [[ -d "$HOME/.config/nuclei-templates/.git" ]]; then
        nuclei_templates_sha=$(cd "$HOME/.config/nuclei-templates" 2>/dev/null && git rev-parse --short HEAD 2>/dev/null || echo "unknown")
    elif [[ -d "$HOME/nuclei-templates/.git" ]]; then
        nuclei_templates_sha=$(cd "$HOME/nuclei-templates" 2>/dev/null && git rev-parse --short HEAD 2>/dev/null || echo "unknown")
    fi

    # Collect tool versions; JSON is built by python3 so quoting/escaping is
    # always valid regardless of what a tool's -version string contains.
    local v_subfinder="" v_httpx="" v_nuclei="" v_naabu=""
    [[ -x "$SUBFINDER" ]] && v_subfinder=$($SUBFINDER -version 2>&1 | head -1)
    [[ -x "$HTTPX" ]]     && v_httpx=$($HTTPX -version 2>&1 | head -1)
    [[ -x "$NUCLEI" ]]    && v_nuclei=$($NUCLEI -version 2>&1 | head -1)
    [[ -x "$NAABU" ]]     && v_naabu=$($NAABU -version 2>&1 | head -1)

    local auth_used=false
    [[ -n "$AUTH_COOKIE$AUTH_HEADER$AUTH_BASIC" ]] && auth_used=true

    TARAF_ENG_ID="$engagement_id" \
    TARAF_TARGET="$(basename "$outdir")" \
    TARAF_ENGAGEMENT_MODE="$ENGAGEMENT_MODE" \
    TARAF_STEALTH="$STEALTH" \
    TARAF_INTERNAL="$INTERNAL_MODE" \
    TARAF_SCOPE_FILE="$SCOPE_FILE" \
    TARAF_EXCLUDE_FILE="$EXCLUDE_FILE" \
    TARAF_AUTH_USED="$auth_used" \
    TARAF_START="$START_TIME" \
    TARAF_END="$(date -Iseconds)" \
    TARAF_VERSION="$VERSION" \
    TARAF_HOST="$(hostname)" \
    TARAF_IP="$public_ip" \
    TARAF_OPERATOR="${USER:-unknown}" \
    TARAF_CMDLINE="$CMD_LINE" \
    TARAF_TEMPLATES_SHA="$nuclei_templates_sha" \
    TARAF_V_SUBFINDER="$v_subfinder" \
    TARAF_V_HTTPX="$v_httpx" \
    TARAF_V_NUCLEI="$v_nuclei" \
    TARAF_V_NAABU="$v_naabu" \
    python3 - "$outdir/engagement.json" <<'PYEOF' 2>>"${LOG_FILE:-/dev/null}" || warn "engagement.json generation failed"
import json, os, sys

e = os.environ
tools = {}
for name, var in (("subfinder", "TARAF_V_SUBFINDER"), ("httpx", "TARAF_V_HTTPX"),
                  ("nuclei", "TARAF_V_NUCLEI"), ("naabu", "TARAF_V_NAABU")):
    if e.get(var):
        tools[name] = e[var].strip()

doc = {
    "engagement_id": e["TARAF_ENG_ID"],
    "target": e["TARAF_TARGET"],
    "engagement_mode": e["TARAF_ENGAGEMENT_MODE"],
    "stealth": e["TARAF_STEALTH"] == "true",
    "internal_mode": e["TARAF_INTERNAL"] == "true",
    "scope_file": e["TARAF_SCOPE_FILE"],
    "exclude_file": e["TARAF_EXCLUDE_FILE"],
    "auth_used": e["TARAF_AUTH_USED"] == "true",
    "start_time": e["TARAF_START"],
    "end_time": e["TARAF_END"],
    "scanner": "taraf v" + e["TARAF_VERSION"],
    "scanner_host": e["TARAF_HOST"],
    "scanner_ip": e["TARAF_IP"],
    "operator": e["TARAF_OPERATOR"],
    "command_line": e["TARAF_CMDLINE"],
    "nuclei_templates_sha": e["TARAF_TEMPLATES_SHA"],
    "tools": tools,
}
with open(sys.argv[1], "w") as fh:
    json.dump(doc, fh, indent=4)
    fh.write("\n")
PYEOF
}

# -- Hostname/IP separation ----------------------------------------------------
filter_real_hostnames() {
    local in_file="$1" out_file="$2"
    if [[ ! -s "$in_file" ]]; then
        : > "$out_file"
        return
    fi
    grep -vE '^([0-9]{1,3}\.){3}[0-9]{1,3}$|^[0-9a-fA-F]*:[0-9a-fA-F:]*$' "$in_file" > "$out_file" 2>/dev/null || true
}

# -- Input normalisation --------------------------------------------------------
# Single awk pass (no per-line subshells). Validates IPv4 octets (0-255),
# accepts CIDR, passes IPv6 through to the IP list, extracts hosts from URLs.
normalise_input() {
    local input="$1" out_ips="$2" out_domains="$3" out_urls="$4"
    awk -v f_ips="$out_ips" -v f_dom="$out_domains" -v f_url="$out_urls" '
        function valid_ipv4(s,   n, a, i) {
            n = split(s, a, ".")
            if (n != 4) return 0
            for (i = 1; i <= 4; i++) {
                if (a[i] !~ /^[0-9]+$/ || a[i] + 0 > 255) return 0
            }
            return 1
        }
        {
            sub(/\r$/, "")                 # CR LF -> LF
            sub(/#.*/, "")                 # strip comments
            gsub(/^[ \t]+|[ \t]+$/, "")    # trim
            if ($0 == "") next

            if ($0 ~ /^https?:\/\//) {
                print $0 >> f_url
                host = $0
                sub(/^[a-zA-Z]+:\/\//, "", host)
                sub(/\/.*$/, "", host)
                sub(/:[0-9]+$/, "", host)
                print host >> f_dom
                next
            }
            ip = $0; sub(/\/[0-9]+$/, "", ip)   # strip CIDR prefix for check
            if (ip ~ /^[0-9.]+$/ && valid_ipv4(ip)) { print $0 >> f_ips; next }
            if ($0 ~ /^[0-9a-fA-F:]+$/ && index($0, ":") > 0) { print $0 >> f_ips; next }  # IPv6
            print $0 >> f_dom
        }
    ' "$input"
    # touch in case awk created nothing (empty input)
    touch "$out_ips" "$out_domains" "$out_urls"
    sort -u -o "$out_ips"     "$out_ips"     2>/dev/null || true
    sort -u -o "$out_domains" "$out_domains" 2>/dev/null || true
    sort -u -o "$out_urls"    "$out_urls"    2>/dev/null || true
}

# -- Probe helpers ---------------------------------------------------------------
# Auth comes from CURL_AUTH_FILE (0600 curl config written by build_auth_args),
# exported so xargs-spawned subshells inherit it -- credentials never appear
# in these workers' argv.
_probe_url() {
    local url="$1"
    local -a auth=()
    [[ -n "${CURL_AUTH_FILE:-}" && -f "${CURL_AUTH_FILE:-}" ]] && auth=(-K "$CURL_AUTH_FILE")
    curl -sk --max-time 15 "${auth[@]}" \
        -o /dev/null -w "%{http_code} %{size_download} ${url}\n" \
        "$url" 2>/dev/null || echo "0 0 $url"
}

_baseline_host() {
    local root_url="$1"
    local -a auth=()
    [[ -n "${CURL_AUTH_FILE:-}" && -f "${CURL_AUTH_FILE:-}" ]] && auth=(-K "$CURL_AUTH_FILE")
    local r1 r2 size_root s1 s2 avg variance
    r1=$(openssl rand -hex 8 2>/dev/null || echo "rand$$$RANDOM")
    r2=$(openssl rand -hex 8 2>/dev/null || echo "rand$$$((RANDOM+1))")
    size_root=$(curl -sk --max-time 10 "${auth[@]}" -o /dev/null -w '%{size_download}' "${root_url}/" 2>/dev/null || echo 0)
    s1=$(curl -sk --max-time 10 "${auth[@]}" -o /dev/null -w '%{size_download}' "${root_url}/notfound-${r1}" 2>/dev/null || echo 0)
    s2=$(curl -sk --max-time 10 "${auth[@]}" -o /dev/null -w '%{size_download}' "${root_url}/notfound-${r2}.html" 2>/dev/null || echo 0)
    avg=$(( (s1 + s2) / 2 ))
    if [[ $s1 -ge $s2 ]]; then variance=$(( s1 - s2 )); else variance=$(( s2 - s1 )); fi
    echo "${root_url} root=${size_root} notfound=${avg} variance=${variance}"
}

# Classify one cloud-bucket URL by response body. Prints "CLASS url" when the
# bucket demonstrably exists; prints nothing for non-existent buckets.
_classify_bucket() {
    local url="$1" body
    body=$(curl -sk --max-time 10 "$url" 2>/dev/null | head -c 3000)
    [[ -z "$body" ]] && return 0
    if printf '%s' "$body" | grep -qiE '<ListBucketResult|<Contents>|<Key>|<Name>'; then
        echo "OPEN_LISTING $url"
    elif printf '%s' "$body" | grep -qiE 'AccessDenied|InvalidAccessKeyId|SignatureDoesNotMatch'; then
        echo "EXISTS_RESTRICTED $url"
    elif printf '%s' "$body" | grep -qiE 'NoSuchBucket|BucketNotFound|The specified bucket does not exist|NoSuchKey'; then
        return 0
    else
        echo "AMBIGUOUS $url"
    fi
}

# Check one URL's body against the takeover fingerprint list passed via the
# TAKEOVER_PATTERNS env var (newline-separated). Prints "url -- pattern: p".
_takeover_check() {
    local url="$1" body pattern
    body=$(curl -sk --max-time 8 "$url" 2>/dev/null | head -c 3000)
    [[ -z "$body" ]] && return 0
    while IFS= read -r pattern; do
        [[ -z "$pattern" ]] && continue
        if printf '%s' "$body" | grep -qiF "$pattern"; then
            printf '%s -- pattern: %s\n' "$url" "$pattern"
            return 0
        fi
    done <<< "${TAKEOVER_PATTERNS:-}"
    return 0
}

# Fetch archive URLs for one domain via gau + waybackurls. Tool paths and the
# log file arrive via exported env (GAU_BIN / WAYBACKURLS_BIN / TARAF_LOG)
# because this runs in xargs-spawned subshells.
_fetch_archive() {
    local domain="$1"
    [[ -z "$domain" ]] && return 0
    if [[ -n "${GAU_BIN:-}" && -x "${GAU_BIN:-}" ]]; then
        timeout 300 "$GAU_BIN" "$domain" --subs --threads 5 2>>"${TARAF_LOG:-/dev/null}"
    fi
    if [[ -n "${WAYBACKURLS_BIN:-}" && -x "${WAYBACKURLS_BIN:-}" ]]; then
        echo "$domain" | timeout 300 "$WAYBACKURLS_BIN" 2>>"${TARAF_LOG:-/dev/null}"
    fi
    return 0
}

export -f _probe_url _baseline_host _classify_bucket _takeover_check _fetch_archive

# -- Helper: run nmap_to_targets.py for --nmap-file mode ---------------------
run_nmap_to_targets() {
    local nmap_input="$1" outdir="$2"
    local script_path
    # Look for nmap_to_targets.py in the same directory as taraf.sh,
    # or fall back to running it as a plain command (must be in $PATH).
    script_path="$(dirname "$(readlink -f "$0")")/nmap_to_targets.py"
    if [[ -f "$script_path" ]]; then
        python3 "$script_path" "$nmap_input" --outdir "$outdir" || die "nmap_to_targets.py failed"
    elif command -v nmap_to_targets.py &>/dev/null; then
        nmap_to_targets.py "$nmap_input" --outdir "$outdir" || die "nmap_to_targets.py failed"
    else
        die "nmap_to_targets.py not found -- place it next to taraf.sh or in PATH"
    fi
}

# =============================================================================
# PHASE 1: PASSIVE RECON
# =============================================================================
phase_passive() {
    local domains_file="$1"
    local passive_dir="$OUTDIR/passive"
    local hostnames_file="$OUTDIR/raw_domains_hostnames.txt"
    [[ -f "$hostnames_file" ]] || filter_real_hostnames "$domains_file" "$hostnames_file"

    state_check "passive" && { info "Phase PASSIVE already done -- skipping"; return 0; }
    [[ "$NO_PASSIVE" == true ]] && { info "NO_PASSIVE -- skipping"; state_mark "passive"; return 0; }
    log "=== PHASE 1: PASSIVE RECON ==="

    local domain_count
    domain_count=$(wc -l < "$domains_file" 2>/dev/null || echo 0)
    if [[ "$domain_count" -eq 0 ]]; then
        warn "No domains for passive recon"
        state_mark "passive"
        return 0
    fi

    # 1.1 CT logs
    touch "$passive_dir/ct_subdomains.txt"
    if ! state_check "passive.ct"; then
        if [[ "$NO_SUBDOM_ENUM" != true && -x "$SUBFINDER" && -s "$hostnames_file" ]]; then
            info "[Passive] CT logs (subfinder --all) ..."
            TIMEOUT=900 run_cmd "subfinder CT" "$SUBFINDER" -dL "$hostnames_file" -all -silent \
                -o "$passive_dir/ct_subdomains.txt"
            ok "CT subdomains: $(wc -l < "$passive_dir/ct_subdomains.txt" 2>/dev/null || echo 0)"
        else
            if [[ "$NO_SUBDOM_ENUM" == true ]]; then
                info "NO_SUBDOM_ENUM -- skipping CT log enumeration"
            elif [[ ! -s "$hostnames_file" ]]; then
                info "[Passive] No genuine hostnames in scope -- skipping CT log lookup (IP-only target list)"
            fi
        fi
        state_mark "passive.ct"
    fi

    # 1.2 Archive URLs
    touch "$passive_dir/archive_urls.txt"
    if ! state_check "passive.archive"; then
        if [[ "$NO_ARCHIVE" != true && -s "$hostnames_file" ]]; then
            info "[Passive] Archive URL extraction (gau / waybackurls, parallel) ..."
            if [[ "$DRY_RUN" == true ]]; then
                local domain
                while IFS= read -r domain; do
                    [[ -z "$domain" ]] && continue
                    [[ -x "$GAU" ]]         && echo -e "${YELLOW}[DRY-RUN]${RESET} gau $domain"
                    [[ -x "$WAYBACKURLS" ]] && echo -e "${YELLOW}[DRY-RUN]${RESET} waybackurls $domain"
                done < "$hostnames_file"
            else
                local archive_parallel=$(( PROBE_PARALLEL > 10 ? 10 : PROBE_PARALLEL ))
                GAU_BIN="$GAU" WAYBACKURLS_BIN="$WAYBACKURLS" TARAF_LOG="$LOG_FILE" \
                xargs -a "$hostnames_file" -P "$archive_parallel" -I{} \
                    bash -c '_fetch_archive "$@"' _ {} \
                    >> "$passive_dir/archive_urls.txt" 2>>"$LOG_FILE"
                sort -u -o "$passive_dir/archive_urls.txt" "$passive_dir/archive_urls.txt" 2>/dev/null || true
            fi
            local archive_count
            archive_count=$(wc -l < "$passive_dir/archive_urls.txt" 2>/dev/null || echo 0)
            ok "Archive URLs: $archive_count"

            if [[ "$archive_count" -gt 0 && -x "$UNFURL" && "$DRY_RUN" != true ]]; then
                info "[Passive] unfurl key/path extraction ..."
                "$UNFURL" -u keys  < "$passive_dir/archive_urls.txt" \
                    > "$passive_dir/archive_params.txt" 2>>"$LOG_FILE" || true
                "$UNFURL" -u paths < "$passive_dir/archive_urls.txt" \
                    > "$passive_dir/archive_paths.txt"  2>>"$LOG_FILE" || true
            fi
        else
            if [[ "$NO_ARCHIVE" == true ]]; then
                info "NO_ARCHIVE -- skipping gau / waybackurls"
            else
                info "[Passive] No genuine hostnames in scope -- skipping archive URL extraction (IP-only target list)"
            fi
        fi
        state_mark "passive.archive"
    fi

    # 1.3 Dorks (domain-semantic -- meaningless without genuine hostnames)
    if ! state_check "passive.dorks"; then
      if [[ -s "$hostnames_file" ]]; then
        info "[Passive] Generating dork queries ..."
        local domain
        while IFS= read -r domain; do
            [[ -z "$domain" ]] && continue
            local org="${domain%%.*}"
            for kw in password api_key secret token config database credentials \
                      AWS_ACCESS_KEY_ID private_key; do
                echo "https://github.com/search?q=%22${domain}%22+${kw}&type=Code"
            done
            for kw in "filename:.env" "filename:config.php" "filename:id_rsa" "filename:.htpasswd"; do
                echo "https://github.com/search?q=%22${domain}%22+${kw}&type=Code"
            done
            echo "https://github.com/search?q=org:${org}+password&type=Code"
            echo "https://github.com/search?q=org:${org}+secret&type=Code"
        done < "$hostnames_file" > "$passive_dir/github_dorks.txt"

        while IFS= read -r domain; do
            [[ -z "$domain" ]] && continue
            echo "https://www.google.com/search?q=site:${domain}+ext:doc+|+ext:pdf+|+ext:csv"
            echo "https://www.google.com/search?q=site:${domain}+inurl:admin+|+inurl:login+|+inurl:portal"
            echo "https://www.google.com/search?q=site:${domain}+ext:xml+|+ext:env+|+ext:ini+|+ext:config"
            echo "https://www.google.com/search?q=site:${domain}+ext:sql+|+ext:bak+|+ext:backup"
            echo "https://www.google.com/search?q=site:${domain}+intitle:index.of"
            echo "https://www.google.com/search?q=site:${domain}+inurl:phpinfo+|+inurl:server-status"
            echo "https://www.google.com/search?q=site:${domain}+inurl:api+|+inurl:swagger+|+inurl:graphql"
            echo "https://www.google.com/search?q=site:${domain}+PHP+Parse+error"
            echo "https://www.google.com/search?q=site:${domain}+inurl:.git+|+inurl:.env"
            echo "https://www.google.com/search?q=site:${domain}+inurl:wp-content"
        done < "$hostnames_file" > "$passive_dir/google_dorks.txt"

        while IFS= read -r domain; do
            [[ -z "$domain" ]] && continue
            echo "https://www.shodan.io/search?query=hostname:${domain}"
            echo "https://search.censys.io/search?resource=hosts&q=${domain}"
            echo "https://crt.sh/?q=%.${domain}"
        done < "$hostnames_file" > "$passive_dir/shodan_queries.txt"

        ok "Dorks written to $passive_dir/"
      else
        info "[Passive] No genuine hostnames in scope -- skipping dork generation (IP-only target list)"
      fi
        state_mark "passive.dorks"
    fi

    # 1.4 Cloud asset discovery
    if [[ "$NO_CLOUD" != true ]] && ! state_check "passive.cloud"; then
        info "[Passive] Cloud asset discovery (S3/Azure/GCP) ..."
        local cloud_cand="$passive_dir/cloud_buckets_candidates.txt"
        : > "$cloud_cand"
        while IFS= read -r domain; do
            [[ -z "$domain" ]] && continue
            local clean_domain="${domain#www.}"
            local org="${clean_domain%%.*}"
            case "$org" in
                www|mail|api|app|portal|admin|test|dev|staging|prod|gov|gouv|smtp|ftp|ns|ns1|ns2|mx|imap|webmail)
                    continue ;;
            esac
            local domain_dashed
            domain_dashed=$(echo "$clean_domain" | tr '.' '-')
            for pattern in \
                "$org" "$org-backup" "$org-prod" "$org-dev" "$org-staging" \
                "$org-data" "$org-uploads" "$org-static" "$org-assets" \
                "$org-logs" "$org-public" "$org-private" "$org-files" \
                "$org-media" "$org-images" "$org-storage" \
                "$domain_dashed" "${domain_dashed}-backup" "${domain_dashed}-data"; do
                echo "https://${pattern}.s3.amazonaws.com"
                echo "https://s3.amazonaws.com/${pattern}"
                echo "https://${pattern}.s3-eu-west-1.amazonaws.com"
                echo "https://${pattern}.s3-us-west-2.amazonaws.com"
                echo "https://${pattern}.blob.core.windows.net"
                echo "https://${pattern}.file.core.windows.net"
                echo "https://storage.googleapis.com/${pattern}"
                echo "https://${pattern}.storage.googleapis.com"
                echo "https://${pattern}.digitaloceanspaces.com"
            done
        done < "$hostnames_file" >> "$cloud_cand"
        sort -u -o "$cloud_cand" "$cloud_cand"

        local cand_count
        cand_count=$(wc -l < "$cloud_cand" 2>/dev/null || echo 0)
        info "Cloud bucket candidates: $cand_count"

        if [[ -x "$HTTPX" && -s "$cloud_cand" && "$DRY_RUN" != true ]]; then
            "$HTTPX" -l "$cloud_cand" \
                -mc 200,403 -t 50 -timeout 10 -silent -nc \
                -title -sc \
                -o "$passive_dir/cloud_buckets_responding.txt" 2>>"$LOG_FILE" || true

            : > "$passive_dir/cloud_buckets_found.txt"
            if [[ -s "$passive_dir/cloud_buckets_responding.txt" ]]; then
                info "[Passive] Validating responding buckets (parallel, $PROBE_PARALLEL workers) ..."
                grep -oP 'https?://\S+' "$passive_dir/cloud_buckets_responding.txt" | sort -u \
                | xargs -P "$PROBE_PARALLEL" -I{} bash -c '_classify_bucket "$@"' _ {} \
                >> "$passive_dir/cloud_buckets_found.txt" 2>>"$LOG_FILE"
                sort -u -o "$passive_dir/cloud_buckets_found.txt" "$passive_dir/cloud_buckets_found.txt" 2>/dev/null || true
            fi
            local responding_count
            responding_count=$(wc -l < "$passive_dir/cloud_buckets_found.txt" 2>/dev/null || echo 0)
            if [[ "$responding_count" -gt 0 ]]; then
                warn "Cloud buckets validated: $responding_count (see cloud_buckets_found.txt)"
            else
                info "No real cloud buckets after body-validation"
            fi
        fi
        state_mark "passive.cloud"
    fi

    # 1.5 OSINT (opt-in)
    if [[ "$RUN_OSINT" == true ]] && ! state_check "passive.osint"; then
        info "[Passive] Email/people OSINT preparation ..."
        : > "$passive_dir/osint_queries.txt"
        local domain
        while IFS= read -r domain; do
            [[ -z "$domain" ]] && continue
            cat >> "$passive_dir/osint_queries.txt" <<EOF
# Domain: $domain
https://hunter.io/search/$domain
https://www.linkedin.com/search/results/people/?keywords=$domain
https://app.dehashed.com/search?query=$domain
https://haveibeenpwned.com/DomainSearch
https://intelx.io/?s=$domain
https://www.google.com/search?q=site:linkedin.com+%22$domain%22
https://github.com/search?q=%22${domain}%22+%22@${domain}%22&type=Code
EOF
        done < "$hostnames_file"

        if [[ -x "$THEHARVESTER" ]]; then
            local first_domain
            first_domain=$(head -1 "$hostnames_file")
            [[ -n "$first_domain" ]] && TIMEOUT=600 run_cmd "theHarvester" \
                "$THEHARVESTER" -d "$first_domain" -b all -f "$passive_dir/harvester_${first_domain}" || true
        fi
        state_mark "passive.osint"
    fi

    state_mark "passive"
    ok "Phase PASSIVE complete"
}

# =============================================================================
# PHASE 2: DISCOVERY
# =============================================================================
phase_discovery() {
    local raw_ips="$1" raw_domains="$2" raw_urls="$3"
    local disc_dir="$OUTDIR/discovery"
    local hostnames_file="$OUTDIR/raw_domains_hostnames.txt"
    [[ -f "$hostnames_file" ]] || filter_real_hostnames "$raw_domains" "$hostnames_file"

    state_check "discovery" && { info "Phase DISCOVERY already done -- skipping"; return 0; }
    log "=== PHASE 2: DISCOVERY ==="

    # 2.1 DNS resolution
    touch "$disc_dir/dns_records.jsonl" "$disc_dir/resolved_ips.txt" "$disc_dir/resolved_hosts.txt"
    if [[ -s "$hostnames_file" && -x "$DNSX" ]] && ! state_check "discovery.dns"; then
        info "[Discovery] DNS resolution (dnsx) ..."
        TIMEOUT=600 run_cmd "dnsx resolve" "$DNSX" \
            -l "$hostnames_file" -a -aaaa -cname -mx -txt -soa \
            -silent -json -o "$disc_dir/dns_records.jsonl"

        if [[ -x "$JQ" && -s "$disc_dir/dns_records.jsonl" ]]; then
            "$JQ" -r 'select(.a!=null) | .a[]?' \
                "$disc_dir/dns_records.jsonl" 2>/dev/null \
                | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' \
                >> "$disc_dir/resolved_ips.txt" || true
            "$JQ" -r 'select(.host!=null) | .host' \
                "$disc_dir/dns_records.jsonl" 2>/dev/null \
                >> "$disc_dir/resolved_hosts.txt" || true
        fi
        state_mark "discovery.dns"
    fi

    cat "$raw_ips" "$disc_dir/resolved_ips.txt" "$raw_domains" 2>/dev/null \
    | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' \
    | sort -u > "$disc_dir/all_ips.txt"
    local ip_count
    ip_count=$(wc -l < "$disc_dir/all_ips.txt" 2>/dev/null || echo 0)
    info "Total unique IPs: $ip_count"

    # 2.2 Subdomain enum
    touch "$disc_dir/subdomains_enum.txt"
    if [[ "$NO_SUBDOM_ENUM" != true ]] && ! state_check "discovery.subdom"; then
        if [[ -s "$hostnames_file" ]]; then
            info "[Discovery] Subdomain enumeration ..."
            if [[ -x "$SUBFINDER" ]]; then
                TIMEOUT=900 run_cmd "subfinder" "$SUBFINDER" -dL "$hostnames_file" -all -silent \
                    -o "$disc_dir/subfinder.txt"
                [[ -s "$disc_dir/subfinder.txt" ]] && \
                    cat "$disc_dir/subfinder.txt" >> "$disc_dir/subdomains_enum.txt"
            fi
            if [[ -x "$ASSETFINDER" ]]; then
                local d
                while IFS= read -r d; do
                    [[ -z "$d" ]] && continue
                    if [[ "$DRY_RUN" == true ]]; then
                        echo -e "${YELLOW}[DRY-RUN]${RESET} assetfinder $d"
                    else
                        verb "EXEC: assetfinder $d"
                        timeout 120 "$ASSETFINDER" --subs-only "$d" \
                            >> "$disc_dir/subdomains_enum.txt" 2>>"$LOG_FILE" || true
                    fi
                done < "$hostnames_file"
            fi
            if [[ -x "$AMASS" ]]; then
                local d
                while IFS= read -r d; do
                    [[ -z "$d" ]] && continue
                    if [[ "$DRY_RUN" == true ]]; then
                        echo -e "${YELLOW}[DRY-RUN]${RESET} amass $d"
                    else
                        verb "EXEC: amass $d"
                        timeout 600 "$AMASS" enum -passive -d "$d" -silent \
                            >> "$disc_dir/subdomains_enum.txt" 2>>"$LOG_FILE" || true
                    fi
                done < "$hostnames_file"
            fi
        else
            info "[Discovery] No genuine hostnames in scope -- skipping subdomain enumeration (IP-only target list)"
        fi
        sort -u -o "$disc_dir/subdomains_enum.txt" "$disc_dir/subdomains_enum.txt" 2>/dev/null || true
        ok "Subdomains enumerated: $(wc -l < "$disc_dir/subdomains_enum.txt" 2>/dev/null || echo 0)"
        state_mark "discovery.subdom"
    else
        [[ "$NO_SUBDOM_ENUM" == true ]] && info "[Discovery] Skipping subdomain enumeration"
    fi

    touch "$disc_dir/subdomains.txt"
    cat "$raw_domains" "$disc_dir/resolved_hosts.txt" "$disc_dir/subdomains_enum.txt" 2>/dev/null \
    >> "$disc_dir/subdomains.txt"
    local url
    while IFS= read -r url; do
        [[ -z "$url" ]] && continue
        echo "$url" | sed 's|^[a-zA-Z]*://||' | cut -d'/' -f1 | cut -d':' -f1
    done < "$raw_urls" 2>/dev/null >> "$disc_dir/subdomains.txt"
    sort -u -o "$disc_dir/subdomains.txt" "$disc_dir/subdomains.txt"

    if [[ -n "$SCOPE_FILE" || -n "$EXCLUDE_FILE" ]]; then
        local pre_count
        pre_count=$(wc -l < "$disc_dir/subdomains.txt" 2>/dev/null || echo 0)
        enforce_scope "$disc_dir/subdomains.txt" "$disc_dir/subdomains_scoped.txt"
        mv "$disc_dir/subdomains_scoped.txt" "$disc_dir/subdomains.txt"
        local post_count
        post_count=$(wc -l < "$disc_dir/subdomains.txt" 2>/dev/null || echo 0)
        info "[Scope] Filtered $pre_count -> $post_count hosts"
    fi

    ok "Target hostnames total: $(wc -l < "$disc_dir/subdomains.txt" 2>/dev/null || echo 0)"

    # 2.3 Host discovery
    local alive_ips="$disc_dir/alive_ips.txt"
    touch "$disc_dir/icmp_hits.txt" "$disc_dir/tcp_discovery_hits.txt" "$alive_ips"

    if [[ "$ip_count" -gt 0 && "$NO_DISCOVERY" != true && -x "$NAABU" ]] && ! state_check "discovery.hostup"; then
        info "[Discovery] Host liveness check (ICMP + TCP) ..."
        local max_jobs=100 ip pid
        local -a ping_pids=()
        while IFS= read -r ip; do
            [[ -z "$ip" ]] && continue
            ( ping -c 2 -W 1 -q "$ip" &>/dev/null \
                && echo "$ip" >> "$disc_dir/icmp_hits.txt" ) &
            ping_pids+=("$!")
            if (( ${#ping_pids[@]} >= max_jobs )); then
                for pid in "${ping_pids[@]}"; do
                    wait "$pid" 2>/dev/null || true
                done
                ping_pids=()
            fi
        done < "$disc_dir/all_ips.txt"
        for pid in "${ping_pids[@]}"; do
            wait "$pid" 2>/dev/null || true
        done

        local disc_ports="$DISCOVERY_PORTS"
        [[ "$INTERNAL_MODE" == true ]] && disc_ports="$INTERNAL_PORTS"

        info "[Discovery] Naabu discovery TCP scan (ports: $disc_ports)..."
        TIMEOUT=300 run_cmd "naabu discovery TCP" "$NAABU" \
            -list "$disc_dir/all_ips.txt" \
            -p "$disc_ports" -s c \
            -c 200 -rate 3000 -retries 1 -silent \
            -o "$disc_dir/discovery_ports.raw"

        if [[ -s "$disc_dir/discovery_ports.raw" ]]; then
            grep -oE '^([0-9]{1,3}\.){3}[0-9]{1,3}' \
                "$disc_dir/discovery_ports.raw" | sort -u \
                > "$disc_dir/tcp_discovery_hits.txt"
        fi

        cat "$disc_dir/icmp_hits.txt" "$disc_dir/tcp_discovery_hits.txt" 2>/dev/null \
        | sort -u > "$alive_ips"

        local alive_count dead_count
        alive_count=$(wc -l < "$alive_ips" 2>/dev/null || echo 0)
        dead_count=$(( ip_count - alive_count ))
        ok "Host discovery: $alive_count alive, $dead_count down"

        comm -23 <(sort "$disc_dir/all_ips.txt") <(sort "$alive_ips") \
            > "$disc_dir/hosts_down.txt" 2>/dev/null || true
        state_mark "discovery.hostup"
    else
        if [[ "$NO_DISCOVERY" == true ]]; then
            info "NO_DISCOVERY -- treating all $ip_count IPs as alive"
        fi
        cp "$disc_dir/all_ips.txt" "$alive_ips" 2>/dev/null || true
    fi

    # 2.4 Port scan
    touch "$disc_dir/naabu_urls.txt" "$disc_dir/open_ports.txt"
    if [[ "$NO_PORTSCAN" != true && -x "$NAABU" && -s "$alive_ips" ]] && ! state_check "discovery.ports"; then
        info "[Discovery] Port scan on web ports (naabu) ..."
        local naabu_flag="c"
        [[ "$SCAN_MODE" == "syn" ]] && naabu_flag="s"

        if [[ "$SCAN_MODE" == "dual" ]]; then
            info "[Discovery] Naabu SYN scan..."
            TIMEOUT=$PHASE_TIMEOUT run_cmd "naabu SYN" "$NAABU" \
                -list "$alive_ips" -p "$WEB_PORTS" -s s \
                -c "$NAABU_CONCURRENCY" -rate "$NAABU_RATE" \
                -retries "$NAABU_RETRIES" \
                -silent -o "$disc_dir/naabu_syn.txt"
            info "[Discovery] Naabu connect scan..."
            TIMEOUT=$PHASE_TIMEOUT run_cmd "naabu connect" "$NAABU" \
                -list "$alive_ips" -p "$WEB_PORTS" -s c \
                -c "$NAABU_CONCURRENCY" -rate "$NAABU_RATE" \
                -retries "$NAABU_RETRIES" \
                -silent -o "$disc_dir/naabu_connect.txt"
            cat "$disc_dir/naabu_syn.txt" "$disc_dir/naabu_connect.txt" 2>/dev/null \
            | sort -u > "$disc_dir/open_ports.txt"
        else
            info "[Discovery] Naabu portscan (mode: $naabu_flag)..."
            TIMEOUT=$PHASE_TIMEOUT run_cmd "naabu portscan" "$NAABU" \
                -list "$alive_ips" -p "$WEB_PORTS" -s "$naabu_flag" \
                -c "$NAABU_CONCURRENCY" -rate "$NAABU_RATE" \
                -retries "$NAABU_RETRIES" \
                -silent -o "$disc_dir/open_ports.txt"
        fi

        if [[ -s "$disc_dir/open_ports.txt" ]]; then
            local entry ip port
            while IFS= read -r entry; do
                ip=$(echo "$entry" | cut -d: -f1)
                port=$(echo "$entry" | cut -d: -f2)
                case "$port" in
                    443|8443|9443) echo "https://${ip}:${port}" ;;
                    *)             echo "http://${ip}:${port}"  ;;
                esac
            done < "$disc_dir/open_ports.txt" > "$disc_dir/naabu_urls.txt"
        fi
        ok "Open ports (naabu): $(wc -l < "$disc_dir/open_ports.txt" 2>/dev/null || echo 0)"
        state_mark "discovery.ports"
    else
        [[ "$NO_PORTSCAN" == true ]] && info "NO_PORTSCAN -- skipping naabu port scan"
    fi

    # 2.4b Nmap (opt-in)
    touch "$disc_dir/nmap_urls.txt"
    if [[ "$RUN_NMAP" == true && -x "$NMAP" && -s "$alive_ips" ]]; then
        info "[Discovery] Optional nmap port scan ..."
        local -a nmap_flags=(-sT)
        [[ "$(id -u)" -eq 0 ]] && nmap_flags=(-sS)
        TIMEOUT=$PHASE_TIMEOUT run_cmd "nmap portscan" "$NMAP" \
            "${nmap_flags[@]}" -iL "$alive_ips" -p "$WEB_PORTS" \
            --open -T4 -n --min-rate 500 \
            -oG "$disc_dir/nmap_web.gnmap" 2>/dev/null || true

        if [[ -s "$disc_dir/nmap_web.gnmap" ]]; then
            grep "^Host:" "$disc_dir/nmap_web.gnmap" | while IFS= read -r line; do
                local ip
                ip=$(echo "$line" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}')
                [[ -z "$ip" ]] && continue
                echo "$line" | grep -oE '[0-9]+/open' | while IFS= read -r ps; do
                    echo "${ip}:${ps%%/*}"
                done
            done | sort -u > "$disc_dir/nmap_open_ports.txt"
        fi

        if [[ -s "$disc_dir/nmap_open_ports.txt" ]]; then
            while IFS= read -r entry; do
                local ip port
                ip=$(echo "$entry" | cut -d: -f1)
                port=$(echo "$entry" | cut -d: -f2)
                case "$port" in
                    443|8443|9443) echo "https://${ip}:${port}" ;;
                    *)             echo "http://${ip}:${port}"  ;;
                esac
            done < "$disc_dir/nmap_open_ports.txt" > "$disc_dir/nmap_urls.txt"
        fi
        ok "Nmap open ports: $(wc -l < "$disc_dir/nmap_open_ports.txt" 2>/dev/null || echo 0)"
    fi

    # 2.5 CF hosts
    touch "$disc_dir/cf_direct_urls.txt"
    if [[ -n "$CF_HOSTS_FILE" && -f "$CF_HOSTS_FILE" ]]; then
        info "[Discovery] CF hosts -- probing directly ..."
        local cfhost
        while IFS= read -r cfhost; do
            [[ -z "$cfhost" ]] && continue
            echo "https://${cfhost}"
            echo "http://${cfhost}"
        done < "$CF_HOSTS_FILE" >> "$disc_dir/cf_direct_urls.txt"
        sort -u -o "$disc_dir/cf_direct_urls.txt" "$disc_dir/cf_direct_urls.txt"
    fi

    # 2.5b Network‑targets web candidates
    local ntwk_web_candidates="$disc_dir/ntwk_web_candidates.txt"
    : > "$ntwk_web_candidates"
    if [[ -n "${NETWORK_TARGETS_FILE:-}" && -s "$NETWORK_TARGETS_FILE" ]]; then
        info "[Discovery] Generating web candidates from --network-targets ..."
        local ntwk_entry ntwk_ip ntwk_port
        while IFS= read -r ntwk_entry; do
            [[ -z "$ntwk_entry" ]] && continue
            ntwk_ip=$(echo "$ntwk_entry" | cut -d: -f1)
            ntwk_port=$(echo "$ntwk_entry" | cut -d: -f2)
            echo "http://${ntwk_ip}:${ntwk_port}"
            echo "https://${ntwk_ip}:${ntwk_port}"
        done < "$NETWORK_TARGETS_FILE" | sort -u > "$ntwk_web_candidates"
        ok "Network‑targets web candidates: $(wc -l < "$ntwk_web_candidates")"
    fi

    # 2.6 Build URL candidate list
    info "[Discovery] Building URL candidate list ..."
    {
        cat "$raw_urls"                  2>/dev/null
        cat "$disc_dir/cf_direct_urls.txt" 2>/dev/null
        cat "$disc_dir/nmap_urls.txt"      2>/dev/null
        cat "$disc_dir/naabu_urls.txt"     2>/dev/null
        cat "$ntwk_web_candidates"         2>/dev/null
    } > "$disc_dir/.explicit_urls.tmp"

    local known_hosts_file="$disc_dir/.known_hosts_for_scheme.tmp"
    grep -oP '^https?://\K[^:/]+' "$disc_dir/.explicit_urls.tmp" 2>/dev/null \
    | sort -u > "$known_hosts_file"

    {
        if [[ -s "$disc_dir/subdomains.txt" ]]; then
            while IFS= read -r host; do
                [[ -z "$host" ]] && continue
                if [[ "$host" =~ ^https?:// ]]; then
                    echo "$host"
                    continue
                fi
                if grep -qxF "$host" "$known_hosts_file" 2>/dev/null; then
                    continue
                fi
                echo "https://${host}"
                echo "http://${host}"
            done < "$disc_dir/subdomains.txt"
        fi
        cat "$disc_dir/.explicit_urls.tmp"
    } | awk '!seen[$0]++' > "$disc_dir/all_targets.txt"
    rm -f "$disc_dir/.explicit_urls.tmp" "$known_hosts_file"

    if [[ -s "$disc_dir/alive_ips.txt" ]]; then
        local known_ips_file="$disc_dir/.known_ips.tmp"
        grep -oP '^https?://\K[^:/]+' "$disc_dir/all_targets.txt" 2>/dev/null \
        | sort -u > "$known_ips_file"
        local ip wp guessed=0 skipped=0
        while IFS= read -r ip; do
            [[ -z "$ip" ]] && continue
            if grep -qxF "$ip" "$known_ips_file" 2>/dev/null; then
                ((skipped++)) || true
                continue
            fi
            ((guessed++)) || true
            for wp in ${WEB_PORTS//,/ }; do
                case "$wp" in
                    443|8443|9443) echo "https://${ip}:${wp}" ;;
                    *)             echo "http://${ip}:${wp}"  ;;
                esac
            done
        done < "$disc_dir/alive_ips.txt" >> "$disc_dir/all_targets.txt"
        sort -u -o "$disc_dir/all_targets.txt" "$disc_dir/all_targets.txt"
        rm -f "$known_ips_file"
        info "Port-guessing: $skipped hosts already had explicit URLs (skipped), $guessed hosts had none (guessed $WEB_PORTS)"
    fi

    if [[ -n "$SCOPE_FILE" || -n "$EXCLUDE_FILE" ]]; then
        enforce_scope "$disc_dir/all_targets.txt" "$disc_dir/all_targets_scoped.txt"
        mv "$disc_dir/all_targets_scoped.txt" "$disc_dir/all_targets.txt"
    fi

    # 2.7 httpx probe
    touch "$disc_dir/httpx_live.jsonl" "$disc_dir/live_urls_httpx.txt" \
          "$disc_dir/live_hosts.txt" "$disc_dir/live_urls.txt"

    if [[ -s "$disc_dir/all_targets.txt" && -x "$HTTPX" ]] && ! state_check "discovery.httpx"; then
        info "[Discovery] HTTP probing (httpx) ..."
        local httpx_args=(
            -l "$disc_dir/all_targets.txt"
            -td -sc -title -server -favicon -ip -cname
            -t "$HTTPX_THREADS"
            -rl "$HTTPX_RATE"
            -timeout 15 -retries 2
            -nc -silent -j -ztls -random-agent
            -mc 200,201,204,301,302,307,308,401,403,405,500,502,503
            -o "$disc_dir/httpx_live.jsonl"
        )
        if [[ "$HTTPX_DELAY" -gt 0 ]]; then
            httpx_args+=(-delay "${HTTPX_DELAY}ms")
        fi
        if [[ ${#AUTH_ARGS_HTTPX[@]} -gt 0 ]]; then
            httpx_args+=("${AUTH_ARGS_HTTPX[@]}")
        fi

        TIMEOUT=$PHASE_TIMEOUT run_cmd "httpx probe" "$HTTPX" "${httpx_args[@]}"

        if [[ -x "$JQ" && -s "$disc_dir/httpx_live.jsonl" ]]; then
            "$JQ" -r 'select(.status_code != null and .status_code > 0) | .url' \
                "$disc_dir/httpx_live.jsonl" 2>/dev/null \
                | sort -u > "$disc_dir/live_urls_httpx.txt"
            "$JQ" -r 'select(.status_code != null and .status_code > 0) | .host // .url' \
                "$disc_dir/httpx_live.jsonl" 2>/dev/null \
                | sed 's|^[a-zA-Z]*://||' | cut -d'/' -f1 \
                | sort -u > "$disc_dir/live_hosts.txt"
        else
            grep -oP '"url"\s*:\s*"\K[^"]+' "$disc_dir/httpx_live.jsonl" 2>/dev/null \
                | sort -u > "$disc_dir/live_urls_httpx.txt" || true
        fi
        state_mark "discovery.httpx"
    fi

    # 2.8 WhatWeb quick overview
    touch "$disc_dir/whatweb_discovery_brief.txt" "$disc_dir/live_urls_whatweb.txt"
    if [[ "$NO_WHATWEB" != true && -x "$WHATWEB" && -s "$disc_dir/all_targets.txt" ]] && ! state_check "discovery.whatweb"; then
        local all_tg_count whatweb_max="${WHATWEB_MAX_TARGETS:-1000}"
        all_tg_count=$(wc -l < "$disc_dir/all_targets.txt" 2>/dev/null || echo 0)
        if [[ "$all_tg_count" -gt "$whatweb_max" ]]; then
            warn "[Discovery] $all_tg_count targets -- skipping WhatWeb quick overview (over WHATWEB_MAX_TARGETS=$whatweb_max)"
        else
            info "[Discovery] WhatWeb quick overview on discovered web services..."
            TIMEOUT=1800 run_cmd "whatweb discovery" "$WHATWEB" \
                --input-file="$disc_dir/all_targets.txt" \
                --log-brief="$disc_dir/whatweb_discovery_brief.txt" \
                --no-errors -q 2>>"$LOG_FILE" || true

            if [[ -s "$disc_dir/whatweb_discovery_brief.txt" ]]; then
                grep -oP '^https?://\S+' "$disc_dir/whatweb_discovery_brief.txt" \
                | sort -u > "$disc_dir/live_urls_whatweb.txt"
            fi
        fi
        state_mark "discovery.whatweb"
    fi

    cat "$disc_dir/live_urls_httpx.txt" "$disc_dir/live_urls_whatweb.txt" 2>/dev/null \
    | awk '!seen[$0]++' | sort -u > "$disc_dir/live_urls.txt"

    local live_count
    live_count=$(wc -l < "$disc_dir/live_urls.txt" 2>/dev/null || echo 0)
    ok "Live HTTP(S) services: $live_count"

    # 2.9 TLS
    if [[ "$NO_TLS" != true && -x "$TLSX" && -s "$disc_dir/live_urls.txt" ]] && ! state_check "discovery.tls"; then
        info "[Discovery] TLS/SSL analysis (tlsx) ..."
        TIMEOUT=600 run_cmd "tlsx" "$TLSX" \
            -l "$disc_dir/live_urls.txt" -silent -json \
            -o "$disc_dir/tlsx.jsonl"
        if [[ -x "$JQ" && -s "$disc_dir/tlsx.jsonl" ]]; then
            "$JQ" -r 'select(.subject_cn!=null) | .subject_cn,
                       (.subject_an // [] | .[])?' \
                "$disc_dir/tlsx.jsonl" 2>/dev/null \
                | grep -v '^\*' | sort -u > "$disc_dir/tls_sans.txt" || true
            info "TLS SANs saved to tls_sans.txt"
        fi
        state_mark "discovery.tls"
    fi

    # 2.10 Quick Tech Profile for immediate overview
    local disc_tech_raw="$disc_dir/tech_profile_raw.txt"
    local disc_tech="$disc_dir/tech_profile.txt"
    : > "$disc_tech_raw"
    if [[ -x "$JQ" && -s "$disc_dir/httpx_live.jsonl" ]]; then
        "$JQ" -r 'select(.tech!=null) | .tech[]' \
            "$disc_dir/httpx_live.jsonl" 2>/dev/null \
            | tr '[:upper:]' '[:lower:]' | sort -u >> "$disc_tech_raw" || true
    fi
    clean_tech_profile "$disc_tech_raw" "$disc_tech"
    if [[ -s "$disc_tech" ]]; then
        ok "[Discovery] Quick Tech Overview: $(tr '\n' ',' < "$disc_tech" | sed 's/,$//')"
    fi

    state_mark "discovery"
    ok "Phase DISCOVERY complete"
}

# =============================================================================
# PHASE 3: ACTIVE ENUMERATION
# =============================================================================
phase_active() {
    local disc_dir="$OUTDIR/discovery"
    local active_dir="$OUTDIR/active"
    local live_urls="$disc_dir/live_urls.txt"

    state_check "active" && { info "Phase ACTIVE already done -- skipping"; return 0; }
    [[ ! -s "$live_urls" ]] && { warn "No live URLs for active phase"; state_mark "active"; return 0; }
    log "=== PHASE 3: ACTIVE ENUMERATION ==="

    # 3.1 Vhost fuzzing
    touch "$active_dir/vhost_discovered.txt"
    if [[ "$NO_VHOST" != true && -x "$FFUF" ]] && ! state_check "active.vhost"; then
        info "[Active] Virtual host enumeration (ffuf) ..."
        local vhost_wl="$WORDLIST_DIR/Discovery/DNS/subdomains-top1million-5000.txt"
        [[ ! -f "$vhost_wl" ]] && vhost_wl="$WORDLIST_DIR/Discovery/DNS/namelist.txt"

        if [[ -f "$vhost_wl" && -x "$JQ" && -s "$disc_dir/httpx_live.jsonl" ]]; then
            "$JQ" -r 'select(.ip!=null) | "\(.ip) \(.url)"' \
                "$disc_dir/httpx_live.jsonl" 2>/dev/null \
                | sort -u > "$active_dir/ip_url_map.txt"

            awk '{print $1}' "$active_dir/ip_url_map.txt" \
            | sort | uniq -c | sort -rn \
            | awk '$1 > 1 {print $2}' > "$active_dir/shared_ips.txt"

            local ip base_url base_host base_domain
            while IFS= read -r ip; do
                [[ -z "$ip" ]] && continue
                base_url=$(grep "^${ip} " "$active_dir/ip_url_map.txt" | head -1 | awk '{print $2}')
                [[ -z "$base_url" ]] && continue
                base_host=$(echo "$base_url" | sed 's|^[a-zA-Z]*://||' | cut -d'/' -f1 | cut -d':' -f1)
                base_domain=$(echo "$base_host" | awk -F. 'NF>=2{print $(NF-1)"."$NF}')
                [[ -z "$base_domain" ]] && continue
                info "[Active] Vhost fuzzing $ip (base: $base_domain) ..."
                local safe_ip
                safe_ip=$(echo "$ip" | tr '.' '_')

                local -a ffuf_args=(
                    -w "$vhost_wl" -u "$base_url"
                    -H "Host: FUZZ.${base_domain}"
                    -t "$FFUF_THREADS" -rate "$FFUF_RATE"
                    -mc 200,301,302,401,403,500,502,503
                    -timeout 10 -s
                    -o "$active_dir/vhost_${safe_ip}.json"
                )
                [[ ${#AUTH_ARGS_FFUF[@]} -gt 0 ]] && ffuf_args+=("${AUTH_ARGS_FFUF[@]}")
                TIMEOUT=600 run_cmd "ffuf vhost $ip" "$FFUF" "${ffuf_args[@]}"
            done < "$active_dir/shared_ips.txt"

            local f
            for f in "$active_dir"/vhost_*.json; do
                [[ -f "$f" ]] || continue
                "$JQ" -r '.results[]? | .url' "$f" 2>/dev/null
            done | sort -u > "$active_dir/vhost_discovered.txt" 2>/dev/null || true
            ok "Virtual hosts discovered: $(wc -l < "$active_dir/vhost_discovered.txt" 2>/dev/null || echo 0)"
        else
            warn "[Active] Skipping vhost fuzz -- wordlist or jq not available"
        fi
        state_mark "active.vhost"
    fi

    # 3.2 Backup probe
    touch "$active_dir/backup_hits.txt" "$active_dir/git_confirmed.txt"
    if [[ "$NO_BACKUP_CHECK" != true ]] && ! state_check "active.backup"; then
        info "[Active] Targeted backup / sensitive file probe ..."
        local candidates="$active_dir/backup_candidates.txt"
        local sized_hits="$active_dir/backup_hits_sized.txt"
        local baseline_file="$active_dir/baselines.txt"
        : > "$candidates"
        : > "$sized_hits"

        local url
        while IFS= read -r url; do
            [[ -z "$url" ]] && continue
            local root_url host first_label domain_stem
            root_url=$(echo "$url" | sed -E 's|^([a-zA-Z]+://[^/]+).*|\1|')
            host=$(echo "$root_url" | sed 's|^[a-zA-Z]*://||' | cut -d':' -f1)
            first_label=$(echo "$host" | cut -d'.' -f1)
            domain_stem=$(echo "$host" | cut -d'.' -f2-)

            for path in \
                /.git/config /.env /.env.bak /.env.prod /.env.local /.env.development \
                /web.config /web.config.bak /Web.config \
                /app.config /appsettings.json /appsettings.Development.json /appsettings.Production.json \
                /backup.zip /backup.tar.gz /backup.sql /backup.tar /backup.7z \
                /dump.sql /database.sql /db.sql /database.bak \
                /config.php /config.php.bak /configuration.php /config.inc.php \
                /wp-config.php /wp-config.php.bak /wp-config.php.swp \
                /phpinfo.php /info.php /test.php /phpunit.php \
                /.htaccess /.htpasswd /.svn/entries /.svn/wc.db \
                /.DS_Store /Thumbs.db \
                /robots.txt /sitemap.xml /humans.txt /security.txt /.well-known/security.txt \
                /crossdomain.xml /clientaccesspolicy.xml \
                /swagger/v1/swagger.json /swagger.json /openapi.json \
                /api/swagger.json /v1/swagger.json /v2/api-docs /api-docs.json \
                /elmah.axd /trace.axd /ScriptResource.axd /WebResource.axd \
                /admin /administrator /adminer.php /admin.php \
                /server-status /server-info /status \
                /actuator /actuator/env /actuator/heapdump /actuator/health \
                /actuator/mappings /actuator/configprops \
                /metrics /prometheus /jmx-console /web-console \
                /_profiler /_debugbar /_wdt \
                /console /h2-console \
                /api/v1/config /api/config \
                /package.json /composer.json /Gemfile /yarn.lock /package-lock.json \
                /.npmrc /.yarnrc /.netrc \
                /.docker/config.json /docker-compose.yml /docker-compose.yaml \
                /Dockerfile /.dockerignore \
                /.aws/credentials /.ssh/id_rsa /.ssh/authorized_keys \
                /firebase.json /.firebaserc \
                /CHANGELOG /CHANGELOG.md /CHANGELOG.txt /README.md \
                /LICENSE /version.txt /VERSION; do
                echo "${root_url}${path}"
            done

            if ! [[ "$host" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
                for ext in zip tar.gz sql bak tar 7z; do
                    echo "${root_url}/${host}.${ext}"
                    echo "${root_url}/${first_label}.${ext}"
                    [[ -n "$domain_stem" && "$domain_stem" != "$host" ]] && \
                        echo "${root_url}/${domain_stem}.${ext}"
                done
            fi
        done < "$live_urls" | sort -u > "$candidates"

        local cand_count
        cand_count=$(wc -l < "$candidates" 2>/dev/null || echo 0)
        info "Backup probe candidates: $cand_count"

        if [[ "$cand_count" -gt 0 && "$DRY_RUN" != true ]]; then
            : > "$baseline_file"

            info "[Active] Building per-host baselines (parallel, $PROBE_PARALLEL workers) ..."
            awk -F/ '{print $1"//"$3}' "$live_urls" | sort -u \
            | xargs -P "$PROBE_PARALLEL" -I{} bash -c '_baseline_host "$@"' _ {} \
            > "$baseline_file"
            ok "Baselines collected: $(wc -l < "$baseline_file") hosts"

            info "[Active] Probing $cand_count candidates (parallel, $PROBE_PARALLEL workers) ..."
            local probe_raw="$active_dir/probe_raw.txt"
            xargs -a "$candidates" -P "$PROBE_PARALLEL" -I{} bash -c '_probe_url "$@"' _ {} \
            > "$probe_raw"

            local line http_code size_hit cand root_url baseline size_notfound size_variance diff threshold
            while IFS= read -r line; do
                http_code=$(echo "$line" | awk '{print $1}')
                size_hit=$(echo "$line" | awk '{print $2}')
                cand=$(echo "$line" | awk '{print $3}')
                [[ -z "$cand" ]] && continue

                if [[ "$http_code" =~ ^(200|206|401|403)$ ]]; then
                    root_url=$(echo "$cand" | sed -E 's|^([a-zA-Z]+://[^/]+).*|\1|')
                    baseline=$(grep "^${root_url} " "$baseline_file" 2>/dev/null | head -1)
                    size_notfound=0
                    size_variance=0
                    if [[ -n "$baseline" ]]; then
                        size_notfound=$(echo "$baseline" | grep -oP 'notfound=\K[0-9]+' || echo 0)
                        size_variance=$(echo "$baseline" | grep -oP 'variance=\K[0-9]+' || echo 0)
                    fi
                    threshold=50
                    [[ $((size_variance * 2)) -gt 50 ]] && threshold=$((size_variance * 2))

                    diff=$(( size_hit - size_notfound ))
                    [[ $diff -lt 0 ]] && diff=$(( -diff ))
                    if [[ "$diff" -lt "$threshold" && "$size_notfound" -gt 0 ]]; then
                        verb "FALSE_POS [$http_code] size=${size_hit} ~= 404=${size_notfound} (var=${size_variance}): $cand"
                        continue
                    fi
                    echo "[$http_code] size=${size_hit}b 404baseline=${size_notfound}b var=${size_variance}b $cand" \
                    >> "$active_dir/backup_hits.txt"
                    echo "$cand size=${size_hit} code=${http_code}" >> "$sized_hits"
                fi
            done < "$probe_raw"

            rm -f "$probe_raw"

            grep '\.git/config' "$active_dir/backup_hits.txt" 2>/dev/null \
            | grep -oP 'https?://\S+' > "$active_dir/git_candidates.txt" || true
            if [[ -s "$active_dir/git_candidates.txt" && -x "$HTTPX" ]]; then
                local -a httpx_git=(
                    -l "$active_dir/git_candidates.txt"
                    -mc 200 -ms '[core]' -ztls -fr
                    -t 20 -rl 30 -timeout 10 -nc -silent
                    -o "$active_dir/git_confirmed.txt"
                )
                [[ ${#AUTH_ARGS_HTTPX[@]} -gt 0 ]] && httpx_git+=("${AUTH_ARGS_HTTPX[@]}")
                TIMEOUT=300 run_cmd "httpx git confirm" "$HTTPX" "${httpx_git[@]}"
            fi

            local hit_count git_count
            hit_count=$(wc -l < "$active_dir/backup_hits.txt" 2>/dev/null || echo 0)
            git_count=$(wc -l < "$active_dir/git_confirmed.txt" 2>/dev/null || echo 0)
            [[ "$hit_count" -gt 0 ]] && warn "Backup probes: $hit_count hits (size-validated)"
            [[ "$git_count" -gt 0 ]] && warn "Git configs confirmed: $git_count"
        fi
        state_mark "active.backup"
    fi

    # 3.3 Lightweight endpoint discovery (replaces katana)
    touch "$active_dir/endpoints_discovered.txt" "$active_dir/js_files.txt" \
          "$active_dir/zip_files.txt" "$active_dir/api_endpoints.txt" \
          "$active_dir/js_files_httpx.txt" "$active_dir/js_files_curl.txt"

    # 3.3a Same-origin link scrape
    touch "$active_dir/endpoints_httpx.txt" "$active_dir/endpoints_headers.txt"
    if [[ "$NO_CRAWL" != true && -s "$live_urls" ]] && ! state_check "active.endpoint_extract"; then
        info "[Active] Same-origin link scrape (single-level) ..."
        local url tmp_html origin
        local -a curl_auth_link_args=("${AUTH_ARGS_CURL[@]}")

        while IFS= read -r url; do
            [[ -z "$url" ]] && continue
            origin=$(echo "$url" | grep -oP '^https?://[^/]+')
            [[ -z "$origin" ]] && continue
            tmp_html="$active_dir/.tmp_link_$(echo "$url" | md5sum | cut -c1-8).html"
            curl -sk --max-time 15 \
                -A 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' \
                "${curl_auth_link_args[@]}" \
                "$url" -o "$tmp_html" 2>/dev/null || continue
            [[ ! -s "$tmp_html" ]] && { rm -f "$tmp_html"; continue; }

            grep -oiP '<a[^>]*href\s*=\s*["\x27]\K[^"\x27]+' "$tmp_html" 2>/dev/null | \
            while IFS= read -r href; do
                [[ -z "$href" ]] && continue
                [[ "$href" =~ ^(mailto|tel|javascript):|^# ]] && continue
                local abs
                abs=$(resolve_url "$url" "$href")
                [[ "$abs" == "${origin}"* ]] && echo "$abs"
            done >> "$active_dir/endpoints_httpx.txt"

            rm -f "$tmp_html"
        done < "$live_urls"

        sort -u -o "$active_dir/endpoints_httpx.txt" "$active_dir/endpoints_httpx.txt" 2>/dev/null || true

        grep -iE '\.js($|\?)' "$active_dir/endpoints_httpx.txt" 2>/dev/null \
        > "$active_dir/js_files_httpx.txt" || true

        grep -iE '\.zip($|\?)' "$active_dir/endpoints_httpx.txt" 2>/dev/null \
        > "$active_dir/zip_files.txt" || true

        grep -iE 'api|graphql|rest|/v[0-9]+|internal|swagger|openapi' \
            "$active_dir/endpoints_httpx.txt" 2>/dev/null \
        > "$active_dir/api_endpoints.txt" || true

        ok "Same-origin links discovered: $(wc -l < "$active_dir/endpoints_httpx.txt" 2>/dev/null || echo 0)"
        state_mark "active.endpoint_extract"
    elif [[ "$NO_CRAWL" == true ]]; then
        info "[Active] NO_CRAWL -- skipping same-origin link scrape"
        state_mark "active.endpoint_extract"
    fi

    # 3.3b Archive URL endpoint expansion
    if [[ "$NO_ARCHIVE" != true && -s "$OUTDIR/passive/archive_urls.txt" ]] && ! state_check "active.archive_endpoints"; then
        info "[Active] Expanding endpoints from archive URLs ..."
        local archive_count
        archive_count=$(wc -l < "$OUTDIR/passive/archive_urls.txt" 2>/dev/null || echo 0)

        if [[ "$archive_count" -gt 0 ]]; then
            grep -oP 'https?://[^?&]+' "$OUTDIR/passive/archive_urls.txt" 2>/dev/null \
            | sort -u > "$active_dir/archive_endpoints.txt" || true

            grep -iE '\.js($|\?)' "$OUTDIR/passive/archive_urls.txt" 2>/dev/null \
            >> "$active_dir/js_files_httpx.txt" || true

            grep -iE 'api|graphql|rest|/v[0-9]+|internal|swagger|openapi|/wp-json/' \
                "$OUTDIR/passive/archive_urls.txt" 2>/dev/null \
            >> "$active_dir/api_endpoints.txt" || true

            ok "Archive-derived endpoints: $(wc -l < "$active_dir/archive_endpoints.txt" 2>/dev/null || echo 0)"
        fi
        state_mark "active.archive_endpoints"
    fi

    # 3.3c ffuf directory brute
    if [[ "$NO_DIRBRUTE" != true && -x "$FFUF" && -s "$live_urls" ]] && ! state_check "active.dirbrute"; then
        info "[Active] Directory discovery (ffuf) -- lightweight endpoint expansion ..."
        local dir_wl="$WORDLIST_DIR/Discovery/Web-Content/common.txt"
        [[ ! -f "$dir_wl" ]] && dir_wl="$WORDLIST_DIR/Discovery/Web-Content/raft-small-words.txt"
        [[ ! -f "$dir_wl" ]] && dir_wl="$WORDLIST_DIR/Discovery/Web-Content/directory-list-2.3-small.txt"

        if [[ -f "$dir_wl" ]]; then
            local brute_targets="$active_dir/dirbrute_targets.txt"
            local live_total dirbrute_max="${DIRBRUTE_MAX:-30}"
            live_total=$(wc -l < "$live_urls")
            if [[ "$live_total" -gt "$dirbrute_max" ]]; then
                info "Many live URLs ($live_total) -- dirbrute on first $dirbrute_max only (override with DIRBRUTE_MAX=<n>)"
                head -n "$dirbrute_max" "$live_urls" > "$brute_targets"
            else
                cp "$live_urls" "$brute_targets"
            fi

            local target
            while IFS= read -r target; do
                [[ -z "$target" ]] && continue
                local safe_target
                safe_target=$(echo "$target" | md5sum | cut -c1-12)
                info "[Active] ffuf dirbrute: $target"

                local -a ffuf_dir_args=(
                    -w "$dir_wl" -u "${target}/FUZZ"
                    -t "$FFUF_THREADS" -rate "$FFUF_RATE"
                    -mc 200,301,302,401,403,405,500
                    -timeout 10 -s
                    -o "$active_dir/dirbrute_${safe_target}.json"
                    -maxtime 120
                )
                [[ ${#AUTH_ARGS_FFUF[@]} -gt 0 ]] && ffuf_dir_args+=("${AUTH_ARGS_FFUF[@]}")
                TIMEOUT=180 run_cmd "ffuf dirbrute ${target}" "$FFUF" "${ffuf_dir_args[@]}"
            done < "$brute_targets"

            local f
            for f in "$active_dir"/dirbrute_*.json; do
                [[ -f "$f" ]] || continue
                "$JQ" -r '.results[]? | .url' "$f" 2>/dev/null
            done | sort -u > "$active_dir/endpoints_ffuf.txt" 2>/dev/null || true

            grep -iE '\.js($|\?)' "$active_dir/endpoints_ffuf.txt" 2>/dev/null \
            >> "$active_dir/js_files_httpx.txt" || true
            grep -iE 'api|graphql|rest|/v[0-9]+|internal|swagger|openapi' \
                "$active_dir/endpoints_ffuf.txt" 2>/dev/null \
            >> "$active_dir/api_endpoints.txt" || true

            ok "ffuf endpoints: $(wc -l < "$active_dir/endpoints_ffuf.txt" 2>/dev/null || echo 0)"
        else
            warn "[Active] No directory wordlist found -- skipping dirbrute"
        fi
        state_mark "active.dirbrute"
    fi

    cat "$active_dir/endpoints_httpx.txt" "$active_dir/endpoints_headers.txt" \
        "$active_dir/archive_endpoints.txt" "$active_dir/endpoints_ffuf.txt" \
        2>/dev/null | awk '!seen[$0]++' | sort -u \
        > "$active_dir/endpoints_discovered.txt" || true

    ok "Total discovered endpoints: $(wc -l < "$active_dir/endpoints_discovered.txt" 2>/dev/null || echo 0)"

    # 3.4 Curl JS extraction
    if [[ "$NO_JS_CURL" != true && -s "$live_urls" ]] && ! state_check "active.js_curl"; then
        info "[Active] Extracting JS references from HTML source (curl) ..."
        local url tmp_html count=0
        local -a curl_auth_args=("${AUTH_ARGS_CURL[@]}")

        while IFS= read -r url; do
            [[ -z "$url" ]] && continue
            ((count++))
            [[ "$count" -gt "$JS_CURL_MAX" ]] && { info "JS curl limit ($JS_CURL_MAX) reached"; break; }

            tmp_html="$active_dir/.tmp_js_$(echo "$url" | md5sum | cut -c1-8).html"
            curl -sk --max-time 15 \
                -A 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' \
                "${curl_auth_args[@]}" \
                "$url" -o "$tmp_html" 2>/dev/null || continue
            [[ ! -s "$tmp_html" ]] && { rm -f "$tmp_html"; continue; }

            grep -oiP '<script[^>]*src\s*=\s*["\x27]\K[^"\x27]+' "$tmp_html" 2>/dev/null | \
            while IFS= read -r src; do
                [[ -z "$src" ]] && continue
                local abs
                abs=$(resolve_url "$url" "$src")
                [[ "$abs" =~ \.js([?#].*)?$ ]] && echo "$abs"
            done >> "$active_dir/js_files_curl.txt"

            rm -f "$tmp_html"
        done < "$live_urls"

        sort -u -o "$active_dir/js_files_curl.txt" "$active_dir/js_files_curl.txt" 2>/dev/null || true
        ok "JS extracted via curl: $(wc -l < "$active_dir/js_files_curl.txt" 2>/dev/null || echo 0)"
        state_mark "active.js_curl"
    fi

    cat "$active_dir/js_files_httpx.txt" "$active_dir/js_files_curl.txt" 2>/dev/null \
    | sort -u > "$active_dir/js_files.txt"
    info "Total JS files: $(wc -l < "$active_dir/js_files.txt" 2>/dev/null || echo 0)"

    # 3.5 CORS
    touch "$active_dir/cors_findings.txt"
    if [[ "$NO_CORS" != true && -s "$live_urls" && -x "$HTTPX" && -x "$JQ" ]] && ! state_check "active.cors"; then
        info "[Active] CORS header check ..."
        local -a httpx_cors=(
            -l "$live_urls" -mc 200
            -ztls -irh -silent -j
            -o "$active_dir/cors_check.jsonl"
        )
        [[ ${#AUTH_ARGS_HTTPX[@]} -gt 0 ]] && httpx_cors+=("${AUTH_ARGS_HTTPX[@]}")
        TIMEOUT=600 run_cmd "httpx CORS" "$HTTPX" "${httpx_cors[@]}"

        "$JQ" -r '
            select(.headers != null) |
            select(
                .headers["access-control-allow-origin"] != null or
                .headers["access-control-allow-credentials"] != null
            ) |
            "\(.url)  [ACAO: \(.headers["access-control-allow-origin"] // "-")]  [ACAC: \(.headers["access-control-allow-credentials"] // "-")]"
        ' "$active_dir/cors_check.jsonl" 2>/dev/null \
        > "$active_dir/cors_findings.txt" || true
        local cors_count
        cors_count=$(wc -l < "$active_dir/cors_findings.txt" 2>/dev/null || echo 0)
        [[ "$cors_count" -gt 0 ]] && warn "CORS headers found on $cors_count endpoints"
        state_mark "active.cors"
    fi

    # 3.6 WhatWeb
    touch "$active_dir/whatweb_summary.txt" "$active_dir/whatweb_tech.txt"
    if [[ "$NO_WHATWEB" != true && -x "$WHATWEB" && -s "$live_urls" ]] && ! state_check "active.whatweb"; then
        info "[Active] WhatWeb fingerprinting ..."
        TIMEOUT=1800 run_cmd "whatweb" "$WHATWEB" \
            --input-file="$live_urls" \
            --log-brief="$active_dir/whatweb_brief.txt" \
            --log-json="$active_dir/whatweb.json" \
            --no-errors -q 2>>"$LOG_FILE" || true

        if [[ -x "$JQ" && -s "$active_dir/whatweb.json" ]]; then
            "$JQ" -r 'select(.plugins != null) | .plugins | keys[]' \
                "$active_dir/whatweb.json" 2>/dev/null \
                | tr '[:upper:]' '[:lower:]' \
                | grep -vE '^(http|httpserver|x-frame-options|x-content-type|x-xss-protection|via-proxy|country|ip|uncommonheaders|cookies|email|html5|script|title|meta-author|meta-refresh-redirect)$' \
                | sort -u > "$active_dir/whatweb_tech.txt" || true
        elif [[ -s "$active_dir/whatweb_brief.txt" ]]; then
            grep -oP '\] \K[^[]+\[' "$active_dir/whatweb_brief.txt" 2>/dev/null \
                | sed 's/\[$//' | tr ',' '\n' \
                | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' \
                | tr '[:upper:]' '[:lower:]' \
                | grep -E '^[a-z][a-z0-9_./ -]+' \
                | sort -u > "$active_dir/whatweb_tech.txt" || true
        fi
        [[ -s "$active_dir/whatweb_brief.txt" ]] && cp "$active_dir/whatweb_brief.txt" "$active_dir/whatweb_summary.txt"
        ok "WhatWeb fingerprints: $(wc -l < "$active_dir/whatweb_summary.txt" 2>/dev/null || echo 0)"
        ok "WhatWeb tech (cleaned): $(wc -l < "$active_dir/whatweb_tech.txt" 2>/dev/null || echo 0)"
        state_mark "active.whatweb"
    fi

    # 3.7 Favicon
    if [[ -x "$JQ" && -s "$disc_dir/httpx_live.jsonl" ]]; then
        "$JQ" -r 'select(.favicon_mmh3!=null) | "\(.favicon_mmh3) \(.url)"' \
            "$disc_dir/httpx_live.jsonl" 2>/dev/null \
            | sort > "$active_dir/favicon_hashes.txt" || true
    fi

    # 3.8 Takeover
    touch "$active_dir/takeover_candidates.txt"
    if [[ "$NO_TAKEOVER" != true && -s "$live_urls" ]] && ! state_check "active.takeover"; then
        info "[Active] Subdomain takeover detection ..."

        if [[ -x "$JQ" && -s "$disc_dir/dns_records.jsonl" ]]; then
            "$JQ" -r 'select(.cname!=null) | "\(.host),\(.cname[]?)"' \
                "$disc_dir/dns_records.jsonl" 2>/dev/null \
                > "$active_dir/cnames.csv" 2>/dev/null || true
        fi

        if [[ -x "$SUBZY" ]]; then
            TIMEOUT=600 run_cmd "subzy takeover" "$SUBZY" run \
                --targets "$disc_dir/subdomains.txt" \
                --hide_fails --output "$active_dir/subzy_results.txt" 2>/dev/null || true
        fi

        if [[ -x "$SUBJACK" ]]; then
            TIMEOUT=600 run_cmd "subjack takeover" "$SUBJACK" \
                -w "$disc_dir/subdomains.txt" -t 50 -timeout 30 -ssl \
                -o "$active_dir/subjack_results.txt" 2>/dev/null || true
        fi

        local takeover_patterns=(
            "There isn't a GitHub Pages site here"
            "Repository not found"
            "There's nothing here yet"
            "Sorry, this shop is currently unavailable"
            "Project doesnt exist"
            "Unrecognized domain"
            "NoSuchBucket"
            "The specified bucket does not exist"
            "Heroku | No such app"
            "is not a registered InCloud Office"
            "Fastly error: unknown domain"
            "Do you want to register"
            "Help Center Closed"
            "Domain uses DO name servers with no records"
            "No settings were found for this company"
        )

        TAKEOVER_PATTERNS=$(printf '%s\n' "${takeover_patterns[@]}")
        export TAKEOVER_PATTERNS
        info "[Active] Takeover body fingerprinting (parallel, $PROBE_PARALLEL workers) ..."
        xargs -a "$live_urls" -P "$PROBE_PARALLEL" -I{} bash -c '_takeover_check "$@"' _ {} \
            >> "$active_dir/takeover_candidates.txt" 2>>"$LOG_FILE"
        sort -u -o "$active_dir/takeover_candidates.txt" "$active_dir/takeover_candidates.txt" 2>/dev/null || true
        while IFS= read -r line; do
            warn "Takeover candidate: $line"
        done < "$active_dir/takeover_candidates.txt"

        if [[ -x "$NUCLEI" && "$NO_NUCLEI" != true ]]; then
            TIMEOUT=$NUCLEI_TIMEOUT run_cmd "nuclei takeovers" "$NUCLEI" \
                -l "$live_urls" \
                -t takeovers/ \
                -severity high,critical \
                -silent -no-interactsh \
                -o "$active_dir/nuclei_takeovers.txt"
        fi

        local takeover_count
        takeover_count=$(wc -l < "$active_dir/takeover_candidates.txt" 2>/dev/null || echo 0)
        [[ "$takeover_count" -gt 0 ]] && warn "Takeover candidates: $takeover_count"
        state_mark "active.takeover"
    fi

    # 3.9 Admin panel probe
    touch "$active_dir/admin_panels_found.txt"
    if [[ "$NO_ADMIN_PROBE" != true && -s "$live_urls" && -x "$HTTPX" ]] && ! state_check "active.admin"; then
        info "[Active] Admin panel discovery (baseline-aware) ..."
        local probe_list="$active_dir/admin_probes.txt"
        local admin_baseline="$active_dir/admin_baseline.txt"
        local admin_raw="$active_dir/admin_raw.jsonl"
        : > "$probe_list"

        local admin_paths=(
            /admin /administrator /admin.php /admin/login /admin/index.php
            /wp-admin /wp-login.php /administrator/index.php
            /manager/html /manager/status /host-manager/html
            /admin.aspx /Admin/login.aspx /admin/login.aspx
            /Default.aspx /Account/Login /Login.aspx
            /ReportServer /Reports
            /actuator /actuator/health /actuator/env /actuator/heapdump
            /actuator/mappings /actuator/configprops /actuator/beans
            /jolokia /jolokia/list /hawtio
            /console /jmx-console /web-console /invoker/JMXInvokerServlet
            /grafana /prometheus /kibana /elasticsearch /_plugin/kibana
            /jenkins /jenkins/login /jenkins/script
            /sonar /sonarqube /nexus /nexus/login /artifactory
            /minio /minio/login
            /adminer /adminer.php /phpmyadmin /pma /mysql
            /webdav /WebDAV
            /portal /portal.htm /portalcheck
            /dana-na/auth/url_default/welcome.cgi
            /remote/login /sslvpn /vpn /vpn/index.html
            /+CSCOE+/logon.html
            /backend /control-panel /cp /cpanel
            /umbraco /typo3 /typo3/install
            /drupal /joomla /sites/default
            /swagger /swagger-ui /swagger-ui.html /api-docs /api/v1 /v1 /v2 /graphql /graphiql
            /openapi.json /swagger.json /api-docs.json /v2/api-docs
            /owa /ecp /aspnet_client /Exchange /OWA
            /_layouts /SitePages
            /Autodiscover/Autodiscover.xml
            /CFIDE/administrator /CFIDE/adminapi
            /confluence /jira /secure/Dashboard.jspa /login.jsp
            /users/sign_in /api/v4 /-/health
            /Citrix/ /logon/LogonPoint/tmindex.html
        )

        while IFS= read -r url; do
            for path in "${admin_paths[@]}"; do
                echo "${url}${path}" >> "$probe_list"
            done
        done < "$live_urls"
        sort -u -o "$probe_list" "$probe_list"

        info "[Active] Building admin-probe baselines ..."
        : > "$admin_baseline"
        local -a curl_auth_args=("${AUTH_ARGS_CURL[@]}")

        local host_url rand_path code_status code_size code_loc
        while IFS= read -r host_url; do
            [[ -z "$host_url" ]] && continue
            rand_path="/zzz-doesnotexist-$(openssl rand -hex 6 2>/dev/null || echo "$RANDOM$RANDOM")"
            read -r code_status code_size code_loc < <(curl -sk --max-time 8 \
                "${curl_auth_args[@]}" \
                -o /dev/null \
                -w '%{http_code} %{size_download} %{redirect_url}\n' \
                "${host_url}${rand_path}" 2>/dev/null || echo "0 0 -")
            echo "${host_url} status=${code_status} size=${code_size} redirect=${code_loc:--}" >> "$admin_baseline"
        done < "$live_urls"
        ok "Admin probe baselines: $(wc -l < "$admin_baseline") hosts"

        local -a httpx_admin=(
            -l "$probe_list"
            -mc 200,201,401,403
            -t 100 -rl 200 -timeout 10 -silent -nc -j
            -title -sc -cl -ztls
            -o "$admin_raw"
        )
        [[ ${#AUTH_ARGS_HTTPX[@]} -gt 0 ]] && httpx_admin+=("${AUTH_ARGS_HTTPX[@]}")
        TIMEOUT=1800 run_cmd "httpx admin probe" "$HTTPX" "${httpx_admin[@]}"

        : > "$active_dir/admin_panels_found.txt"
        if [[ -s "$admin_raw" && -x "$JQ" ]]; then
            local probe_url probe_root probe_sc probe_cl probe_title baseline_sc baseline_cl size_diff line
            while IFS= read -r line; do
                probe_url=$(echo "$line" | "$JQ" -r '.url // empty' 2>/dev/null)
                probe_sc=$(echo "$line"  | "$JQ" -r '.status_code // 0' 2>/dev/null)
                probe_cl=$(echo "$line"  | "$JQ" -r '.content_length // 0' 2>/dev/null)
                probe_title=$(echo "$line" | "$JQ" -r '.title // ""' 2>/dev/null)
                [[ -z "$probe_url" || "$probe_sc" == "0" ]] && continue

                if [[ "$probe_sc" == "401" || "$probe_sc" == "403" ]]; then
                    echo "[${probe_sc}] cl=${probe_cl} title=\"${probe_title}\" ${probe_url}" \
                    >> "$active_dir/admin_panels_found.txt"
                    continue
                fi

                probe_root=$(echo "$probe_url" | sed -E 's|^([a-zA-Z]+://[^/]+).*|\1|')
                baseline_sc=$(grep "^${probe_root} " "$admin_baseline" 2>/dev/null | head -1 | grep -oP 'status=\K[0-9]+' || echo 0)
                baseline_cl=$(grep "^${probe_root} " "$admin_baseline" 2>/dev/null | head -1 | grep -oP 'size=\K[0-9]+' || echo 0)

                if [[ "$probe_sc" == "$baseline_sc" ]]; then
                    size_diff=$(( probe_cl - baseline_cl ))
                    [[ $size_diff -lt 0 ]] && size_diff=$(( -size_diff ))
                    if [[ $size_diff -lt 50 ]]; then
                        verb "FALSE_POS admin probe matches baseline: $probe_url"
                        continue
                    fi
                fi

                echo "[${probe_sc}] cl=${probe_cl} title=\"${probe_title}\" ${probe_url}" \
                >> "$active_dir/admin_panels_found.txt"
            done < "$admin_raw"
        fi

        local admin_count
        admin_count=$(wc -l < "$active_dir/admin_panels_found.txt" 2>/dev/null || echo 0)
        if [[ "$admin_count" -gt 0 ]]; then
            warn "Admin panels found (post-filter): $admin_count"
        else
            info "No admin panels survived baseline filter"
        fi
        state_mark "active.admin"
    fi

    state_mark "active"
    ok "Phase ACTIVE complete"
}

# =============================================================================
# Tech profile cleaning & nuclei tag mapping
# =============================================================================
clean_tech_profile() {
    local in_file="$1" out_file="$2"
    if [[ ! -s "$in_file" ]]; then
        : > "$out_file"
        return
    fi
    cat "$in_file" \
    | grep -vE '^[[:space:]]*$' \
    | grep -vE '^([0-9]{1,3}\.){3}[0-9]{1,3}([:/][0-9]+)?$' \
    | grep -vE '^[0-9]+(\.[0-9]+)*$' \
    | grep -vE '@' \
    | grep -vE '^https?://' \
    | grep -vE '^(sameorigin|deny|nosniff|mode=block|max-age|public|private|no-cache|no-store)' \
    | grep -vE '^x-(content|frame|xss|request|powered|forwarded)' \
    | grep -vE '^(200|201|301|302|400|401|403|404|405|500|502|503) ' \
    | grep -vE '^_[a-z]+_session$' \
    | grep -vE '^cookie' \
    | grep -vE 'password[a-z_]*$' \
    | grep -vE '^\.::' \
    | grep -E '^[a-z][a-z0-9_./ -]+' \
    | sort -u > "$out_file"
}

map_tech_to_nuclei_tags() {
    local tech_file="$1"
    local tag_set="cve,exposure,auth,default-logins,misconfig,token,config"

    if [[ -s "$tech_file" ]]; then
        local raw_tech tech
        while IFS= read -r raw_tech; do
            [[ -z "$raw_tech" ]] && continue
            tech=$(echo "$raw_tech" \
                | sed -E 's|[:/].*$||' \
                | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' \
                | tr '[:upper:]' '[:lower:]')
            [[ -z "$tech" ]] && continue
            case "$tech" in
                httpserver|http-server|web-server) ;;
                *nginx*)                    tag_set+=",nginx" ;;
                *apache*httpd*|*apache/*|apache)  tag_set+=",apache,apache-httpd" ;;
                *asp*|*aspnet*|*iis*|microsoft-iis*)  tag_set+=",iis,aspnet,asp,microsoft" ;;
                *wordpress*|*wp-*)          tag_set+=",wordpress,wp-plugin,wp-theme" ;;
                *spring*|*actuator*)        tag_set+=",spring,spring-boot,java,actuator" ;;
                *jhipster*)                 tag_set+=",jhipster,spring-boot,java" ;;
                *tomcat*|*coyote*)          tag_set+=",tomcat,java,apache-tomcat" ;;
                *jboss*|*wildfly*)          tag_set+=",jboss,wildfly,java" ;;
                *weblogic*)                 tag_set+=",weblogic,oracle,java" ;;
                *websphere*)                tag_set+=",websphere,ibm,java" ;;
                *zk*framework*|*zkframework*|zk)  tag_set+=",zk,zkoss,java" ;;
                *java*)                     tag_set+=",java" ;;
                *php*)                      tag_set+=",php" ;;
                *phusion*passenger*|*passenger*)  tag_set+=",passenger,ruby,rails" ;;
                *rails*|*ruby*)             tag_set+=",rails,ruby" ;;
                *elasticsearch*|*elastic*)  tag_set+=",elasticsearch,elastic" ;;
                *kibana*)                   tag_set+=",kibana,elastic" ;;
                *logstash*)                 tag_set+=",logstash,elastic" ;;
                *drupal*)                   tag_set+=",drupal" ;;
                *joomla*)                   tag_set+=",joomla" ;;
                *django*)                   tag_set+=",django,python" ;;
                *flask*)                    tag_set+=",flask,python" ;;
                *laravel*)                  tag_set+=",laravel,php" ;;
                *symfony*)                  tag_set+=",symfony,php" ;;
                *codeigniter*)              tag_set+=",codeigniter,php" ;;
                *jenkins*)                  tag_set+=",jenkins,ci-cd" ;;
                *gitlab*)                   tag_set+=",gitlab,git" ;;
                *gitea*|*gogs*)             tag_set+=",gitea,gogs,git" ;;
                *swagger*|*openapi*)        tag_set+=",swagger,openapi,api" ;;
                *graphql*)                  tag_set+=",graphql,api" ;;
                *devexpress*)               tag_set+=",devexpress,aspnet,iis" ;;
                *signalr*)                  tag_set+=",signalr,aspnet,iis" ;;
                *nodejs*|*node.js*|*node-*) tag_set+=",nodejs,node,javascript" ;;
                *express*)                  tag_set+=",express,nodejs" ;;
                *next.js*|*nextjs*)         tag_set+=",nextjs,react,nodejs" ;;
                *redis*)                    tag_set+=",redis" ;;
                *mongodb*|*mongo*)          tag_set+=",mongodb,nosql" ;;
                *mysql*|*mariadb*)          tag_set+=",mysql,mariadb" ;;
                *postgres*|*postgresql*)    tag_set+=",postgresql,postgres" ;;
                *mssql*|*sqlserver*)        tag_set+=",mssql,sqlserver,microsoft" ;;
                *oracle*)                   tag_set+=",oracle" ;;
                *jquery*)                   tag_set+=",jquery,javascript" ;;
                *bootstrap*)                tag_set+=",bootstrap" ;;
                *angular*)                  tag_set+=",angular,javascript" ;;
                *react*)                    tag_set+=",react,javascript" ;;
                *vue*)                      tag_set+=",vue,javascript" ;;
                *wso2*)                     tag_set+=",wso2" ;;
                *jira*|*confluence*|*bitbucket*|*atlassian*) tag_set+=",atlassian,jira,confluence" ;;
                *grafana*)                  tag_set+=",grafana" ;;
                *prometheus*)               tag_set+=",prometheus" ;;
                *keycloak*)                 tag_set+=",keycloak,oauth,sso" ;;
                *minio*)                    tag_set+=",minio,s3" ;;
                *citrix*|*netscaler*|*storefront*)  tag_set+=",citrix,netscaler" ;;
                *fortinet*|*fortigate*|*fortios*)   tag_set+=",fortinet,fortigate" ;;
                *pulse*secure*|*ivanti*)    tag_set+=",ivanti,pulse-secure" ;;
                *vmware*|*vcenter*|*vsphere*) tag_set+=",vmware,vcenter" ;;
                *exchange*|*outlook*|*owa*) tag_set+=",exchange,owa,microsoft" ;;
                *sharepoint*)               tag_set+=",sharepoint,microsoft" ;;
                *papercut*)                 tag_set+=",papercut" ;;
                *glpi*)                     tag_set+=",glpi" ;;
                *sonarqube*)                tag_set+=",sonarqube" ;;
                *coldfusion*|*cfide*)       tag_set+=",coldfusion,adobe" ;;
                *moodle*)                   tag_set+=",moodle" ;;
                *nextcloud*|*owncloud*)     tag_set+=",nextcloud,owncloud" ;;
                *rabbitmq*)                 tag_set+=",rabbitmq" ;;
                *docker*|*container-registry*) tag_set+=",docker" ;;
                *cloudflare*)               tag_set+=",cloudflare" ;;
                *font-awesome*|*fontawesome*) ;;
                debian|ubuntu|centos|rhel|alpine|windows*) ;;
                *) ;;
            esac
        done < "$tech_file"
    fi
    echo "$tag_set" | tr ',' '\n' | sort -u | grep -v '^$' | paste -sd ','
}

# =============================================================================
# PHASE 4: DEEP ANALYSIS
# =============================================================================
phase_deep() {
    local disc_dir="$OUTDIR/discovery"
    local active_dir="$OUTDIR/active"
    local deep_dir="$OUTDIR/deep"
    local live_urls="$disc_dir/live_urls.txt"

    state_check "deep" && { info "Phase DEEP already done -- skipping"; return 0; }
    log "=== PHASE 4: DEEP ANALYSIS ==="

    # 4.1 Param discovery
    touch "$deep_dir/urls_with_params.txt"
    if [[ "$NO_PARAM" != true && -s "$live_urls" ]] && ! state_check "deep.param"; then
        info "[Deep] Parameter discovery ..."
        local param_sources="$deep_dir/param_sources.txt"
        : > "$param_sources"
        [[ -s "$OUTDIR/passive/archive_urls.txt" ]] && \
            cat "$OUTDIR/passive/archive_urls.txt" >> "$param_sources"
        [[ -s "$active_dir/endpoints_discovered.txt" ]] && \
            cat "$active_dir/endpoints_discovered.txt" >> "$param_sources"
        sort -u -o "$param_sources" "$param_sources"

        if [[ -x "$UNFURL" && -s "$param_sources" && "$DRY_RUN" != true ]]; then
            "$UNFURL" -u keys < "$param_sources" \
                > "$deep_dir/params_unfurl.txt" 2>>"$LOG_FILE" || true
        fi
        grep '?' "$param_sources" 2>/dev/null | sort -u \
        > "$deep_dir/urls_with_params.txt" || true
        ok "URLs with parameters: $(wc -l < "$deep_dir/urls_with_params.txt" 2>/dev/null || echo 0)"
        state_mark "deep.param"
    fi

    # 4.2 JS analysis
    touch "$deep_dir/js_analysis.txt" "$deep_dir/js_secrets.txt" \
          "$deep_dir/js_endpoints.txt" "$deep_dir/sourcemaps_found.txt"
    if [[ "$NO_JS" != true && -s "$active_dir/js_files.txt" ]] && ! state_check "deep.js"; then
        info "[Deep] JS download + beautify + analysis ..."

        local js_raw_dir="$deep_dir/js_raw"
        local js_pretty_dir="$deep_dir/js_pretty"
        mkdir -p "$js_raw_dir" "$js_pretty_dir"

        local JSBEAUTIFY=""
        command -v js-beautify &>/dev/null && JSBEAUTIFY="js-beautify"
        command -v prettier    &>/dev/null && [[ -z "$JSBEAUTIFY" ]] && JSBEAUTIFY="prettier --parser babel"
        [[ -z "$JSBEAUTIFY" ]] && warn "[Deep] js-beautify/prettier not found -- analyzing minified JS"

        local -a curl_auth_args=("${AUTH_ARGS_CURL[@]}")

        local jsurl fname raw_f pretty_f
        while IFS= read -r jsurl; do
            [[ -z "$jsurl" ]] && continue
            fname=$(echo "$jsurl" | md5sum | cut -c1-12)_$(basename "$jsurl" | tr '?&=' '_' | cut -c1-40)
            raw_f="$js_raw_dir/${fname}"
            pretty_f="$js_pretty_dir/pretty_${fname}"

            if [[ "$DRY_RUN" != true ]]; then
                curl -sL --max-time 20 -k \
                    -A 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' \
                    "${curl_auth_args[@]}" \
                    "$jsurl" -o "$raw_f" 2>/dev/null || true
            fi

            [[ ! -s "$raw_f" ]] && continue

            local smap
            smap=$(grep -oP '//# sourceMappingURL=\K\S+' "$raw_f" | head -1)
            if [[ -n "$smap" ]]; then
                local smap_url
                if [[ "$smap" =~ ^https?:// ]]; then
                    smap_url="$smap"
                else
                    smap_url="${jsurl%/*}/${smap}"
                fi
                warn "Sourcemap found: $jsurl -> $smap_url"
                echo "$smap_url" >> "$deep_dir/sourcemaps_found.txt"
                curl -sL --max-time 20 -k "${curl_auth_args[@]}" "$smap_url" \
                    -o "$js_raw_dir/sourcemap_${fname}.map" 2>/dev/null || true
            fi

            if [[ -n "$JSBEAUTIFY" && "$DRY_RUN" != true ]]; then
                if [[ "$JSBEAUTIFY" == "js-beautify" ]]; then
                    js-beautify "$raw_f" > "$pretty_f" 2>/dev/null || cp "$raw_f" "$pretty_f"
                else
                    $JSBEAUTIFY "$raw_f" > "$pretty_f" 2>/dev/null || cp "$raw_f" "$pretty_f"
                fi
            else
                cp "$raw_f" "$pretty_f"
            fi

            local target_f="$pretty_f"

            grep -oP "(?<=[\"'])/[a-zA-Z0-9_/.-]{2,}(?=[\"'])" "$target_f" 2>/dev/null \
                | sort -u | while read -r ep; do echo "${jsurl} -> $ep"; done \
                >> "$deep_dir/js_analysis.txt"

            grep -oP "(?<=[\"'])(https?://[^\"']{4,})(?=[\"'])" "$target_f" 2>/dev/null \
                | sort -u >> "$deep_dir/js_endpoints.txt"

            grep -oP "(?<=[\"'])(api|/v[0-9]+|/api)[a-zA-Z0-9/_-]+(?=[\"'])" \
                "$target_f" 2>/dev/null | sort -u >> "$deep_dir/js_endpoints.txt"

            grep -oP '(?:api\w*Url|base[Uu]rl|endpoint|backendUrl|serviceUrl)\s*:\s*["\x27][^"\'']+' \
                "$target_f" 2>/dev/null | sort -u >> "$deep_dir/js_endpoints.txt"

            grep -oiP '(api[_-]?key|secret|token|auth|password|passwd|pwd|aws_access_key_id|private_key|client_secret|access_token|recaptcha\w*key)\s*[:=]\s*["\x27][^"\'']{6,}["\x27]' \
                "$target_f" 2>/dev/null >> "$deep_dir/js_secrets.txt"

            grep -oP 'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+' \
                "$target_f" 2>/dev/null | while read -r jwt; do
                echo "JWT_IN_JS url=$jsurl token=$jwt"
            done >> "$deep_dir/js_secrets.txt"

            grep -oP '(?<=["\x27 (])(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)[0-9.]{3,}(?=["\x27 )])' \
                "$target_f" 2>/dev/null | sort -u | while read -r ip; do
                echo "INTERNAL_IP url=$jsurl ip=$ip"
            done >> "$deep_dir/js_secrets.txt"

            grep -oiP '(Data Source|Server=|database=|uid=|pwd=|connection[Ss]tring)\s*=\s*[^;"\x27]{4,}' \
                "$target_f" 2>/dev/null >> "$deep_dir/js_secrets.txt"

            verb "Analyzed: $(basename "$jsurl")"
        done < "$active_dir/js_files.txt"

        sort -u -o "$deep_dir/js_analysis.txt"  "$deep_dir/js_analysis.txt"  2>/dev/null || true
        sort -u -o "$deep_dir/js_endpoints.txt" "$deep_dir/js_endpoints.txt" 2>/dev/null || true
        sort -u -o "$deep_dir/js_secrets.txt"   "$deep_dir/js_secrets.txt"   2>/dev/null || true

        if [[ -x "$GITLEAKS" && "$DRY_RUN" != true ]]; then
            "$GITLEAKS" detect --source "$js_pretty_dir" --no-git \
                --report-path "$deep_dir/gitleaks_js.json" --report-format json \
                2>>"$LOG_FILE" || true
        fi

        local secret_count ep_count sm_count
        secret_count=$(wc -l < "$deep_dir/js_secrets.txt"   2>/dev/null || echo 0)
        ep_count=$(wc -l     < "$deep_dir/js_endpoints.txt" 2>/dev/null || echo 0)
        sm_count=$(wc -l     < "$deep_dir/sourcemaps_found.txt" 2>/dev/null || echo 0)
        [[ "$secret_count" -gt 0 ]] && warn "$secret_count potential secrets found in JS"
        [[ "$sm_count" -gt 0 ]]     && warn "$sm_count sourcemaps found"
        ok "JS: $ep_count endpoints, $secret_count secrets | pretty -> $js_pretty_dir/"
        state_mark "deep.js"
    fi

    # 4.3 Tech profile
    local tech_file="$deep_dir/tech_profile.txt"
    local tech_file_raw="$deep_dir/tech_profile_raw.txt"
    : > "$tech_file_raw"

    if [[ -x "$JQ" && -s "$disc_dir/httpx_live.jsonl" ]]; then
        "$JQ" -r 'select(.tech!=null) | .tech[]' \
            "$disc_dir/httpx_live.jsonl" 2>/dev/null \
            | tr '[:upper:]' '[:lower:]' | sort -u >> "$tech_file_raw" || true
    fi
    if [[ -s "$active_dir/whatweb_tech.txt" ]]; then
        cat "$active_dir/whatweb_tech.txt" >> "$tech_file_raw"
    fi
    sort -u -o "$tech_file_raw" "$tech_file_raw" 2>/dev/null || true

    clean_tech_profile "$tech_file_raw" "$tech_file"

    if [[ -s "$tech_file" ]]; then
        info "[Deep] Tech detected: $(tr '\n' ',' < "$tech_file" | sed 's/,$//' | cut -c1-200)"
    else
        warn "[Deep] No tech detected -- nuclei will use base tags only"
    fi

    local tech_tags
    tech_tags=$(map_tech_to_nuclei_tags "$tech_file")
    if [[ -z "$tech_tags" || "$tech_tags" == "," ]]; then
        tech_tags="cve,exposure,auth,default-logins,misconfig,token,config"
        warn "[Deep] Tech tags empty -- falling back to base tag set"
    fi
    info "[Deep] Nuclei aggregate tags: $tech_tags"

    # -- Tunable nuclei concurrency/rate/severity for the web passes ----------
    local nweb_recon_conc="${NUCLEI_WEB_RECON_CONC:-10}"
    local nweb_recon_rate="${NUCLEI_WEB_RECON_RATE:-30}"
    local nweb_tech_conc="${NUCLEI_WEB_TECH_CONC:-5}"
    local nweb_tech_rate="${NUCLEI_WEB_TECH_RATE:-15}"

    local nweb_recon_severity="${NUCLEI_WEB_RECON_SEVERITY:-info,low,medium,high,critical}"
    local nweb_recon_etags="${NUCLEI_WEB_RECON_ETAGS:-fuzz,dos,osint}"
    local nweb_tech_severity="${NUCLEI_WEB_TECH_SEVERITY:-info,low,medium,high,critical}"
    local nweb_tech_etags="${NUCLEI_WEB_TECH_ETAGS:-fuzz,dos,osint}"

    # 4.4 Nuclei (web-facing findings)
    touch "$deep_dir/nuclei_recon.txt" "$deep_dir/nuclei_full.txt"
    if [[ "$NO_NUCLEI" != true && -x "$NUCLEI" && -s "$live_urls" ]] && ! state_check "deep.nuclei"; then

        info "[Deep] Nuclei recon scan (concurrency=$nweb_recon_conc rate=$nweb_recon_rate severity=$nweb_recon_severity etags=$nweb_recon_etags) ..."
        local -a nuc_recon_args=(
            -l "$live_urls"
            -tags exposure,config,tech,devops,token,api,misconfig,debug,backup,logs
            -severity "$nweb_recon_severity"
            -etags "$nweb_recon_etags"
            -concurrency "$nweb_recon_conc"
            -rl "$nweb_recon_rate"
            -timeout 15
            -retries 1
            -silent -no-interactsh
            -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            -o "$deep_dir/nuclei_recon.txt"
        )
        [[ ${#AUTH_ARGS_NUCLEI[@]} -gt 0 ]] && nuc_recon_args+=("${AUTH_ARGS_NUCLEI[@]}")
        TIMEOUT=$NUCLEI_TIMEOUT run_cmd "nuclei recon" "$NUCLEI" "${nuc_recon_args[@]}"

        local high_value="$deep_dir/high_value_urls.txt"
        local hv_limit="${HV_LIMIT:-500}"
        local hv_admin_cap="${HV_ADMIN_CAP:-30}"
        local hv_api_cap="${HV_API_CAP:-50}"
        {
            [[ -s "$active_dir/api_endpoints.txt" ]]    && head -n "$hv_api_cap" "$active_dir/api_endpoints.txt"
            [[ -s "$active_dir/vhost_discovered.txt" ]] && cat "$active_dir/vhost_discovered.txt"
            [[ -s "$active_dir/admin_panels_found.txt" ]] && \
                grep -oP 'https?://\S+' "$active_dir/admin_panels_found.txt" 2>/dev/null | head -n "$hv_admin_cap"
            cat "$live_urls"
        } | sort -u > "$high_value"

        local hv_count
        hv_count=$(wc -l < "$high_value" 2>/dev/null || echo 0)

        if [[ "$hv_count" -gt 0 ]]; then
            if [[ "$hv_count" -gt "$hv_limit" ]]; then
                warn "High-value list ($hv_count) over limit ($hv_limit) -- truncating. Override with HV_LIMIT=<n>."
                head -n "$hv_limit" "$high_value" > "${high_value}.trunc"
                mv "${high_value}.trunc" "$high_value"
                hv_count="$hv_limit"
            fi

            info "[Deep] Nuclei aggregate-tech scan ($hv_count URLs, concurrency=$nweb_tech_conc rate=$nweb_tech_rate severity=$nweb_tech_severity etags=$nweb_tech_etags)"
            local -a nuc_tech_args=(
                -l "$high_value"
                -tags "$tech_tags"
                -severity "$nweb_tech_severity"
                -etags "$nweb_tech_etags"
                -concurrency "$nweb_tech_conc"
                -rl "$nweb_tech_rate"
                -timeout 20
                -retries 1
                -silent -no-interactsh
                -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                -o "$deep_dir/nuclei_full.txt"
            )
            [[ ${#AUTH_ARGS_NUCLEI[@]} -gt 0 ]] && nuc_tech_args+=("${AUTH_ARGS_NUCLEI[@]}")
            TIMEOUT=$NUCLEI_TIMEOUT run_cmd "nuclei tech" "$NUCLEI" "${nuc_tech_args[@]}"
        else
            warn "High-value list is empty -- skipping aggregate nuclei"
        fi
        state_mark "deep.nuclei"
    fi

    # 4.4b Per-URL targeted nuclei
    local per_url_nuclei_max="${PER_URL_NUCLEI_MAX:-50}"
    if [[ "$NO_PER_URL_NUCLEI" != true && "$NO_NUCLEI" != true \
          && -x "$NUCLEI" && -x "$JQ" && -s "$disc_dir/httpx_live.jsonl" ]] \
          && ! state_check "deep.nuclei_per_url"; then
        info "[Deep] Per-URL targeted nuclei scans (max $per_url_nuclei_max) ..."
        local per_url_dir="$deep_dir/nuclei_per_url"
        mkdir -p "$per_url_dir"

        "$JQ" -r 'select(.tech!=null and .url!=null) |
            [.url, (.tech | join(","))] | @tsv' \
            "$disc_dir/httpx_live.jsonl" 2>/dev/null \
            > "$deep_dir/url_tech_map.tsv"

        local max_per_url="$per_url_nuclei_max" scanned=0
        local url techs url_tags t safe_url t_clean
        while IFS=$'\t' read -r url techs; do
            [[ -z "$url" || -z "$techs" ]] && continue
            ((scanned++))
            [[ "$scanned" -gt "$max_per_url" ]] && { info "Per-URL limit ($max_per_url) reached -- override with PER_URL_NUCLEI_MAX"; break; }

            url_tags="cve,exposure"
            for t in $(echo "$techs" | tr ',' '\n' | tr '[:upper:]' '[:lower:]'); do
                t_clean=$(echo "$t" | sed -E 's|[:/].*$||')
                case "$t_clean" in
                    httpserver|http-server|web-server) ;;
                    *nginx*)      url_tags+=",nginx" ;;
                    *apache*)     url_tags+=",apache" ;;
                    *iis*|*asp*)  url_tags+=",iis,aspnet" ;;
                    *wordpress*)  url_tags+=",wordpress" ;;
                    *spring*|*actuator*) url_tags+=",spring,actuator,java" ;;
                    *tomcat*)     url_tags+=",tomcat,java" ;;
                    *zk*)         url_tags+=",zk,zkoss,java" ;;
                    *passenger*|*ruby*|*rails*) url_tags+=",rails,ruby,passenger" ;;
                    *php*)        url_tags+=",php" ;;
                    *jenkins*)    url_tags+=",jenkins" ;;
                    *gitlab*)     url_tags+=",gitlab" ;;
                    *grafana*)    url_tags+=",grafana" ;;
                    *drupal*)     url_tags+=",drupal" ;;
                    *joomla*)     url_tags+=",joomla" ;;
                    *laravel*)    url_tags+=",laravel,php" ;;
                    *django*)     url_tags+=",django,python" ;;
                    *exchange*|*owa*) url_tags+=",exchange,owa" ;;
                    *sharepoint*) url_tags+=",sharepoint" ;;
                    *citrix*|*netscaler*) url_tags+=",citrix,netscaler" ;;
                    *fortinet*|*fortigate*) url_tags+=",fortinet,fortigate" ;;
                    *coldfusion*) url_tags+=",coldfusion" ;;
                    *jboss*|*wildfly*) url_tags+=",jboss,wildfly,java" ;;
                    *weblogic*)   url_tags+=",weblogic,java" ;;
                    *graphql*)    url_tags+=",graphql,api" ;;
                    *swagger*|*openapi*) url_tags+=",swagger,api" ;;
                esac
            done
            url_tags=$(echo "$url_tags" | tr ',' '\n' | sort -u | grep -v '^$' | paste -sd ',')

            safe_url=$(echo "$url" | md5sum | cut -c1-12)
            local -a nuc_per_args=(
                -u "$url"
                -tags "$url_tags"
                -severity medium,high,critical
                -etags fuzz,dos
                -concurrency 5 -rl 15
                -timeout 15 -retries 1
                -silent -no-interactsh
                -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                -o "$per_url_dir/${safe_url}.txt"
            )
            [[ ${#AUTH_ARGS_NUCLEI[@]} -gt 0 ]] && nuc_per_args+=("${AUTH_ARGS_NUCLEI[@]}")
            verb "Per-URL nuclei: $url -> tags: $url_tags"
            TIMEOUT=900 run_cmd "nuclei per-url" "$NUCLEI" "${nuc_per_args[@]}"
        done < "$deep_dir/url_tech_map.tsv"

        if compgen -G "$per_url_dir/*.txt" > /dev/null; then
            cat "$per_url_dir"/*.txt 2>/dev/null \
            | sort -u >> "$deep_dir/nuclei_full.txt"
            sort -u -o "$deep_dir/nuclei_full.txt" "$deep_dir/nuclei_full.txt"
            info "Per-URL nuclei results merged into nuclei_full.txt"
        fi
        state_mark "deep.nuclei_per_url"
    fi

    # 4.4c Default credentials (web)
    touch "$deep_dir/default_creds.txt"
    if [[ "$NO_DEFAULT_CREDS" != true && "$NO_NUCLEI" != true && -x "$NUCLEI" && -s "$live_urls" ]] \
       && ! state_check "deep.default_creds"; then
        info "[Deep] Default credentials nuclei scan (web) ..."
        local -a nuc_dc_args=(
            -l "$live_urls"
            -t default-logins/
            -severity medium,high,critical
            -etags fuzz,dos
            -concurrency 5 -rl 10
            -timeout 15
            -silent -no-interactsh
            -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            -o "$deep_dir/default_creds.txt"
        )
        TIMEOUT=$NUCLEI_TIMEOUT run_cmd "nuclei default-logins" "$NUCLEI" "${nuc_dc_args[@]}"
        local dc_count
        dc_count=$(wc -l < "$deep_dir/default_creds.txt" 2>/dev/null || echo 0)
        [[ "$dc_count" -gt 0 ]] && warn "Default credentials hits: $dc_count"
        state_mark "deep.default_creds"
    fi

    # 4.4d Network-protocol nuclei pass (SMB/LDAP/RDP/MSSQL/Kerberos/etc.)
    touch "$deep_dir/nuclei_network.txt"
    local network_targets_src=""
    if [[ -n "${NETWORK_TARGETS_FILE:-}" && -s "$NETWORK_TARGETS_FILE" ]]; then
        network_targets_src="$NETWORK_TARGETS_FILE"
        info "[Deep] Network-protocol targets: $NETWORK_TARGETS_FILE (user-supplied)"
    elif [[ -s "$disc_dir/open_ports.txt" ]]; then
        network_targets_src="$disc_dir/open_ports.txt"
        info "[Deep] Network-protocol targets: $disc_dir/open_ports.txt (naabu discovery)"
    fi

    if [[ "$NO_NUCLEI" != true && -x "$NUCLEI" && -n "$network_targets_src" ]] \
       && ! state_check "deep.network_nuclei"; then
        local net_conc="${NUCLEI_NET_CONC:-25}"
        local net_rate="${NUCLEI_NET_RATE:-100}"
        local net_severity="${NUCLEI_NET_SEVERITY:-critical,high,medium}"
        local net_exclude_tags="${NUCLEI_NET_EXCLUDE_TAGS:-fuzz,dos}"
        info "[Deep] Network-protocol nuclei scan (concurrency=$net_conc rate=$net_rate severity=$net_severity exclude-tags=$net_exclude_tags) ..."
        local -a nuc_net_args=(
            -l "$network_targets_src"
            -tags smb,ldap,rdp,mssql,kerberos,dns,ssh,ftp,rpc,telnet,snmp,network,default-logins
            -severity "$net_severity"
            -etags "$net_exclude_tags"
            -concurrency "$net_conc"
            -rl "$net_rate"
            -timeout 10
            -retries 1
            -silent -no-interactsh
            -o "$deep_dir/nuclei_network.txt"
        )
        TIMEOUT=$NUCLEI_TIMEOUT run_cmd "nuclei network" "$NUCLEI" "${nuc_net_args[@]}"
        local net_count
        net_count=$(wc -l < "$deep_dir/nuclei_network.txt" 2>/dev/null || echo 0)
        [[ "$net_count" -gt 0 ]] && warn "Network-protocol findings: $net_count"
        state_mark "deep.network_nuclei"
    elif [[ -z "$network_targets_src" ]]; then
        info "[Deep] No network target source available -- skipping network-protocol nuclei (pass --network-targets FILE or leave naabu portscan enabled)"
    fi

    local nuc_total
    nuc_total=$(cat "$deep_dir/nuclei_recon.txt" "$deep_dir/nuclei_full.txt" \
                    "$deep_dir/default_creds.txt" "$deep_dir/nuclei_network.txt" 2>/dev/null \
                | sort -u | wc -l)
    ok "Nuclei total findings (all passes): $nuc_total"

    # 4.5 Dalfox
    touch "$deep_dir/dalfox_results.txt"
    if [[ "$NO_DALFOX" != true && -x "$DALFOX" && -s "$deep_dir/urls_with_params.txt" ]] \
       && ! state_check "deep.dalfox"; then
        info "[Deep] Dalfox XSS scan (first $DALFOX_MAX parametric URLs -- override with DALFOX_MAX=<n>) ..."
        head -n "$DALFOX_MAX" "$deep_dir/urls_with_params.txt" > "$deep_dir/dalfox_targets.txt"

        local -a dalfox_args=(
            file "$deep_dir/dalfox_targets.txt"
            --silence
            --output "$deep_dir/dalfox_results.txt"
        )
        [[ -n "$AUTH_COOKIE" ]] && dalfox_args+=(--cookie "$AUTH_COOKIE")
        [[ -n "$AUTH_HEADER" ]] && dalfox_args+=(--header "$AUTH_HEADER")
        TIMEOUT=$PHASE_TIMEOUT run_cmd "dalfox" "$DALFOX" "${dalfox_args[@]}"
        state_mark "deep.dalfox"
    fi

    # 4.6 Screenshots
    if [[ "$NO_SCREENSHOTS" != true && -x "$GOWITNESS" && -s "$live_urls" ]] \
       && ! state_check "deep.screenshots"; then
        info "[Deep] Screenshots (gowitness) ..."
        TIMEOUT=1800 run_cmd "gowitness" "$GOWITNESS" scan file \
            -f "$live_urls" -s "$deep_dir/screenshots" 2>/dev/null || true
        ok "Screenshots saved to $deep_dir/screenshots/"
        state_mark "deep.screenshots"
    fi

    # 4.7 Verify scripts
    if ! state_check "deep.verify_scripts"; then
        local verify_dir="$deep_dir/verify"
        mkdir -p "$verify_dir"
        local all_findings="$deep_dir/all_findings_combined.txt"
        cat "$deep_dir/nuclei_recon.txt" "$deep_dir/nuclei_full.txt" \
            "$deep_dir/default_creds.txt" "$deep_dir/nuclei_network.txt" 2>/dev/null \
        | sort -u > "$all_findings"

        if [[ -s "$all_findings" ]]; then
            local count=0
            while IFS= read -r line; do
                local tid url
                tid=$(echo "$line" | grep -oP '^\[\K[^\]]+' | head -1)
                url=$(echo "$line" | grep -oP 'https?://\S+|[0-9]{1,3}(\.[0-9]{1,3}){3}:[0-9]+' | head -1)
                [[ -z "$tid" || -z "$url" ]] && continue
                ((count++))
                local safe_tid
                safe_tid=$(echo "${tid}_${count}" | tr -c '[:alnum:]_' '_')
                cat > "$verify_dir/verify_${safe_tid}.sh" <<EOFV
#!/bin/bash
# taraf verify finding: $tid against $url
# NOTE: auth headers are intentionally NOT baked into this script (they are
# session secrets). If the original finding was authenticated, re-run with:
#   nuclei -u "$url" -id "$tid" -H "Cookie: ..." -v
 "$(command -v nuclei || echo nuclei)" -u "$url" -id "$tid" -v
EOFV
                chmod +x "$verify_dir/verify_${safe_tid}.sh" 2>/dev/null || true
            done < "$all_findings"
            ok "Generated $count verification scripts in $verify_dir/"
        fi
        state_mark "deep.verify_scripts"
    fi

    state_mark "deep"
    ok "Phase DEEP complete"
}

# =============================================================================
# PHASE 5: REPORTING
# =============================================================================
phase_report() {
    local report_dir="$OUTDIR/report"
    local disc_dir="$OUTDIR/discovery"
    local deep_dir="$OUTDIR/deep"
    local active_dir="$OUTDIR/active"

    mkdir -p "$active_dir" "$deep_dir"
    touch \
        "$active_dir/vhost_discovered.txt" \
        "$active_dir/backup_hits.txt" \
        "$active_dir/backup_hits_sized.txt" \
        "$active_dir/git_confirmed.txt" \
        "$active_dir/endpoints_discovered.txt" \
        "$active_dir/api_endpoints.txt" \
        "$active_dir/zip_files.txt" \
        "$active_dir/cors_findings.txt" \
        "$active_dir/whatweb_summary.txt" \
        "$active_dir/js_files.txt" \
        "$active_dir/js_files_httpx.txt" \
        "$active_dir/js_files_curl.txt" \
        "$active_dir/takeover_candidates.txt" \
        "$active_dir/admin_panels_found.txt" \
        "$deep_dir/nuclei_recon.txt" \
        "$deep_dir/nuclei_full.txt" \
        "$deep_dir/default_creds.txt" \
        "$deep_dir/nuclei_network.txt" \
        "$deep_dir/js_secrets.txt" \
        "$deep_dir/js_endpoints.txt" \
        "$deep_dir/js_analysis.txt" \
        "$deep_dir/sourcemaps_found.txt" \
        "$deep_dir/dalfox_results.txt" \
        "$deep_dir/tech_profile.txt"

    state_check "report" && { info "Phase REPORT already done -- skipping"; return 0; }
    log "=== PHASE 5: REPORTING ==="
    mkdir -p "$report_dir"

    write_engagement_metadata "$OUTDIR"

    local target_name
    target_name=$(basename "$OUTDIR")
    local report_md="$report_dir/summary.md"

    local ct_count arch_count ip_count alive_count sub_count live_count
    local vhost_count backup_hits git_confirmed ep_count api_count zip_count
    local nuc_recon nuc_full nuc_dc nuc_net js_secrets xss_count cors_count ww_count
    local js_ep_count sm_count js_curl_count js_httpx_count takeover_count admin_count
    ct_count=$(wc    -l < "$OUTDIR/passive/ct_subdomains.txt"    2>/dev/null || echo 0)
    arch_count=$(wc  -l < "$OUTDIR/passive/archive_urls.txt"     2>/dev/null || echo 0)
    ip_count=$(wc    -l < "$disc_dir/all_ips.txt"                2>/dev/null || echo 0)
    alive_count=$(wc -l < "$disc_dir/alive_ips.txt"              2>/dev/null || echo 0)
    sub_count=$(wc   -l < "$disc_dir/subdomains.txt"             2>/dev/null || echo 0)
    live_count=$(wc  -l < "$disc_dir/live_urls.txt"              2>/dev/null || echo 0)
    vhost_count=$(wc -l < "$active_dir/vhost_discovered.txt"     2>/dev/null || echo 0)
    backup_hits=$(wc -l < "$active_dir/backup_hits.txt"          2>/dev/null || echo 0)
    git_confirmed=$(wc -l < "$active_dir/git_confirmed.txt"      2>/dev/null || echo 0)
    ep_count=$(wc    -l < "$active_dir/endpoints_discovered.txt" 2>/dev/null || echo 0)
    api_count=$(wc   -l < "$active_dir/api_endpoints.txt"        2>/dev/null || echo 0)
    zip_count=$(wc   -l < "$active_dir/zip_files.txt"            2>/dev/null || echo 0)
    nuc_recon=$(wc   -l < "$deep_dir/nuclei_recon.txt"           2>/dev/null || echo 0)
    nuc_full=$(wc    -l < "$deep_dir/nuclei_full.txt"            2>/dev/null || echo 0)
    nuc_dc=$(wc      -l < "$deep_dir/default_creds.txt"          2>/dev/null || echo 0)
    nuc_net=$(wc     -l < "$deep_dir/nuclei_network.txt"         2>/dev/null || echo 0)
    js_secrets=$(wc  -l < "$deep_dir/js_secrets.txt"             2>/dev/null || echo 0)
    xss_count=$(wc   -l < "$deep_dir/dalfox_results.txt"         2>/dev/null || echo 0)
    cors_count=$(wc  -l < "$active_dir/cors_findings.txt"        2>/dev/null || echo 0)
    ww_count=$(wc    -l < "$active_dir/whatweb_summary.txt"      2>/dev/null || echo 0)
    js_ep_count=$(wc -l < "$deep_dir/js_endpoints.txt"           2>/dev/null || echo 0)
    sm_count=$(wc    -l < "$deep_dir/sourcemaps_found.txt"       2>/dev/null || echo 0)
    js_curl_count=$(wc -l < "$active_dir/js_files_curl.txt"      2>/dev/null || echo 0)
    js_httpx_count=$(wc -l < "$active_dir/js_files_httpx.txt"    2>/dev/null || echo 0)
    takeover_count=$(wc -l < "$active_dir/takeover_candidates.txt" 2>/dev/null || echo 0)
    admin_count=$(wc -l < "$active_dir/admin_panels_found.txt"   2>/dev/null || echo 0)

    cat > "$report_md" <<MDEOF
# taraf -- Engagement Report: ${target_name}
**Generated:** $(date)
**Scanner:** taraf v${VERSION}
**Engagement Mode:** ${ENGAGEMENT_MODE}
**Stealth:** ${STEALTH}
**Authenticated:** $([ -n "$AUTH_COOKIE$AUTH_HEADER$AUTH_BASIC" ] && echo "Yes" || echo "No")

## Executive Summary

| Metric | Value |
|--------|-------|
| Total IPs | ${ip_count} |
| Alive Hosts | ${alive_count} |
| Target Hostnames | ${sub_count} |
| Live HTTP(S) Services | ${live_count} |
| Admin Panels Found | ${admin_count} |
| Takeover Candidates | ${takeover_count} |
| Backup Probes Hit | ${backup_hits} |
| Git Config Confirmed | ${git_confirmed} |
| Endpoints Discovered | ${ep_count} |
| Nuclei Findings (recon) | ${nuc_recon} |
| Nuclei Findings (tech) | ${nuc_full} |
| Nuclei Findings (network protocols) | ${nuc_net} |
| Default Credentials | ${nuc_dc} |
| CORS Issues | ${cors_count} |
| XSS Findings | ${xss_count} |
| JS Secrets | ${js_secrets} |
| JS Endpoints | ${js_ep_count} |
| Sourcemaps | ${sm_count} |
| WhatWeb Fingerprints | ${ww_count} |

## 1. Passive

| Source | Count |
|--------|-------|
| CT Logs | ${ct_count} |
| Archive URLs | ${arch_count} |

## 2. Discovery

| Metric | Count |
|--------|-------|
| Total IPs | ${ip_count} |
| Alive Hosts | ${alive_count} |
| Target Hostnames | ${sub_count} |
| Live Services | ${live_count} |

### Technology Stack (top 20)

MDEOF
    if [[ -x "$JQ" && -s "$disc_dir/httpx_live.jsonl" ]]; then
        "$JQ" -r 'select(.tech!=null) | .tech[]' \
            "$disc_dir/httpx_live.jsonl" 2>/dev/null \
            | sort | uniq -c | sort -rn | head -20 \
            | while read -r count tech; do
                echo "- ${tech} (${count})"
            done >> "$report_md"
    fi

    cat >> "$report_md" <<MDEOF
## 3. Active

| Source | Count |
|--------|-------|
| Virtual Hosts | ${vhost_count} |
| Admin Panels | ${admin_count} |
| Takeover Candidates | ${takeover_count} |
| Backup Hits | ${backup_hits} |
| Git Confirmed | ${git_confirmed} |
| Discovered Endpoints | ${ep_count} |
| API Endpoints | ${api_count} |
| .zip Links | ${zip_count} |
| WhatWeb Fingerprints | ${ww_count} |
| JS Files (HTTPX) | ${js_httpx_count} |
| JS Files (Curl) | ${js_curl_count} |

### Backup Hits

MDEOF
    if [[ -s "$active_dir/backup_hits.txt" ]]; then
        cat "$active_dir/backup_hits.txt" >> "$report_md"
    else
        echo "_No backup/sensitive files found._" >> "$report_md"
    fi

    cat >> "$report_md" <<MDEOF
### Takeover Candidates

MDEOF
    if [[ -s "$active_dir/takeover_candidates.txt" ]]; then
        cat "$active_dir/takeover_candidates.txt" >> "$report_md"
    else
        echo "_No takeover candidates detected._" >> "$report_md"
    fi

    cat >> "$report_md" <<MDEOF
### Admin Panels Found

MDEOF
    if [[ -s "$active_dir/admin_panels_found.txt" ]]; then
        head -30 "$active_dir/admin_panels_found.txt" >> "$report_md"
    else
        echo "_No admin panels detected._" >> "$report_md"
    fi

    cat >> "$report_md" <<MDEOF
### CORS Findings

MDEOF
    if [[ -s "$active_dir/cors_findings.txt" ]]; then
        cat "$active_dir/cors_findings.txt" >> "$report_md"
    else
        echo "_No CORS misconfigurations._" >> "$report_md"
    fi

    cat >> "$report_md" <<MDEOF
## 4. Deep

| Source | Count |
|--------|-------|
| Nuclei (recon) | ${nuc_recon} |
| Nuclei (tech/CVE) | ${nuc_full} |
| Nuclei (network protocols) | ${nuc_net} |
| Default Credentials | ${nuc_dc} |
| JS Endpoints | ${js_ep_count} |
| JS Secrets | ${js_secrets} |
| Sourcemaps | ${sm_count} |
| XSS | ${xss_count} |

### Network-Protocol Findings (SMB/LDAP/RDP/MSSQL/Kerberos/etc.)

\`\`\`
MDEOF
    if [[ -s "$deep_dir/nuclei_network.txt" ]]; then
        cat "$deep_dir/nuclei_network.txt" >> "$report_md"
    else
        echo "(none -- either no findings, or no --network-targets / naabu port list was available)" >> "$report_md"
    fi
    echo '```' >> "$report_md"

    cat >> "$report_md" <<MDEOF
### JS Secrets (first 20)

\`\`\`
MDEOF
    if [[ -s "$deep_dir/js_secrets.txt" ]]; then
        head -n 20 "$deep_dir/js_secrets.txt" >> "$report_md"
    fi
    echo '```' >> "$report_md"

    cat >> "$report_md" <<MDEOF
### Nuclei Findings -- web (first 50)

\`\`\`
MDEOF
    cat "$deep_dir/nuclei_recon.txt" "$deep_dir/nuclei_full.txt" \
        "$deep_dir/default_creds.txt" 2>/dev/null \
    | sort -u | head -n 50 >> "$report_md"
    echo '```' >> "$report_md"

    cat >> "$report_md" <<MDEOF
## 5. Metadata

See [engagement.json](../engagement.json) for chain of custody.

## 6. Verification Scripts

Per-finding scripts in \`deep/verify/\`.

---
*taraf v${VERSION} -- map the edge*
MDEOF

    cat > "$report_dir/summary.csv" <<CSVEOF
Category,Metric,Count
Overview,Target,${target_name}
Overview,Timestamp,$(date -Iseconds)
Overview,Mode,${ENGAGEMENT_MODE}
Overview,Stealth,${STEALTH}
Passive,CT_Subdomains,${ct_count}
Passive,Archive_URLs,${arch_count}
Discovery,Total_IPs,${ip_count}
Discovery,Alive_IPs,${alive_count}
Discovery,Target_Hostnames,${sub_count}
Discovery,Live_URLs,${live_count}
Active,VHosts,${vhost_count}
Active,Admin_Panels,${admin_count}
Active,Takeover_Candidates,${takeover_count}
Active,Backup_Hits,${backup_hits}
Active,Git_Confirmed,${git_confirmed}
Active,Discovered_Endpoints,${ep_count}
Active,API_Endpoints,${api_count}
Active,ZIP_Links,${zip_count}
Active,WhatWeb,${ww_count}
Active,JS_HTTPX,${js_httpx_count}
Active,JS_Curl,${js_curl_count}
Deep,Nuclei_Recon,${nuc_recon}
Deep,Nuclei_Tech,${nuc_full}
Deep,Nuclei_Network,${nuc_net}
Deep,Default_Creds,${nuc_dc}
Deep,JS_Endpoints,${js_ep_count}
Deep,JS_Secrets,${js_secrets}
Deep,Sourcemaps,${sm_count}
Deep,XSS,${xss_count}
Deep,CORS,${cors_count}
CSVEOF

    state_mark "report"
    ok "Phase REPORT complete -> $report_md"
}

# =============================================================================
# SUMMARY BANNER
# =============================================================================
print_summary() {
    local disc_dir="$OUTDIR/discovery"
    local deep_dir="$OUTDIR/deep"
    local active_dir="$OUTDIR/active"

    echo ""
    echo -e "${BOLD}===================================================${RESET}"
    echo -e "${BOLD} taraf summary -- $(basename "$OUTDIR")${RESET}"
    echo -e "${BOLD} recon: ${RECON_MODE}  mode: ${ENGAGEMENT_MODE}  stealth: ${STEALTH}${RESET}"
    echo -e "${BOLD}===================================================${RESET}"

    local -A labels=(
        ["$disc_dir/all_ips.txt"]="IPs in scope"
        ["$disc_dir/alive_ips.txt"]="Alive hosts"
        ["$disc_dir/hosts_down.txt"]="Hosts down"
        ["$disc_dir/subdomains.txt"]="Target hostnames"
        ["$disc_dir/live_urls.txt"]="Live HTTP(S) URLs"
        ["$disc_dir/open_ports.txt"]="Open ports (naabu)"
        ["$disc_dir/nmap_open_ports.txt"]="Nmap open ports"
        ["$active_dir/vhost_discovered.txt"]="Virtual hosts"
        ["$active_dir/admin_panels_found.txt"]="Admin panels"
        ["$active_dir/takeover_candidates.txt"]="Takeover candidates"
        ["$active_dir/backup_hits.txt"]="Backup hits"
        ["$active_dir/git_confirmed.txt"]="Git confirmed"
        ["$active_dir/zip_files.txt"]=".zip links"
        ["$active_dir/api_endpoints.txt"]="API endpoints"
        ["$active_dir/endpoints_discovered.txt"]="Discovered endpoints"
        ["$active_dir/cors_findings.txt"]="CORS issues"
        ["$active_dir/whatweb_summary.txt"]="WhatWeb fingerprints"
        ["$active_dir/whatweb_tech.txt"]="WhatWeb tech (cleaned)"
        ["$active_dir/js_files.txt"]="JS files total"
        ["$active_dir/js_files_curl.txt"]="JS files (curl)"
        ["$deep_dir/tech_profile.txt"]="Tech profile entries"
        ["$deep_dir/js_endpoints.txt"]="JS endpoints"
        ["$deep_dir/js_secrets.txt"]="JS secrets"
        ["$deep_dir/sourcemaps_found.txt"]="Sourcemaps"
        ["$deep_dir/nuclei_recon.txt"]="Nuclei (recon)"
        ["$deep_dir/nuclei_full.txt"]="Nuclei (tech)"
        ["$deep_dir/nuclei_network.txt"]="Nuclei (network protocols)"
        ["$deep_dir/default_creds.txt"]="Default credentials"
        ["$deep_dir/dalfox_results.txt"]="XSS findings"
    )

    local f count
    for f in "${!labels[@]}"; do
        [[ -f "$f" ]] || continue
        count=$(wc -l < "$f" 2>/dev/null || echo 0)
        printf "  %-44s %s\n" "${labels[$f]}" "$count"
    done

    echo ""
    echo -e "  ${CYAN}output dir${RESET}      : $OUTDIR"
    echo -e "  ${CYAN}engagement${RESET}      : $OUTDIR/engagement.json"
    echo -e "  ${CYAN}live URLs${RESET}       : $disc_dir/live_urls.txt"
    echo -e "  ${CYAN}backup hits${RESET}     : $active_dir/backup_hits.txt"
    echo -e "  ${CYAN}admin panels${RESET}    : $active_dir/admin_panels_found.txt"
    echo -e "  ${CYAN}takeovers${RESET}       : $active_dir/takeover_candidates.txt"
    echo -e "  ${CYAN}JS secrets${RESET}      : $deep_dir/js_secrets.txt"
    echo -e "  ${CYAN}JS pretty${RESET}       : $deep_dir/js_pretty/"
    echo -e "  ${CYAN}endpoints${RESET}       : $active_dir/endpoints_discovered.txt"
    echo -e "  ${CYAN}nuclei${RESET}          : $deep_dir/nuclei_recon.txt"
    echo -e "  ${CYAN}nuclei tech${RESET}     : $deep_dir/nuclei_full.txt"
    echo -e "  ${CYAN}nuclei network${RESET}  : $deep_dir/nuclei_network.txt"
    echo -e "  ${CYAN}per-URL nuclei${RESET}  : $deep_dir/nuclei_per_url/"
    echo -e "  ${CYAN}default creds${RESET}   : $deep_dir/default_creds.txt"
    echo -e "  ${CYAN}verify scripts${RESET}  : $deep_dir/verify/"
    echo -e "  ${CYAN}screenshots${RESET}     : $deep_dir/screenshots/"
    echo -e "  ${CYAN}report${RESET}          : $OUTDIR/report/summary.md"
    echo -e "  ${CYAN}full log${RESET}        : $OUTDIR/taraf.log"
    echo -e "${BOLD}===================================================${RESET}"
    echo ""
}

# =============================================================================
# PIPELINE (with nmap-file support)
# =============================================================================
run_pipeline() {
    local input_file="$1"
    local target_name="$2"

    [[ ! -f "$input_file" ]] && { warn "Input not found: $input_file"; return 1; }

    OUTDIR=$(init_outdir "$target_name")
    info "Output: $OUTDIR"
    LOG_FILE="$OUTDIR/taraf.log"
    state_init "$OUTDIR"

    write_engagement_metadata "$OUTDIR"

    local raw_ips="$OUTDIR/raw_ips.txt"
    local raw_domains="$OUTDIR/raw_domains.txt"
    local raw_urls="$OUTDIR/raw_urls.txt"
    normalise_input "$input_file" "$raw_ips" "$raw_domains" "$raw_urls"

    if [[ -n "$SCOPE_FILE" || -n "$EXCLUDE_FILE" ]]; then
        info "[Scope] Applying scope filters to raw inputs ..."
        local raw
        for raw in "$raw_ips" "$raw_domains" "$raw_urls"; do
            [[ -s "$raw" ]] || continue
            enforce_scope "$raw" "${raw}.scoped"
            mv "${raw}.scoped" "$raw"
        done
        local scoped_total=0 sc
        for sc in "$raw_ips" "$raw_domains" "$raw_urls"; do
            [[ -s "$sc" ]] && scoped_total=$(( scoped_total + $(wc -l < "$sc") ))
        done
        if [[ "$scoped_total" -eq 0 ]]; then
            die "[Scope] Scope/exclude filters removed ALL targets -- check $SCOPE_FILE / $EXCLUDE_FILE (fixed-string matching, one entry per line)"
        fi
        info "[Scope] $scoped_total targets remain after filtering"
    fi

    # Fresh run in a reused outdir: drop stale *.failed markers so failed
    # sub-phases actually re-run. (--resume keeps them for retry logic.)
    [[ "$RESUME" != true ]] && state_reset_failures

    filter_real_hostnames "$raw_domains" "$OUTDIR/raw_domains_hostnames.txt"
    local hn_count
    hn_count=$(wc -l < "$OUTDIR/raw_domains_hostnames.txt" 2>/dev/null || echo 0)
    info "Genuine hostnames (non-IP) for domain-semantic lookups: $hn_count"

    local ip_in dom_in url_in total
    ip_in=$(wc -l < "$raw_ips"      2>/dev/null || echo 0)
    dom_in=$(wc -l < "$raw_domains" 2>/dev/null || echo 0)
    url_in=$(wc -l < "$raw_urls"    2>/dev/null || echo 0)
    total=$(( ip_in + dom_in + url_in ))
    info "Input: IPs=$ip_in  Domains=$dom_in  URLs=$url_in  Total=$total"

    if [[ "$total" -gt "$MAX_TARGETS" ]]; then
        die "Input has $total targets -- exceeds MAX_TARGETS=$MAX_TARGETS. Override with --max-targets."
    fi

    IFS=',' read -ra PHASE_ARRAY <<< "$PHASES"
    local phase
    for phase in "${PHASE_ARRAY[@]}"; do
        case "$phase" in
            passive)   phase_passive   "$raw_domains" ;;
            discovery) phase_discovery "$raw_ips" "$raw_domains" "$raw_urls" ;;
            active)    phase_active ;;
            deep)      phase_deep ;;
            report)    phase_report ;;
            *)         warn "Unknown phase: $phase" ;;
        esac
    done

    # Rotate oversized outputs (MAX_OUTFILE_MB) so reruns do not append to
    # multi-GB files. Previously defined but never called.
    local big
    for big in "$OUTDIR/taraf.log" "$OUTDIR/passive/archive_urls.txt" \
               "$OUTDIR/discovery/httpx_live.jsonl" "$OUTDIR/discovery/dns_records.jsonl" \
               "$OUTDIR/deep/nuclei_recon.txt" "$OUTDIR/deep/nuclei_full.txt" \
               "$OUTDIR/deep/nuclei_network.txt"; do
        rotate_if_large "$big"
    done

    print_summary
    ok "Pipeline complete: $target_name -> $OUTDIR"
}

# =============================================================================
# ENTRYPOINT (skipped when the file is sourced for testing/library use)
# =============================================================================
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
parse_args "$@"
banner
apply_mode_presets
build_auth_args
resolve_all_tools
check_tools
resolve_scan_mode
start_pause_watcher

if [[ -n "$OUTDIR_BASE" ]]; then
    mkdir -p "$OUTDIR_BASE"
fi

case "$MODE" in
    target-dir)
        [[ ! -d "$MODE_VAL" ]] && die "Directory not found: $MODE_VAL"
        info "Processing all .txt files in: $MODE_VAL"
        for f in "$MODE_VAL"/*.txt; do
            [[ -f "$f" ]] || continue
            name=$(basename "$f" .txt)
            log "==================================================="
            log "Target group: $name"
            log "==================================================="
            run_pipeline "$f" "$name"
        done
        ;;
    file)
        name=$(basename "$MODE_VAL" .txt)
        run_pipeline "$MODE_VAL" "$name"
        ;;
    domain)
        tmpfile=$(mktemp)
        TARAF_TMPFILES+=("$tmpfile")
        echo "$MODE_VAL" > "$tmpfile"
        run_pipeline "$tmpfile" "$MODE_VAL"
        ;;
    cidr)
        [[ -z "$MAPCIDR" || ! -x "$MAPCIDR" ]] && die "mapcidr not found -- required for --cidr"
        tmpfile=$(mktemp)
        TARAF_TMPFILES+=("$tmpfile")
        "$MAPCIDR" -cidr "$MODE_VAL" -silent > "$tmpfile"
        safe_name=$(echo "$MODE_VAL" | tr '/.' '_')
        run_pipeline "$tmpfile" "$safe_name"
        ;;
    url)
        tmpfile=$(mktemp)
        TARAF_TMPFILES+=("$tmpfile")
        echo "$MODE_VAL" > "$tmpfile"
        urlhost=$(echo "$MODE_VAL" | sed 's|^[a-zA-Z]*://||' | cut -d'/' -f1)
        run_pipeline "$tmpfile" "$urlhost"
        ;;
    nmap)
        tmpdir=$(mktemp -d)
        TARAF_TMPFILES+=("$tmpdir")
        run_nmap_to_targets "$MODE_VAL" "$tmpdir"
        web_file="$tmpdir/web_targets.txt"
        net_file="$tmpdir/all_open_hostports.txt"
        [[ -s "$web_file" ]] || warn "nmap_to_targets produced no web targets"
        [[ -s "$net_file" ]] || warn "nmap_to_targets produced no network targets"

        # Use the generated web targets as the primary --file,
        # and the all_open_hostports as --network-targets.
        # Also, auto-skip naabu port scan since nmap already provided the port data.
        NETWORK_TARGETS_FILE="$net_file"
        NO_PORTSCAN=true
        name=$(basename "$MODE_VAL" .nmap)
        run_pipeline "$web_file" "$name"
        ;;
    *)
        die "Unknown mode: $MODE"
        ;;
esac

log "taraf complete."
fi  
