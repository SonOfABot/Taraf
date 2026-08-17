#!/usr/bin/env python3
"""
nmap_to_targets.py -- convert nmap -sVC (normal/-oN/-oA) output into
taraf-ready target files. Classifies ports by evidence, not port-number
assumption, so it correctly handles things like:

    3333/tcp  open  ssh        -> ssh, not web
    8080/tcp  open  http       -> web (http)
    9200/tcp  open  http       -> web (http), even though 9200 is normally
                                   Elasticsearch's default port -- nmap's own
                                   service probe wins over stereotype
    23/tcp    open  telnet     -> flagged interesting (Huawei switch telnetd)
    9100/tcp  open  jetdirect? -> flagged interesting, NOT treated as web
    111/tcp   open  rpcbind    -> flagged interesting, NOT treated as web

A port is classified as HTTPS if its service string contains "ssl" OR its
script block contains ssl-cert/ssl-date/tls-alpn. It's classified as HTTP
if the service string is exactly "http"/"https" OR the block contains an
http-* nmap script (http-title, http-server-header, http-methods, etc.)
even when nmap listed the service as "unknown" or a guessed name with "?".

Usage:
    python3 nmap_to_targets.py SCAN.nmap --outdir ./targets

Outputs (in --outdir):
    web_targets.txt          http://ip:port and https://ip:port lines.
                              Feed directly: taraf.sh --file web_targets.txt
    all_open_hostports.txt   ip:port for every open port, any service.
                              Feed directly: taraf.sh --network-targets all_open_hostports.txt
    ssh_targets.txt          ip:port for ssh services specifically.
    interesting_hosts.txt    ports/services worth a first manual look
                              (telnet, printers/jetdirect, rpcbind, admin
                              panels, container/orchestration exposure).
    service_inventory.tsv    host  port  proto  service  product/version  tls(y/n)
                              Full per-port record -- good raw material for
                              the report's asset inventory section.
"""

import argparse
import re
import sys
from pathlib import Path

PORT_LINE_RE = re.compile(
    r'^(?P<port>\d+)/(?P<proto>tcp|udp)\s+(?P<state>open(?:\|filtered)?)\s+'
    r'(?P<service>\S+)(?:\s+(?P<version>.*))?$'
)
HOST_LINE_RE = re.compile(r'^Nmap scan report for (?P<rest>.+)$')

TLS_SCRIPT_MARKERS = ('ssl-cert', 'ssl-date', 'tls-alpn', 'ssl-enum-ciphers')
HTTP_SCRIPT_MARKERS = (
    'http-title', 'http-server-header', 'http-methods', 'http-headers',
    'http-open-proxy', 'http-webdav-scan', 'http-robots.txt',
    'http-cookie-flags', 'http-generator', 'http-trane-info',
)

INTERESTING_SERVICE_MARKERS = (
    'telnet', 'rpcbind', 'jetdirect', 'printer', 'snmp', 'vnc',
    'x11', 'nfs', 'tftp', 'rlogin', 'rsh', 'finger',
)
INTERESTING_VERSION_MARKERS = (
    'switch admin', 'printer', 'canon', 'huawei', 'cadvisor',
    'default', 'anonymous', 'jetdirect',
)


class PortRecord:
    __slots__ = ('port', 'proto', 'service', 'version', 'script_lines')

    def __init__(self, port, proto, service, version):
        self.port = port
        self.proto = proto
        self.service = service
        self.version = version or ''
        self.script_lines = []

    def has_tls_evidence(self):
        svc = self.service.lower()
        if 'ssl' in svc or svc == 'https':
            return True
        blob = '\n'.join(self.script_lines).lower()
        return any(m in blob for m in TLS_SCRIPT_MARKERS)

    def has_http_evidence(self):
        svc = self.service.lower().rstrip('?')
        if svc in ('http', 'https', 'http-proxy', 'http-alt'):
            return True
        blob = '\n'.join(self.script_lines).lower()
        return any(m in blob for m in HTTP_SCRIPT_MARKERS)

    def is_ssh(self):
        return self.service.lower().rstrip('?') == 'ssh'

    def is_interesting(self):
        svc = self.service.lower()
        ver = self.version.lower()
        if any(m in svc for m in INTERESTING_SERVICE_MARKERS):
            return True
        if any(m in ver for m in INTERESTING_VERSION_MARKERS):
            return True
        blob = '\n'.join(self.script_lines).lower()
        if 'cadvisor' in blob or 'containers' in blob:
            return True
        # Unknown service on a high, non-ephemeral-looking port with no
        # other evidence at all -- worth a manual glance.
        if svc in ('unknown',) and not self.script_lines:
            return True
        return False

    def classification(self):
        if self.has_tls_evidence() and self.has_http_evidence():
            return 'https'
        if self.has_http_evidence():
            return 'http'
        if self.is_ssh():
            return 'ssh'
        return 'other'


class HostBlock:
    __slots__ = ('ip', 'hostname', 'ports')

    def __init__(self, ip, hostname=None):
        self.ip = ip
        self.hostname = hostname
        self.ports = []


def parse_host_line(line):
    m = HOST_LINE_RE.match(line.strip())
    if not m:
        return None, None
    rest = m.group('rest').strip()
    # "example.com (10.0.0.1)" or just "10.0.0.1"
    paren = re.match(r'^(\S+)\s+\((\d+\.\d+\.\d+\.\d+)\)$', rest)
    if paren:
        return paren.group(2), paren.group(1)
    ip_only = re.match(r'^(\d+\.\d+\.\d+\.\d+)$', rest)
    if ip_only:
        return ip_only.group(1), None
    # Fallback: treat whole token as the identifier (covers IPv6 etc.)
    return rest, None


def parse_nmap_file(path):
    hosts = []
    current_host = None
    current_port = None

    with open(path, 'r', errors='replace') as fh:
        for raw_line in fh:
            line = raw_line.rstrip('\n')
            stripped = line.strip()

            if stripped.startswith('Nmap scan report for'):
                ip, hostname = parse_host_line(stripped)
                if ip:
                    current_host = HostBlock(ip, hostname)
                    hosts.append(current_host)
                    current_port = None
                continue

            if current_host is None:
                continue

            m = PORT_LINE_RE.match(stripped)
            if m:
                port = int(m.group('port'))
                proto = m.group('proto')
                service = m.group('service')
                version = m.group('version') or ''
                current_port = PortRecord(port, proto, service, version)
                current_host.ports.append(current_port)
                continue

            # Nmap script output lines are indented / start with | or |_
            if current_port is not None and (stripped.startswith('|') or line.startswith(' ')):
                current_port.script_lines.append(stripped)
                continue

            # Blank line or new section resets script association but not host
            if stripped == '' or stripped.startswith('Nmap scan report') or \
               stripped.startswith('Host script results') or \
               stripped.startswith('Service Info') or \
               stripped.startswith('Nmap done'):
                current_port = None

    return hosts


def write_outputs(hosts, outdir: Path):
    outdir.mkdir(parents=True, exist_ok=True)

    web_lines = []
    all_open_lines = []
    ssh_lines = []
    interesting_lines = []
    inventory_rows = [('host', 'port', 'proto', 'service', 'product_version', 'tls')]

    seen_web = set()
    seen_open = set()
    seen_ssh = set()

    for host in hosts:
        for p in host.ports:
            cls = p.classification()
            tls = 'y' if p.has_tls_evidence() else 'n'
            inventory_rows.append((
                host.ip, str(p.port), p.proto, p.service,
                p.version.replace('\t', ' ').strip(), tls
            ))

            hp = f"{host.ip}:{p.port}"
            if hp not in seen_open:
                all_open_lines.append(hp)
                seen_open.add(hp)

            if cls in ('http', 'https'):
                url = f"{cls}://{host.ip}:{p.port}"
                if url not in seen_web:
                    web_lines.append(url)
                    seen_web.add(url)
            elif cls == 'ssh':
                if hp not in seen_ssh:
                    ssh_lines.append(hp)
                    seen_ssh.add(hp)

            if p.is_interesting():
                note = p.version.strip() or p.service
                interesting_lines.append(f"{host.ip}:{p.port}\t{p.service}\t{note}")

    (outdir / 'web_targets.txt').write_text('\n'.join(sorted(web_lines)) + ('\n' if web_lines else ''))
    (outdir / 'all_open_hostports.txt').write_text('\n'.join(sorted(all_open_lines, key=lambda x: (x.split(':')[0], int(x.split(':')[1])))) + ('\n' if all_open_lines else ''))
    (outdir / 'ssh_targets.txt').write_text('\n'.join(sorted(ssh_lines)) + ('\n' if ssh_lines else ''))
    (outdir / 'interesting_hosts.txt').write_text('\n'.join(interesting_lines) + ('\n' if interesting_lines else ''))

    with open(outdir / 'service_inventory.tsv', 'w') as fh:
        for row in inventory_rows:
            fh.write('\t'.join(row) + '\n')

    return {
        'hosts': len(hosts),
        'ports_total': sum(len(h.ports) for h in hosts),
        'web': len(web_lines),
        'ssh': len(ssh_lines),
        'all_open': len(all_open_lines),
        'interesting': len(interesting_lines),
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('nmap_file', help='Path to nmap normal-format output (.nmap, or -oN/-oA file)')
    ap.add_argument('--outdir', default='./targets', help='Output directory (default: ./targets)')
    args = ap.parse_args()

    path = Path(args.nmap_file)
    if not path.is_file():
        print(f"error: file not found: {path}", file=sys.stderr)
        sys.exit(1)

    hosts = parse_nmap_file(path)
    if not hosts:
        print("warning: no 'Nmap scan report for' blocks found -- is this normal-format nmap output?", file=sys.stderr)

    outdir = Path(args.outdir)
    stats = write_outputs(hosts, outdir)

    print(f"Parsed {stats['hosts']} hosts, {stats['ports_total']} open ports")
    print(f"  web_targets.txt          {stats['web']} http(s) URLs")
    print(f"  all_open_hostports.txt   {stats['all_open']} ip:port entries")
    print(f"  ssh_targets.txt          {stats['ssh']} ssh services")
    print(f"  interesting_hosts.txt    {stats['interesting']} flagged for manual review")
    print(f"  service_inventory.tsv    full per-port record")
    print(f"\nOutput dir: {outdir}")


if __name__ == '__main__':
    main()
