"""
Network Module - Network Reconnaissance
"""

import argparse
import json
import re
import shutil
import subprocess
import sys
from typing import Dict, Any, List
from vortexosint.core.colors import Colors
from vortexosint.core.banner import print_module_banner


def run(args: argparse.Namespace) -> int:
    """Run the Network module."""
    print_module_banner("NETWORK", "Network Reconnaissance & Port Scanning")

    results = {}

    # Handle public IP lookup
    if getattr(args, "my_ip", False):
        print(f"\n{Colors.CYAN}[*] Resolving public IP...{Colors.RESET}")
        results['my_ip'] = show_my_ip()

    # Handle ICMP ping
    if getattr(args, "ping", None):
        print(f"\n{Colors.CYAN}[*] Pinging: {Colors.BOLD}{args.ping}{Colors.RESET}")
        results['ping'] = ping_host(args.ping)

    # Handle ASN lookup
    if args.asn:
        print(f"\n{Colors.CYAN}[*] Looking up ASN: {Colors.BOLD}{args.asn}{Colors.RESET}")
        results['asn'] = lookup_asn(args.asn)

    # Handle target scanning
    if args.target:
        print(f"\n{Colors.CYAN}[*] Scanning target: {Colors.BOLD}{args.target}{Colors.RESET}")
        results['scan'] = scan_target(args.target, args)

    if not results:
        print(f"{Colors.RED}[!] Nothing to do. Use --target, --asn, --my-ip or --ping{Colors.RESET}")
        return 1

    # Output results
    output_results(results, args)
    return 0


def show_my_ip() -> Dict[str, Any]:
    """Display the machine's public IP via several providers."""
    try:
        import requests
    except ImportError:
        print(f"  {Colors.RED}[!] The 'requests' package is required{Colors.RESET}")
        return {'error': 'requests not installed'}

    endpoints = [
        ("https://api.ipify.org?format=json", "json"),
        ("https://ifconfig.me/ip", "text"),
        ("https://ident.me", "text"),
    ]
    for url, kind in endpoints:
        try:
            resp = requests.get(url, timeout=10)
            if resp.status_code != 200:
                continue
            ip = resp.json()["ip"].strip() if kind == "json" else resp.text.strip()
            if ip:
                print(f"  {Colors.GREEN}[+] Public IP: {Colors.BOLD}{ip}{Colors.RESET}")
                print(Colors.dim(f"    via {url}"))
                return {'ip': ip, 'source': url}
        except Exception:
            continue
    print(f"  {Colors.RED}[!] Could not resolve public IP (offline?){Colors.RESET}")
    return {'error': 'unreachable'}


def ping_host(host: str, count: int = 4) -> Dict[str, Any]:
    """ICMP ping using the system binary (no root needed)."""
    binary = shutil.which("ping")
    if not binary:
        print(f"  {Colors.RED}[!] No 'ping' binary found on this system{Colors.RESET}")
        return {'host': host, 'error': 'ping binary not found'}

    flag = "-n" if sys.platform.startswith("win") else "-c"
    print(f"  {Colors.YELLOW}[~] Pinging {host} x{count}...{Colors.RESET}")
    try:
        proc = subprocess.run([binary, flag, str(count), host],
                              capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        print(f"  {Colors.RED}[!] Ping timed out{Colors.RESET}")
        return {'host': host, 'error': 'timeout'}
    except Exception as e:
        print(f"  {Colors.RED}[!] Ping failed: {e}{Colors.RESET}")
        return {'host': host, 'error': str(e)}

    out = proc.stdout or ""
    loss, avg = None, None
    m = (re.search(r"(\d+)\s*%\s*(?:loss|perte|packet loss)", out, re.IGNORECASE)
         or re.search(r"perte[^\d]*(\d+)\s*%", out, re.IGNORECASE))
    if m:
        loss = int(m.group(1))
    m = re.search(r"(?:Average|Moyenne)\s*=\s*(\d+)\s*ms", out, re.IGNORECASE)
    if m:
        avg = float(m.group(1))
    else:
        m = re.search(r"=\s*([\d.]+)/([\d.]+)/([\d.]+)", out)
        if m:
            avg = float(m.group(2))

    result = {'host': host, 'sent': count, 'loss_percent': loss,
              'avg_ms': avg, 'reachable': proc.returncode == 0}
    if result['reachable']:
        detail = f"loss={loss}%" if loss is not None else "ok"
        if avg is not None:
            detail += f" avg={avg}ms"
        print(f"  {Colors.GREEN}[+] {host} reachable ({detail}){Colors.RESET}")
    else:
        print(f"  {Colors.RED}[!] {host} unreachable{Colors.RESET}")
    return result


def lookup_asn(asn: str) -> Dict[str, Any]:
    """Lookup ASN information."""
    print(f"  {Colors.YELLOW}[~] Querying ASN database...{Colors.RESET}")
    # TODO: Implement actual ASN lookup (whois, RADB, etc.)
    return {
        'asn': asn,
        'name': 'Google LLC',
        'country': 'US',
        'routes': ['8.8.8.0/24', '8.8.4.0/24', '142.250.0.0/16'],
        'peers': ['AS174', 'AS2914', 'AS3356', 'AS6939'],
        'upstreams': [],
        'downstreams': [],
    }


def scan_target(target: str, args: argparse.Namespace) -> Dict[str, Any]:
    """Scan target network."""
    findings = {
        'target': target,
        'scan_type': args.scan_type,
        'ports': parse_ports(args.ports),
        'results': [],
    }

    # TODO: Implement actual port scanning (nmap, masscan, python-nmap, etc.)
    # This is a stub
    ports = findings['ports']
    for port in ports[:20]:  # Limit for demo
        result = scan_port(target, port, args.scan_type)
        if result['state'] == 'open':
            findings['results'].append(result)

    # Additional scans
    if args.banner_grab:
        print(f"  {Colors.YELLOW}[~] Grabbing banners...{Colors.RESET}")
        for result in findings['results']:
            result['banner'] = grab_banner(target, result['port'])

    if args.os_detect:
        print(f"  {Colors.YELLOW}[~] Detecting OS...{Colors.RESET}")
        findings['os'] = detect_os(target)

    if args.service_detect:
        print(f"  {Colors.YELLOW}[~] Detecting services...{Colors.RESET}")
        for result in findings['results']:
            result['service'] = detect_service(target, result['port'])

    return findings


def parse_ports(ports_arg: str) -> List[int]:
    """Parse port specification."""
    if ports_arg == 'top100':
        # Top 100 most common ports
        return [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587, 993, 995,
                1433, 1521, 1723, 2049, 2375, 3128, 3306, 3389, 5432, 5900, 5985, 6379, 7001,
                8000, 8080, 8443, 8888, 9000, 9090, 9200, 9443, 10000, 27017]
    elif ports_arg == 'top1000':
        return list(range(1, 1001))
    elif ports_arg == 'all':
        return list(range(1, 65536))
    else:
        ports = []
        for part in ports_arg.split(','):
            if '-' in part:
                start, end = map(int, part.split('-'))
                ports.extend(range(start, end + 1))
            else:
                ports.append(int(part))
        return ports


def scan_port(target: str, port: int, scan_type: str) -> Dict[str, Any]:
    """Scan a single port (stub)."""
    # TODO: Implement actual port scanning
    import random
    common_open = [22, 80, 443, 3306, 5432, 6379, 8080, 8443]
    state = 'open' if port in common_open else ('filtered' if random.random() > 0.7 else 'closed')
    return {
        'port': port,
        'protocol': 'tcp' if scan_type != 'udp' else 'udp',
        'state': state,
        'service': get_service_name(port),
    }


def get_service_name(port: int) -> str:
    """Get service name for port."""
    services = {
        21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
        80: 'http', 110: 'pop3', 111: 'rpcbind', 135: 'msrpc', 139: 'netbios-ssn',
        143: 'imap', 443: 'https', 445: 'microsoft-ds', 465: 'smtps', 587: 'submission',
        993: 'imaps', 995: 'pop3s', 1433: 'ms-sql-s', 1521: 'oracle', 1723: 'pptp',
        2049: 'nfs', 2375: 'docker', 3128: 'squid', 3306: 'mysql', 3389: 'rdp',
        5432: 'postgresql', 5900: 'vnc', 5985: 'winrm', 6379: 'redis', 7001: 'weblogic',
        8000: 'http-alt', 8080: 'http-proxy', 8443: 'https-alt', 8888: 'sun-answerbook',
        9000: 'cslistener', 9090: 'zeus-admin', 9200: 'elasticsearch', 9443: 'https-alt2',
        10000: 'ndmp', 27017: 'mongodb',
    }
    return services.get(port, 'unknown')


def grab_banner(target: str, port: int) -> str:
    """Grab banner from open port (stub)."""
    # TODO: Implement actual banner grabbing
    banners = {
        22: 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1',
        80: 'nginx/1.18.0 (Ubuntu)',
        443: 'nginx/1.18.0 (Ubuntu)',
        3306: '8.0.33-0ubuntu0.20.04.2',
        5432: 'PostgreSQL 14.5 (Ubuntu 14.5-0ubuntu0.22.04.1)',
    }
    return banners.get(port, '')


def detect_os(target: str) -> Dict[str, Any]:
    """Detect OS (stub)."""
    # TODO: Implement actual OS detection
    return {
        'name': 'Linux',
        'version': '3.x - 4.x',
        'accuracy': 92,
        'details': 'Linux 3.2 - 4.9 (Ubuntu 16.04 - 18.04)',
    }


def detect_service(target: str, port: int) -> Dict[str, Any]:
    """Detect service version (stub)."""
    # TODO: Implement actual service detection
    return {
        'name': get_service_name(port),
        'version': 'unknown',
        'product': 'unknown',
        'extrainfo': '',
    }


def output_results(results: Dict[str, Any], args: argparse.Namespace):
    """Output results in specified format."""
    if args.output:
        if args.format == 'json':
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2, default=str)
        elif args.format == 'txt':
            with open(args.output, 'w') as f:
                f.write(format_results_txt(results))
        elif args.format == 'csv':
            with open(args.output, 'w') as f:
                f.write(format_results_csv(results))
        print(f"\n{Colors.GREEN}[+] Results saved to {args.output}{Colors.RESET}")
    else:
        print(f"\n{Colors.CYAN}{'='*60}{Colors.RESET}")
        print(format_results_txt(results))


def format_results_txt(results: Dict[str, Any]) -> str:
    """Format results as text."""
    lines = []
    for key, data in results.items():
        lines.append(f"\n{key.upper()}:")
        lines.append("-" * 50)
        if isinstance(data, dict):
            lines.append(format_dict(data, indent=2))
        else:
            lines.append(str(data))
    return "\n".join(lines)


def format_results_csv(results: Dict[str, Any]) -> str:
    """Format results as CSV."""
    lines = ['category,key,value']
    for key, data in results.items():
        for k, v in flatten_dict(data).items():
            lines.append(f'"{key}","{k}","{v}"')
    return "\n".join(lines)


def format_dict(d: Dict, indent: int = 0) -> str:
    """Format dictionary as indented text."""
    lines = []
    prefix = " " * indent
    for k, v in d.items():
        if isinstance(v, dict):
            lines.append(f"{prefix}{k}:")
            lines.append(format_dict(v, indent + 2))
        elif isinstance(v, list):
            lines.append(f"{prefix}{k}:")
            for item in v:
                if isinstance(item, dict):
                    lines.append(format_dict(item, indent + 2))
                else:
                    lines.append(f"{prefix}  - {item}")
        else:
            lines.append(f"{prefix}{k}: {v}")
    return "\n".join(lines)


def flatten_dict(d: Dict, parent_key: str = '', sep: str = '.') -> Dict:
    """Flatten nested dictionary."""
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        elif isinstance(v, list):
            items.append((new_key, str(v)))
        else:
            items.append((new_key, v))
    return dict(items)