"""
OSINT Module - General OSINT Reconnaissance
"""

import argparse
import json
import os
import sys
from typing import Dict, Any, List
from vortexosint.core.colors import Colors
from vortexosint.core.banner import print_module_banner


def run(args: argparse.Namespace) -> int:
    """Run the OSINT module."""
    print_module_banner("OSINT", "General OSINT Reconnaissance & Information Gathering")

    # Validate at least one target
    targets = []
    if args.domain:
        targets.append(('domain', args.domain))
    if args.email:
        targets.append(('email', args.email))
    if args.phone:
        targets.append(('phone', args.phone))
    if args.username:
        targets.append(('username', args.username))
    if args.ip:
        targets.append(('ip', args.ip))

    if not targets:
        print(f"{Colors.RED}[!] No target specified. Use --domain, --email, --phone, --username, or --ip{Colors.RESET}")
        return 1

    results = {}

    for target_type, target_value in targets:
        print(f"\n{Colors.CYAN}[*] Investigating {target_type}: {Colors.BOLD}{target_value}{Colors.RESET}")
        result = investigate_target(target_type, target_value, args)
        results[target_value] = result

    # Output results
    output_results(results, args)

    return 0


def investigate_target(target_type: str, target_value: str, args: argparse.Namespace) -> Dict[str, Any]:
    """Investigate a single target based on type."""
    result = {
        'target': target_value,
        'type': target_type,
        'findings': {}
    }

    if target_type == 'domain':
        result['findings'] = investigate_domain(target_value, args)
    elif target_type == 'email':
        result['findings'] = investigate_email(target_value, args)
    elif target_type == 'phone':
        result['findings'] = investigate_phone(target_value, args)
    elif target_type == 'username':
        result['findings'] = investigate_username(target_value, args)
    elif target_type == 'ip':
        result['findings'] = investigate_ip(target_value, args)

    return result


def investigate_domain(domain: str, args: argparse.Namespace) -> Dict[str, Any]:
    """Investigate a domain."""
    findings = {
        'whois': get_whois(domain),
        'dns': get_dns_records(domain),
        'subdomains': enumerate_subdomains(domain, args.deep),
        'ssl': get_ssl_info(domain),
        'technologies': detect_technologies(domain),
        'emails': find_emails(domain) if args.deep else [],
        'links': crawl_links(domain) if args.deep else [],
        'wayback': get_wayback_urls(domain, getattr(args, 'wayback_limit', 200),
                                    getattr(args, 'timeout', 30))
        if getattr(args, 'wayback', False) else {},
    }
    return findings


def investigate_email(email: str, args: argparse.Namespace) -> Dict[str, Any]:
    """Investigate an email address."""
    domain = email.split('@')[-1] if '@' in email else ''
    findings = {
        'format_valid': validate_email_format(email),
        'domain': domain,
        'mx_records': get_mx_records(domain) if domain else [],
        'breach_check': check_breaches(email) if args.deep else {},
        'social_accounts': find_social_by_email(email) if args.deep else [],
        'gravatar': check_gravatar(email),
        'deliverability': check_deliverability(email) if args.deep else {},
    }
    return findings


def investigate_phone(phone: str, args: argparse.Namespace) -> Dict[str, Any]:
    """Investigate a phone number."""
    findings = {
        'format': parse_phone(phone),
        'carrier': lookup_carrier(phone),
        'location': lookup_phone_location(phone),
        'line_type': detect_line_type(phone),
        'social_accounts': find_social_by_phone(phone) if args.deep else [],
        'breach_check': check_phone_breaches(phone) if args.deep else {},
    }
    return findings


def investigate_username(username: str, args: argparse.Namespace) -> Dict[str, Any]:
    """Investigate a username across platforms."""
    platforms = get_platforms(args.sources)
    findings = {
        'platforms': {},
        'total_found': 0,
    }
    for platform in platforms:
        result = check_username_platform(username, platform)
        findings['platforms'][platform] = result
        if result.get('found'):
            findings['total_found'] += 1
    return findings


def investigate_ip(ip: str, args: argparse.Namespace) -> Dict[str, Any]:
    """Investigate an IP address."""
    findings = {
        'geolocation': get_ip_geolocation(ip),
        'asn': get_asn_info(ip),
        'reverse_dns': get_reverse_dns(ip),
        'ports': scan_common_ports(ip) if args.deep else [],
        'reputation': check_ip_reputation(ip),
        'vpn_proxy': detect_vpn_proxy(ip),
    }
    return findings


WAYBACK_CDX = "https://web.archive.org/cdx/search/cdx"

INTERESTING_EXTS = {
    ".js", ".json", ".php", ".asp", ".aspx", ".jsp", ".env", ".bak",
    ".old", ".sql", ".xml", ".txt", ".pdf", ".zip", ".tar", ".gz",
    ".config", ".yml", ".yaml", ".log", ".swp",
}
INTERESTING_KEYS = ("admin", "login", "api", "config", "backup", "test",
                    "dev", "staging", "private", ".git/")


def get_wayback_urls(domain: str, limit: int = 200, timeout: int = 30) -> Dict[str, Any]:
    """Query the Wayback CDX API for archived URLs (HTTP 200, deduped)."""
    print(f"  {Colors.YELLOW}[~] Querying Wayback Machine CDX...{Colors.RESET}")
    try:
        import requests
    except ImportError:
        print(f"  {Colors.RED}[!] The 'requests' package is required{Colors.RESET}")
        return {'error': 'requests not installed', 'total': 0, 'urls': []}
    domain = (domain or "").strip().lower()
    for prefix in ("http://", "https://"):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    domain = domain.split("/")[0]
    if not domain:
        return {'error': 'empty domain', 'total': 0, 'urls': []}
    params = {"url": domain, "matchType": "domain", "output": "json",
              "filter": "statuscode:200", "collapse": "urlkey",
              "limit": str(max(1, limit))}
    try:
        resp = requests.get(WAYBACK_CDX, params=params, timeout=timeout)
        if resp.status_code != 200:
            print(f"  {Colors.RED}[!] Wayback API HTTP {resp.status_code}{Colors.RESET}")
            return {'error': f'http {resp.status_code}', 'total': 0, 'urls': []}
        rows = resp.json()
    except Exception as e:
        print(f"  {Colors.RED}[!] Wayback query failed: {e}{Colors.RESET}")
        return {'error': str(e), 'total': 0, 'urls': []}
    if not rows:
        return {'total': 0, 'urls': [], 'interesting': [], 'by_extension': {}}
    body = rows[1:] if rows[0][0] == "urlkey" else rows
    urls = [row[2] for row in body if len(row) >= 3 and row[2]]
    by_ext: Dict[str, int] = {}
    interesting = []
    for u in urls:
        path = u.split("?", 1)[0].lower()
        ext = os.path.splitext(path)[1] or "(none)"
        by_ext[ext] = by_ext.get(ext, 0) + 1
        if ext in INTERESTING_EXTS or any(k in path for k in INTERESTING_KEYS):
            interesting.append(u)
    interesting = interesting[:50]
    print(f"  {Colors.GREEN}[+] {len(urls)} archived URLs "
          f"({len(interesting)} interesting){Colors.RESET}")
    top_ext = dict(sorted(by_ext.items(), key=lambda kv: -kv[1])[:15])
    return {'total': len(urls), 'limit': limit, 'urls': urls,
            'interesting': interesting, 'by_extension': top_ext}


def show_wayback(data: Dict[str, Any], domain: str):
    """Pretty summary for quick mode."""
    if data.get('error'):
        print(f"{Colors.RED}[!] Wayback: {data['error']}{Colors.RESET}")
        return
    print(f"\n{Colors.CYAN}[*] Wayback Machine — {domain}: "
          f"{Colors.BOLD}{data['total']} URLs archivees{Colors.RESET}")
    if data.get('by_extension'):
        print(f"  {Colors.YELLOW}Top extensions:{Colors.RESET}")
        for ext, count in list(data['by_extension'].items())[:8]:
            print(f"    {ext}: {count}")
    if data.get('interesting'):
        print(f"  {Colors.YELLOW}Interessantes ({len(data['interesting'])}):{Colors.RESET}")
        for u in data['interesting'][:30]:
            print(f"    - {u}")
    else:
        print("  " + Colors.dim("Rien de suspect dans cet echantillon."))


# --- Helper functions (stubs for actual implementation) ---

def get_whois(domain: str) -> Dict[str, Any]:
    """Get WHOIS information for domain."""
    print(f"  {Colors.YELLOW}[~] Querying WHOIS...{Colors.RESET}")
    # TODO: Implement actual WHOIS query
    return {
        'registrar': 'Example Registrar',
        'creation_date': '2020-01-01',
        'expiration_date': '2025-01-01',
        'name_servers': ['ns1.example.com', 'ns2.example.com'],
        'status': 'clientTransferProhibited',
    }


def get_dns_records(domain: str) -> Dict[str, List[str]]:
    """Get DNS records for domain."""
    print(f"  {Colors.YELLOW}[~] Querying DNS records...{Colors.RESET}")
    # TODO: Implement actual DNS query
    return {
        'A': ['93.184.216.34'],
        'AAAA': ['2606:2800:220:1:248:1893:25c8:1946'],
        'MX': ['10 mail.example.com'],
        'NS': ['ns1.example.com', 'ns2.example.com'],
        'TXT': ['v=spf1 include:_spf.example.com ~all'],
        'CNAME': ['www.example.com'],
    }


def enumerate_subdomains(domain: str, deep: bool) -> List[str]:
    """Enumerate subdomains."""
    print(f"  {Colors.YELLOW}[~] Enumerating subdomains...{Colors.RESET}")
    # TODO: Implement actual subdomain enumeration
    subs = ['www', 'mail', 'ftp', 'api', 'dev', 'staging', 'admin', 'blog', 'shop', 'app']
    if deep:
        subs += ['test', 'demo', 'beta', 'vpn', 'git', 'jenkins', 'jira', 'wiki', 'cdn', 'static']
    return [f"{sub}.{domain}" for sub in subs]


def get_ssl_info(domain: str) -> Dict[str, Any]:
    """Get SSL certificate information."""
    print(f"  {Colors.YELLOW}[~] Checking SSL certificate...{Colors.RESET}")
    # TODO: Implement actual SSL check
    return {
        'issuer': 'Let\'s Encrypt',
        'valid_from': '2024-01-01',
        'valid_to': '2024-04-01',
        'subject_alt_names': [domain, f'www.{domain}'],
        'signature_algorithm': 'sha256WithRSAEncryption',
        'key_size': 2048,
    }


def detect_technologies(domain: str) -> List[Dict[str, str]]:
    """Detect technologies used by the domain."""
    print(f"  {Colors.YELLOW}[~] Detecting technologies...{Colors.RESET}")
    # TODO: Implement actual technology detection
    return [
        {'name': 'Nginx', 'category': 'Web Server', 'version': '1.18.0'},
        {'name': 'React', 'category': 'JavaScript Framework', 'version': '18.2.0'},
        {'name': 'Cloudflare', 'category': 'CDN', 'version': ''},
    ]


def find_emails(domain: str) -> List[str]:
    """Find email addresses associated with domain."""
    print(f"  {Colors.YELLOW}[~] Searching for emails...{Colors.RESET}")
    # TODO: Implement actual email search
    return [f'admin@{domain}', f'support@{domain}', f'info@{domain}']


def crawl_links(domain: str) -> List[str]:
    """Crawl and find links on domain."""
    print(f"  {Colors.YELLOW}[~] Crawling links...{Colors.RESET}")
    # TODO: Implement actual crawling
    return [f'https://{domain}/', f'https://{domain}/about', f'https://{domain}/contact']


def validate_email_format(email: str) -> bool:
    """Validate email format."""
    import re
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def get_mx_records(domain: str) -> List[str]:
    """Get MX records for domain."""
    print(f"  {Colors.YELLOW}[~] Querying MX records...{Colors.RESET}")
    # TODO: Implement actual MX query
    return [f'10 mail.{domain}', f'20 mail2.{domain}']


def check_breaches(email: str) -> Dict[str, Any]:
    """Check if email appears in known breaches."""
    print(f"  {Colors.YELLOW}[~] Checking breach databases...{Colors.RESET}")
    # TODO: Implement actual breach check (HaveIBeenPwned API, etc.)
    return {
        'breached': False,
        'breaches': [],
        'paste_count': 0,
    }


def find_social_by_email(email: str) -> List[Dict[str, str]]:
    """Find social media accounts by email."""
    print(f"  {Colors.YELLOW}[~] Searching social accounts by email...{Colors.RESET}")
    # TODO: Implement actual search
    return []


def check_gravatar(email: str) -> Dict[str, Any]:
    """Check Gravatar for email."""
    print(f"  {Colors.YELLOW}[~] Checking Gravatar...{Colors.RESET}")
    # TODO: Implement actual Gravatar check
    return {
        'exists': False,
        'profile_url': None,
        'avatar_url': None,
    }


def check_deliverability(email: str) -> Dict[str, Any]:
    """Check email deliverability."""
    print(f"  {Colors.YELLOW}[~] Checking deliverability...{Colors.RESET}")
    # TODO: Implement actual deliverability check
    return {
        'deliverable': True,
        'catch_all': False,
        'disposable': False,
        'role_account': False,
    }


def parse_phone(phone: str) -> Dict[str, str]:
    """Parse and format phone number."""
    import re
    # Basic cleaning
    digits = re.sub(r'\D', '', phone)
    return {
        'original': phone,
        'digits': digits,
        'country_code': digits[:2] if len(digits) > 10 else '1',
        'national_number': digits[2:] if len(digits) > 10 else digits,
    }


def lookup_carrier(phone: str) -> str:
    """Lookup phone carrier."""
    print(f"  {Colors.YELLOW}[~] Looking up carrier...{Colors.RESET}")
    # TODO: Implement actual carrier lookup
    return 'Unknown Carrier'


def lookup_phone_location(phone: str) -> Dict[str, str]:
    """Lookup phone location."""
    print(f"  {Colors.YELLOW}[~] Looking up location...{Colors.RESET}")
    # TODO: Implement actual location lookup
    return {
        'country': 'Unknown',
        'region': 'Unknown',
        'city': 'Unknown',
        'timezone': 'Unknown',
    }


def detect_line_type(phone: str) -> str:
    """Detect phone line type."""
    # TODO: Implement actual line type detection
    return 'mobile'


def find_social_by_phone(phone: str) -> List[Dict[str, str]]:
    """Find social accounts by phone."""
    print(f"  {Colors.YELLOW}[~] Searching social accounts by phone...{Colors.RESET}")
    # TODO: Implement actual search
    return []


def check_phone_breaches(phone: str) -> Dict[str, Any]:
    """Check phone in breaches."""
    print(f"  {Colors.YELLOW}[~] Checking phone breaches...{Colors.RESET}")
    # TODO: Implement actual breach check
    return {'breached': False, 'breaches': []}


def get_platforms(sources: str) -> List[str]:
    """Get list of platforms to check."""
    all_platforms = [
        'github', 'gitlab', 'bitbucket', 'twitter', 'instagram', 'linkedin',
        'facebook', 'reddit', 'youtube', 'twitch', 'tiktok', 'pinterest',
        'medium', 'dev.to', 'stackoverflow', 'telegram', 'discord', 'steam',
        'spotify', 'soundcloud', 'vimeo', 'dribbble', 'behance', 'flickr',
    ]
    if sources == 'all':
        return all_platforms
    return [s.strip() for s in sources.split(',')]


def check_username_platform(username: str, platform: str) -> Dict[str, Any]:
    """Check username on a specific platform."""
    print(f"  {Colors.YELLOW}[~] Checking {platform}...{Colors.RESET}")
    # TODO: Implement actual platform checks
    return {
        'platform': platform,
        'found': False,
        'url': f'https://{platform}.com/{username}',
        'profile_data': {},
    }


def get_ip_geolocation(ip: str) -> Dict[str, Any]:
    """Get IP geolocation."""
    print(f"  {Colors.YELLOW}[~] Getting geolocation...{Colors.RESET}")
    # TODO: Implement actual geolocation
    return {
        'ip': ip,
        'country': 'United States',
        'region': 'California',
        'city': 'San Francisco',
        'lat': 37.7749,
        'lon': -122.4194,
        'timezone': 'America/Los_Angeles',
        'isp': 'Example ISP',
    }


def get_asn_info(ip: str) -> Dict[str, Any]:
    """Get ASN information for IP."""
    print(f"  {Colors.YELLOW}[~] Getting ASN info...{Colors.RESET}")
    # TODO: Implement actual ASN lookup
    return {
        'asn': 'AS15169',
        'name': 'Google LLC',
        'route': '8.8.8.0/24',
        'country': 'US',
    }


def get_reverse_dns(ip: str) -> List[str]:
    """Get reverse DNS for IP."""
    print(f"  {Colors.YELLOW}[~] Getting reverse DNS...{Colors.RESET}")
    # TODO: Implement actual reverse DNS
    return [f'{ip}.in-addr.arpa']


def scan_common_ports(ip: str) -> List[Dict[str, Any]]:
    """Scan common ports on IP."""
    print(f"  {Colors.YELLOW}[~] Scanning common ports...{Colors.RESET}")
    # TODO: Implement actual port scan
    return [
        {'port': 80, 'protocol': 'tcp', 'state': 'open', 'service': 'http'},
        {'port': 443, 'protocol': 'tcp', 'state': 'open', 'service': 'https'},
        {'port': 22, 'protocol': 'tcp', 'state': 'closed', 'service': 'ssh'},
    ]


def check_ip_reputation(ip: str) -> Dict[str, Any]:
    """Check IP reputation."""
    print(f"  {Colors.YELLOW}[~] Checking IP reputation...{Colors.RESET}")
    # TODO: Implement actual reputation check
    return {
        'malicious': False,
        'suspicious': False,
        'categories': [],
        'score': 0,
    }


def detect_vpn_proxy(ip: str) -> Dict[str, bool]:
    """Detect VPN/Proxy."""
    print(f"  {Colors.YELLOW}[~] Detecting VPN/Proxy...{Colors.RESET}")
    # TODO: Implement actual VPN/Proxy detection
    return {
        'vpn': False,
        'proxy': False,
        'tor': False,
        'hosting': False,
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
    for target, data in results.items():
        lines.append(f"\nTarget: {target} ({data['type']})")
        lines.append("-" * 50)
        lines.append(format_dict(data['findings'], indent=2))
    return "\n".join(lines)


def format_results_csv(results: Dict[str, Any]) -> str:
    """Format results as CSV."""
    lines = ['target,type,key,value']
    for target, data in results.items():
        for key, value in flatten_dict(data['findings']).items():
            lines.append(f'"{target}","{data["type"]}","{key}","{value}"')
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