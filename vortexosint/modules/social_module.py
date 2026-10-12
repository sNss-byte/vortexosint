"""
Social Module - Social Media Intelligence
"""

import argparse
import json
import sys
from typing import Dict, Any, List
from vortexosint.core.colors import Colors
from vortexosint.core.banner import print_module_banner


def run(args: argparse.Namespace) -> int:
    """Run the Social module."""
    print_module_banner("SOCIAL", "Social Media Intelligence & Username Enumeration")

    targets = []
    if args.username:
        targets.append(('username', args.username))
    if args.email:
        targets.append(('email', args.email))
    if args.phone:
        targets.append(('phone', args.phone))

    if not targets:
        print(f"{Colors.RED}[!] No target specified. Use --username, --email, or --phone{Colors.RESET}")
        return 1

    results = {}

    for target_type, target_value in targets:
        print(f"\n{Colors.CYAN}[*] Investigating {target_type}: {Colors.BOLD}{target_value}{Colors.RESET}")
        result = investigate_target(target_type, target_value, args)
        results[target_value] = result

    # Check availability if requested
    if args.check_availability and args.username:
        results['availability'] = check_availability(args.username, args)

    output_results(results, args)
    return 0


def investigate_target(target_type: str, target_value: str, args: argparse.Namespace) -> Dict[str, Any]:
    """Investigate a single target based on type."""
    result = {
        'target': target_value,
        'type': target_type,
        'findings': {}
    }

    platforms = get_platforms(args.platforms)

    if target_type == 'username':
        result['findings'] = investigate_username(target_value, platforms)
    elif target_type == 'email':
        result['findings'] = investigate_email(target_value, platforms)
    elif target_type == 'phone':
        result['findings'] = investigate_phone(target_value, platforms)

    return result


def investigate_username(username: str, platforms: List[str]) -> Dict[str, Any]:
    """Investigate username across platforms."""
    findings = {
        'username': username,
        'platforms': {},
        'total_found': 0,
        'profiles': [],
    }

    for platform in platforms:
        print(f"  {Colors.YELLOW}[~] Checking {platform}...{Colors.RESET}")
        result = check_username_platform(username, platform)
        findings['platforms'][platform] = result
        if result.get('found'):
            findings['total_found'] += 1
            findings['profiles'].append({
                'platform': platform,
                'url': result.get('url'),
                'data': result.get('profile_data', {}),
            })

    return findings


def investigate_email(email: str, platforms: List[str]) -> Dict[str, Any]:
    """Investigate email across platforms."""
    findings = {
        'email': email,
        'platforms': {},
        'total_found': 0,
        'gravatar': check_gravatar(email),
        'breaches': check_breaches(email),
    }

    for platform in platforms:
        print(f"  {Colors.YELLOW}[~] Checking {platform} for email...{Colors.RESET}")
        result = check_email_platform(email, platform)
        findings['platforms'][platform] = result
        if result.get('found'):
            findings['total_found'] += 1

    return findings


def investigate_phone(phone: str, platforms: List[str]) -> Dict[str, Any]:
    """Investigate phone across platforms."""
    findings = {
        'phone': phone,
        'platforms': {},
        'total_found': 0,
    }

    for platform in platforms:
        print(f"  {Colors.YELLOW}[~] Checking {platform} for phone...{Colors.RESET}")
        result = check_phone_platform(phone, platform)
        findings['platforms'][platform] = result
        if result.get('found'):
            findings['total_found'] += 1

    return findings


def check_availability(username: str, args: argparse.Namespace) -> Dict[str, Any]:
    """Check username availability on platforms."""
    print(f"\n{Colors.CYAN}[*] Checking availability for: {Colors.BOLD}{username}{Colors.RESET}")
    platforms = get_platforms(args.platforms)
    availability = {}

    for platform in platforms:
        print(f"  {Colors.YELLOW}[~] Checking {platform}...{Colors.RESET}")
        # TODO: Implement actual availability check
        availability[platform] = {
            'available': True,  # Stub
            'url': f'https://{platform}.com/{username}',
        }

    return availability


# --- Helper functions (stubs for actual implementation) ---

def get_platforms(platforms_arg: str) -> List[str]:
    """Get list of platforms to check."""
    all_platforms = [
        # Code & Dev
        'github', 'gitlab', 'bitbucket', 'sourceforge', 'codepen', 'replit',
        'stackoverflow', 'dev.to', 'hashnode', 'medium', 'hackernews',
        # Social Media
        'twitter', 'instagram', 'facebook', 'linkedin', 'reddit', 'pinterest',
        'tiktok', 'snapchat', 'tumblr', 'vk', 'ok',
        # Video & Streaming
        'youtube', 'twitch', 'vimeo', 'dailymotion', 'rumble', 'odysee',
        # Audio
        'soundcloud', 'spotify', 'bandcamp', 'mixcloud', 'audiomack',
        # Creative
        'dribbble', 'behance', 'flickr', '500px', 'deviantart', 'artstation',
        # Communication
        'telegram', 'discord', 'signal', 'slack', 'matrix',
        # Gaming
        'steam', 'epicgames', 'xbox', 'playstation', 'nintendo', 'battlenet',
        'origin', 'gog', 'itch.io',
        # Professional
        'angellist', 'crunchbase', 'producthunt', 'wellfound',
        # Crypto
        'etherscan', 'blockchain.com', 'coinbase', 'binance',
        # Other
        'patreon', 'ko-fi', 'buymeacoffee', 'substack', 'ghost',
        'keybase', 'mastodon', 'lemmy', 'truthsocial', 'gab',
    ]

    if platforms_arg == 'all':
        return all_platforms
    return [p.strip().lower() for p in platforms_arg.split(',')]


def check_username_platform(username: str, platform: str) -> Dict[str, Any]:
    """Check username on a specific platform."""
    # TODO: Implement actual platform checks (HTTP requests, APIs, etc.)
    urls = {
        'github': f'https://github.com/{username}',
        'gitlab': f'https://gitlab.com/{username}',
        'twitter': f'https://twitter.com/{username}',
        'instagram': f'https://instagram.com/{username}',
        'linkedin': f'https://linkedin.com/in/{username}',
        'reddit': f'https://reddit.com/user/{username}',
        'youtube': f'https://youtube.com/@{username}',
        'twitch': f'https://twitch.tv/{username}',
        'tiktok': f'https://tiktok.com/@{username}',
        'pinterest': f'https://pinterest.com/{username}',
        'facebook': f'https://facebook.com/{username}',
        'medium': f'https://medium.com/@{username}',
        'dev.to': f'https://dev.to/{username}',
        'stackoverflow': f'https://stackoverflow.com/users/{username}',
        'telegram': f'https://t.me/{username}',
        'discord': f'https://discord.com/users/{username}',
        'steam': f'https://steamcommunity.com/id/{username}',
        'soundcloud': f'https://soundcloud.com/{username}',
        'spotify': f'https://open.spotify.com/user/{username}',
        'dribbble': f'https://dribbble.com/{username}',
        'behance': f'https://behance.net/{username}',
        'patreon': f'https://patreon.com/{username}',
        'keybase': f'https://keybase.io/{username}',
        'mastodon': f'https://mastodon.social/@{username}',
    }

    url = urls.get(platform, f'https://{platform}.com/{username}')

    # Stub - would actually check HTTP status
    return {
        'platform': platform,
        'url': url,
        'found': False,  # Would be True if account exists
        'profile_data': {},
        'error': None,
    }


def check_email_platform(email: str, platform: str) -> Dict[str, Any]:
    """Check email on a specific platform."""
    # TODO: Implement actual email checks
    return {
        'platform': platform,
        'found': False,
        'profile_data': {},
    }


def check_phone_platform(phone: str, platform: str) -> Dict[str, Any]:
    """Check phone on a specific platform."""
    # TODO: Implement actual phone checks
    return {
        'platform': platform,
        'found': False,
        'profile_data': {},
    }


def check_gravatar(email: str) -> Dict[str, Any]:
    """Check Gravatar for email."""
    print(f"  {Colors.YELLOW}[~] Checking Gravatar...{Colors.RESET}")
    # TODO: Implement actual Gravatar check
    import hashlib
    email_hash = hashlib.md5(email.lower().strip().encode()).hexdigest()
    return {
        'exists': False,
        'profile_url': f'https://gravatar.com/{email_hash}',
        'avatar_url': f'https://gravatar.com/avatar/{email_hash}',
    }


def check_breaches(email: str) -> Dict[str, Any]:
    """Check email in breach databases."""
    print(f"  {Colors.YELLOW}[~] Checking breach databases...{Colors.RESET}")
    # TODO: Implement actual breach check (HaveIBeenPwned API)
    return {
        'breached': False,
        'breach_count': 0,
        'breaches': [],
        'paste_count': 0,
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