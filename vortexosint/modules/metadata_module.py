"""
Metadata Module - File Metadata Extraction
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Dict, Any, List
from vortexosint.core.colors import Colors
from vortexosint.core.banner import print_module_banner


def run(args: argparse.Namespace) -> int:
    """Run the Metadata module."""
    print_module_banner("METADATA", "File Metadata Extraction & Analysis")

    files = []

    if args.file:
        files.append(Path(args.file))
    if args.dir:
        dir_path = Path(args.dir)
        if dir_path.exists():
            if args.recursive:
                files.extend(dir_path.rglob('*'))
            else:
                files.extend(dir_path.glob('*'))
        else:
            print(f"{Colors.RED}[!] Directory not found: {args.dir}{Colors.RESET}")
            return 1

    if not files:
        print(f"{Colors.RED}[!] No files specified. Use --file or --dir{Colors.RESET}")
        return 1

    # Filter to only files
    files = [f for f in files if f.is_file()]

    if not files:
        print(f"{Colors.YELLOW}[!] No files found{Colors.RESET}")
        return 0

    print(f"\n{Colors.CYAN}[*] Analyzing {len(files)} file(s)...{Colors.RESET}")

    results = {}
    for file_path in files:
        print(f"\n{Colors.YELLOW}[~] Analyzing: {file_path}{Colors.RESET}")
        result = analyze_file(file_path, args)
        results[str(file_path)] = result

    output_results(results, args)
    return 0


def analyze_file(file_path: Path, args: argparse.Namespace) -> Dict[str, Any]:
    """Analyze a single file."""
    result = {
        'file': str(file_path),
        'size': file_path.stat().st_size,
        'modified': file_path.stat().st_mtime,
        'extension': file_path.suffix.lower(),
        'mime_type': get_mime_type(file_path),
        'findings': {}
    }

    findings = {}

    # Basic file info
    findings['basic'] = get_basic_info(file_path)

    # EXIF data
    if args.exif or file_path.suffix.lower() in ['.jpg', '.jpeg', '.tiff', '.tif', '.png', '.webp']:
        findings['exif'] = extract_exif(file_path)

    # GPS data
    if args.gps or file_path.suffix.lower() in ['.jpg', '.jpeg', '.tiff', '.tif']:
        findings['gps'] = extract_gps(file_path)

    # Strings extraction
    if args.strings:
        findings['strings'] = extract_strings(file_path)

    # Hashes
    findings['hashes'] = calculate_hashes(file_path)

    # File-specific analysis
    if file_path.suffix.lower() == '.pdf':
        findings['pdf'] = analyze_pdf(file_path)
    elif file_path.suffix.lower() in ['.doc', '.docx']:
        findings['office'] = analyze_office(file_path)
    elif file_path.suffix.lower() in ['.xls', '.xlsx']:
        findings['office'] = analyze_office(file_path)
    elif file_path.suffix.lower() in ['.ppt', '.pptx']:
        findings['office'] = analyze_office(file_path)

    result['findings'] = findings
    return result


def get_mime_type(file_path: Path) -> str:
    """Get MIME type of file."""
    import mimetypes
    mime, _ = mimetypes.guess_type(str(file_path))
    return mime or 'application/octet-stream'


def get_basic_info(file_path: Path) -> Dict[str, Any]:
    """Get basic file information."""
    import datetime
    stat = file_path.stat()
    return {
        'name': file_path.name,
        'path': str(file_path),
        'size': stat.st_size,
        'size_human': format_size(stat.st_size),
        'created': datetime.datetime.fromtimestamp(stat.st_ctime).isoformat(),
        'modified': datetime.datetime.fromtimestamp(stat.st_mtime).isoformat(),
        'accessed': datetime.datetime.fromtimestamp(stat.st_atime).isoformat(),
        'extension': file_path.suffix,
        'mime_type': get_mime_type(file_path),
    }


def format_size(size: int) -> str:
    """Format file size human-readable."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024:
            return f"{size:.2f} {unit}"
        size /= 1024
    return f"{size:.2f} PB"


def extract_exif(file_path: Path) -> Dict[str, Any]:
    """Extract EXIF data from image."""
    print(f"  {Colors.YELLOW}[~] Extracting EXIF...{Colors.RESET}")
    # TODO: Implement actual EXIF extraction (PIL/Pillow, exifread, etc.)
    try:
        # Stub
        return {
            'has_exif': True,
            'camera': {
                'make': 'Unknown',
                'model': 'Unknown',
                'software': 'Unknown',
            },
            'datetime': 'Unknown',
            'settings': {
                'aperture': 'Unknown',
                'shutter_speed': 'Unknown',
                'iso': 'Unknown',
                'focal_length': 'Unknown',
            },
            'raw_tags': {},
        }
    except Exception as e:
        return {'error': str(e), 'has_exif': False}


def extract_gps(file_path: Path) -> Dict[str, Any]:
    """Extract GPS coordinates from image."""
    print(f"  {Colors.YELLOW}[~] Extracting GPS...{Colors.RESET}")
    # TODO: Implement actual GPS extraction
    return {
        'has_gps': False,
        'latitude': None,
        'longitude': None,
        'altitude': None,
        'map_link': None,
    }


def extract_strings(file_path: Path) -> List[str]:
    """Extract strings from binary file."""
    print(f"  {Colors.YELLOW}[~] Extracting strings...{Colors.RESET}")
    # TODO: Implement actual strings extraction
    strings = []
    try:
        with open(file_path, 'rb') as f:
            data = f.read(1024 * 1024)  # First 1MB
        # Simple ASCII string extraction
        current = ''
        for byte in data:
            if 32 <= byte <= 126:
                current += chr(byte)
            else:
                if len(current) >= 4:
                    strings.append(current)
                current = ''
        if len(current) >= 4:
            strings.append(current)
    except Exception:
        pass
    return strings[:100]  # Limit to 100 strings


def calculate_hashes(file_path: Path) -> Dict[str, str]:
    """Calculate file hashes."""
    print(f"  {Colors.YELLOW}[~] Calculating hashes...{Colors.RESET}")
    import hashlib

    hashes = {}
    algorithms = ['md5', 'sha1', 'sha256', 'sha512']

    try:
        with open(file_path, 'rb') as f:
            data = f.read()

        for algo in algorithms:
            h = hashlib.new(algo)
            h.update(data)
            hashes[algo] = h.hexdigest()
    except Exception as e:
        hashes['error'] = str(e)

    return hashes


def analyze_pdf(file_path: Path) -> Dict[str, Any]:
    """Analyze PDF file."""
    print(f"  {Colors.YELLOW}[~] Analyzing PDF...{Colors.RESET}")
    # TODO: Implement actual PDF analysis (PyPDF2, pdfplumber, etc.)
    return {
        'pages': 0,
        'title': '',
        'author': '',
        'subject': '',
        'creator': '',
        'producer': '',
        'creation_date': '',
        'modification_date': '',
        'encrypted': False,
        'javascript': False,
        'embedded_files': [],
    }


def analyze_office(file_path: Path) -> Dict[str, Any]:
    """Analyze Office document."""
    print(f"  {Colors.YELLOW}[~] Analyzing Office document...{Colors.RESET}")
    # TODO: Implement actual Office analysis (python-docx, openpyxl, etc.)
    return {
        'title': '',
        'author': '',
        'subject': '',
        'keywords': '',
        'comments': '',
        'created': '',
        'modified': '',
        'last_modified_by': '',
        'revision': 0,
        'application': '',
        'hidden_data': False,
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
    for file_path, data in results.items():
        lines.append(f"\nFile: {file_path}")
        lines.append("-" * 50)
        basic = data['findings'].get('basic', {})
        lines.append(f"Size: {basic.get('size_human', 'N/A')} ({data['size']} bytes)")
        lines.append(f"Type: {data['mime_type']}")
        lines.append(f"Modified: {data['modified']}")
        lines.append("")
        lines.append(format_dict(data['findings'], indent=2))
    return "\n".join(lines)


def format_results_csv(results: Dict[str, Any]) -> str:
    """Format results as CSV."""
    lines = ['file,key,value']
    for file_path, data in results.items():
        for key, value in flatten_dict(data['findings']).items():
            lines.append(f'"{file_path}","{key}","{value}"')
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