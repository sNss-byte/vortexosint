# VortexOSINT

<div align="center">

```
    ██╗   ██╗███████╗███████╗████████╗███████╗███╗   ███╗
    ██║   ██║██╔════╝██╔════╝╚══██╔══╝██╔════╝████╗ ████║
    ██║   ██║█████╗  ███████╗   ██║   █████╗  ██╔████╔██║
    ╚██╗ ██╔╝██╔══╝  ╚════██║   ██║   ██╔══╝  ██║╚██╔╝██║
     ╚████╔╝ ███████╗███████║   ██║   ███████╗██║ ╚═╝ ██║
      ╚═══╝  ╚══════╝╚══════╝   ╚═╝   ╚══════╝╚═╝     ╚═╝
```

**Multi-tool OSINT/GEOSINT Reconnaissance Framework**

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/Version-1.0.0-orange.svg)](https://github.com/vortexosint/vortexosint/releases)

</div>

---

## 🎯 Overview

VortexOSINT is a comprehensive command-line intelligence gathering toolkit designed for OSINT (Open Source Intelligence), GEOSINT (Geospatial Intelligence), and related reconnaissance activities. Built with a modular architecture, it provides specialized modules for different intelligence domains.

## ✨ Features

| Module | Description |
|--------|-------------|
| **OSINT** | Domain, email, phone, username, IP reconnaissance |
| **GEOSINT** | IP geolocation, coordinate analysis, address geocoding, WiFi/cell tower lookup |
| **NETWORK** | Port scanning, service detection, OS fingerprinting, ASN lookup |
| **CRYPTO** | Blockchain address analysis, transaction tracking, entity profiling |
| **SOCIAL** | Username enumeration across 50+ platforms, email/phone lookup |
| **METADATA** | File metadata extraction (EXIF, GPS, PDF, Office docs, hashes) |

## 🚀 Installation

### Quick Install
```bash
pip install vortexosint
```

### From Source
```bash
git clone https://github.com/vortexosint/vortexosint.git
cd vortexosint
pip install -e .
```

### With Full Features
```bash
pip install vortexosint[full]
```

## 📖 Usage

### Global Options
```bash
vortexosint --help                 # Show help
vortexosint --version              # Show version
vortexosint --no-banner            # Disable ASCII banner
vortexosint --no-color             # Disable colored output
vortexosint -V                     # Verbose output
vortexosint -o results.json        # Save output to file
vortexosint --format json|txt|csv  # Output format
```

### OSINT Module
```bash
# Domain reconnaissance
vortexosint osint --domain example.com
vortexosint osint -d example.com --deep

# Email investigation
vortexosint osint --email admin@example.com
vortexosint osint -e admin@example.com --deep

# Phone investigation
vortexosint osint --phone "+33 1 23 45 67 89"

# Username enumeration
vortexosint osint --username johndoe
vortexosint osint -u johndoe --deep

# IP investigation
vortexosint osint --ip 8.8.8.8
```

### GEOSINT Module
```bash
# IP geolocation
vortexosint geosint --ip 8.8.8.8
vortexosint geosint -i 8.8.8.8 --provider ipapi

# Reverse geocoding (coordinates to address)
vortexosint geosint --coords "48.8566,2.3522"
vortexosint geosint -c "48.8566,2.3522" --radius 5000

# Forward geocoding (address to coordinates)
vortexosint geosint --address "1600 Pennsylvania Ave NW"
vortexosint geosint -a "1600 Pennsylvania Ave NW" --map

# WiFi BSSID lookup (wardriving)
vortexosint geosint --wifi "AA:BB:CC:DD:EE:FF"
vortexosint geosint -w "AA:BB:CC:DD:EE:FF"

# Cell tower lookup
vortexosint geosint --cell "310,260,12345,67890"
```

### NETWORK Module
```bash
# Port scan
vortexosint network --target 192.168.1.0/24
vortexosint network -t example.com --ports 80,443,8080
vortexosint network -t 10.0.0.1 --scan-type syn

# Service detection
vortexosint network --target example.com --service-detect --banner-grab

# OS detection
vortexosint network --target 192.168.1.1 --os-detect

# ASN lookup
vortexosint network --asn AS15169
```

### CRYPTO Module
```bash
# Address analysis
vortexosint crypto --address 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
vortexosint crypto -a 0x742d35Cc6634C0532925a3b844Bc9e7595f6E --blockchain eth

# Transaction analysis
vortexosint crypto --tx 4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b

# Entity lookup
vortexosint crypto --entity "Binance"
vortexosint crypto -e "Coinbase" --cluster
```

### SOCIAL Module
```bash
# Username enumeration
vortexosint social --username johndoe
vortexosint social -u johndoe --platforms twitter,github,linkedin

# Email lookup
vortexosint social --email johndoe@example.com

# Phone lookup
vortexosint social --phone "+1 555 123 4567"

# Availability check
vortexosint social --username johndoe --check-availability
```

### METADATA Module
```bash
# Single file
vortexosint metadata --file document.pdf
vortexosint metadata -f image.jpg --gps --exif

# Directory batch analysis
vortexosint metadata --dir /path/to/files
vortexosint metadata -d /path/to/files --recursive --strings
```

## 📊 Output Formats

```bash
# JSON (default)
vortexosint osint -d example.com -o results.json

# Text
vortexosint osint -d example.com -o results.txt --format txt

# CSV
vortexosint osint -d example.com -o results.csv --format csv
```

## 🔧 Configuration

Create a `.env` file for API keys:
```env
# Geolocation APIs
IPAPI_KEY=your_key
IPINFO_TOKEN=your_token
GEOJS_KEY=your_key

# Breach checking
HIBP_API_KEY=your_key

# Blockchain APIs
BLOCKCYPHER_TOKEN=your_token
ETHERSCAN_API_KEY=your_key

# Social APIs
TWITTER_BEARER_TOKEN=your_token
GITHUB_TOKEN=your_token
```

## 📁 Project Structure

```
vortexosint/
├── vortexosint/
│   ├── __init__.py
│   ├── cli.py              # Main CLI entry point
│   ├── core/
│   │   ├── __init__.py
│   │   ├── colors.py       # Terminal colors
│   │   └── banner.py       # ASCII banners
│   └── modules/
│       ├── __init__.py
│       ├── osint_module.py
│       ├── geosint_module.py
│       ├── network_module.py
│       ├── crypto_module.py
│       ├── social_module.py
│       └── metadata_module.py
├── pyproject.toml
├── requirements.txt
└── README.md
```

## ⚠️ Legal Disclaimer

**This tool is for educational and authorized testing purposes only.**

- Only use on systems you own or have explicit permission to test
- Respect rate limits and terms of service of external APIs
- Comply with applicable laws and regulations
- The authors are not responsible for misuse

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Open a Pull Request

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

## 🙏 Acknowledgments

- Inspired by tools like `recon-ng`, `theHarvester`, `Sherlock`, `PhoneInfoga`
- Built with Python and love for the OSINT community

---

<div align="center">
Made with ❤️ by the VortexOSINT Team
</div>