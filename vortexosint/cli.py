#!/usr/bin/env python3
"""
VortexOSINT - Main CLI Entry Point
Multi-tool OSINT/GEOSINT CLI for reconnaissance and intelligence gathering.

Two ways to use it:
  1. Direct mode  : vortexosint <module> [options]   (scripts & power users)
  2. Menu mode    : vortexosint                      (interactive, guided)
"""

import argparse
import sys
import os
from typing import Optional

# Initialize colorama for Windows ANSI support
try:
    import colorama
    colorama.init()
except ImportError:
    pass

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from vortexosint import __version__
except ImportError:
    # Fallback when the package is shadowed by the project-root folder
    # (e.g. `python -m vortexosint` run from the parent directory).
    try:
        from importlib.metadata import version as _pkg_version

        __version__ = _pkg_version("vortexosint")
    except Exception:
        __version__ = "1.0.0"

from vortexosint.core import ui
from vortexosint.core.banner import print_banner
from vortexosint.core.colors import Colors
from vortexosint.modules import (
    osint_module,
    geosint_module,
    network_module,
    crypto_module,
    social_module,
    metadata_module,
    password_module
)

MODULE_HANDLERS = {
    'osint': osint_module.run,
    'geosint': geosint_module.run,
    'network': network_module.run,
    'crypto': crypto_module.run,
    'social': social_module.run,
    'metadata': metadata_module.run,
    'password': password_module.run,
}


class ColoredHelpFormatter(argparse.RawDescriptionHelpFormatter):
    """argparse formatter with colorized section headings."""

    def start_section(self, heading):
        if heading:
            heading = f"{Colors.CYAN}{Colors.BOLD}{heading}{Colors.RESET}"
        return super().start_section(heading)


class VortexOSINT:
    """Main VortexOSINT CLI Application."""

    def __init__(self):
        self.parser = self._create_parser()
        self.args = None

    # ------------------------------------------------------------------
    # Parser (options unchanged: modules read these attributes)
    # ------------------------------------------------------------------

    def _create_parser(self) -> argparse.ArgumentParser:
        """Create the main argument parser with all subcommands."""
        parser = argparse.ArgumentParser(
            prog='vortexosint',
            description='VortexOSINT - Multi-tool OSINT/GEOSINT CLI',
            epilog='Examples:\n'
                   '  vortexosint osint --domain example.com\n'
                   '  vortexosint geosint --ip 8.8.8.8\n'
                   '  vortexosint network --target 192.168.1.0/24\n'
                   '  vortexosint social --username johndoe\n'
                   '  vortexosint metadata --file document.pdf\n'
                   '  vortexosint crypto --address 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\n'
                   '\n'
                   'Run without a MODULE to open the interactive menu.',
            formatter_class=ColoredHelpFormatter,
            add_help=False
        )

        # Global arguments
        parser.add_argument('-h', '--help', action='help',
                            help='Show this help message and exit')
        parser.add_argument('-v', '--version', action='version',
                            version=f'%(prog)s {__version__}',
                            help='Show version and exit')
        parser.add_argument('--no-banner', action='store_true',
                            help='Disable ASCII banner')
        parser.add_argument('--no-color', action='store_true',
                            help='Disable colored output')
        parser.add_argument('--verbose', '-V', action='count', default=0,
                            help='Increase verbosity (-V, -VV, -VVV)')
        parser.add_argument('--output', '-o', type=str,
                            help='Output file for results (JSON format)')
        parser.add_argument('--format', choices=['json', 'txt', 'csv'], default='json',
                            help='Output format (default: json)')
        parser.add_argument('--menu', action='store_true',
                            help='Force the interactive menu')

        # Subparsers for modules
        subparsers = parser.add_subparsers(dest='module', metavar='MODULE',
                                           help='Available modules: osint, geosint, network, crypto, social, metadata, password')

        # OSINT Module
        osint_parser = subparsers.add_parser('osint', help='General OSINT reconnaissance',
                                             formatter_class=ColoredHelpFormatter,
                                             epilog='Examples:\n'
                                                    '  vortexosint osint --domain example.com\n'
                                                    '  vortexosint osint --email admin@example.com\n'
                                                    '  vortexosint osint --phone "+33 1 23 45 67 89"\n'
                                                    '  vortexosint osint --username johndoe --deep')
        osint_parser.add_argument('--domain', '-d', type=str,
                                  help='Target domain for reconnaissance')
        osint_parser.add_argument('--email', '-e', type=str,
                                  help='Email address to investigate')
        osint_parser.add_argument('--phone', '-p', type=str,
                                  help='Phone number to investigate (international format)')
        osint_parser.add_argument('--username', '-u', type=str,
                                  help='Username to search across platforms')
        osint_parser.add_argument('--ip', '-i', type=str,
                                  help='IP address to investigate')
        osint_parser.add_argument('--deep', action='store_true',
                                  help='Enable deep reconnaissance (slower but more thorough)')
        osint_parser.add_argument('--sources', type=str, default='all',
                                  help='Comma-separated list of sources (default: all)')
        osint_parser.add_argument('--timeout', type=int, default=30,
                                  help='Request timeout in seconds (default: 30)')

        # GEOSINT Module
        geo_parser = subparsers.add_parser('geosint', help='Geospatial intelligence',
                                           formatter_class=ColoredHelpFormatter,
                                           epilog='Examples:\n'
                                                  '  vortexosint geosint --ip 8.8.8.8\n'
                                                  '  vortexosint geosint --coords "48.8566,2.3522"\n'
                                                  '  vortexosint geosint --address "1600 Pennsylvania Ave NW"\n'
                                                  '  vortexosint geosint --wifi "AA:BB:CC:DD:EE:FF"')
        geo_parser.add_argument('--ip', '-i', type=str,
                                help='IP address for geolocation')
        geo_parser.add_argument('--coords', '-c', type=str,
                                help='Coordinates (lat,lon) for reverse geocoding')
        geo_parser.add_argument('--address', '-a', type=str,
                                help='Address for forward geocoding')
        geo_parser.add_argument('--wifi', '-w', type=str,
                                help='WiFi BSSID (MAC) for wardriving lookup')
        geo_parser.add_argument('--cell', type=str,
                                help='Cell tower info (MCC,MNC,LAC,CID)')
        geo_parser.add_argument('--radius', type=int, default=1000,
                                help='Search radius in meters (default: 1000)')
        geo_parser.add_argument('--map', action='store_true',
                                help='Generate interactive HTML map')
        geo_parser.add_argument('--provider', choices=['ipapi', 'ipinfo', 'geojs', 'all'], default='all',
                                help='Geolocation provider (default: all)')

        # Network Module
        net_parser = subparsers.add_parser('network', help='Network reconnaissance',
                                           formatter_class=ColoredHelpFormatter,
                                           epilog='Examples:\n'
                                                  '  vortexosint network --target 192.168.1.0/24\n'
                                                  '  vortexosint network --target example.com --ports 80,443,8080\n'
                                                  '  vortexosint network --target 10.0.0.1 --scan-type syn\n'
                                                  '  vortexosint network --asn AS15169')
        net_parser.add_argument('--target', '-t', type=str, required=True,
                                help='Target IP, CIDR, or hostname')
        net_parser.add_argument('--ports', '-p', type=str, default='top100',
                                help='Ports to scan (default: top100, e.g., 80,443,1-1000)')
        net_parser.add_argument('--scan-type', '-s', choices=['syn', 'connect', 'udp', 'ack'],
                                default='syn', help='Scan type (default: syn)')
        net_parser.add_argument('--asn', type=str,
                                help='ASN number for ASN lookup (e.g., AS15169)')
        net_parser.add_argument('--banner-grab', action='store_true',
                                help='Enable banner grabbing on open ports')
        net_parser.add_argument('--os-detect', action='store_true',
                                help='Enable OS detection')
        net_parser.add_argument('--service-detect', action='store_true',
                                help='Enable service version detection')
        net_parser.add_argument('--rate', type=int, default=1000,
                                help='Packets per second (default: 1000)')

        # Crypto Module
        crypto_parser = subparsers.add_parser('crypto', help='Cryptocurrency intelligence',
                                              formatter_class=ColoredHelpFormatter,
                                              epilog='Examples:\n'
                                                     '  vortexosint crypto --address 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\n'
                                                     '  vortexosint crypto --tx 4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b\n'
                                                     '  vortexosint crypto --entity "Binance"')
        crypto_parser.add_argument('--address', '-a', type=str,
                                   help='Cryptocurrency address to analyze')
        crypto_parser.add_argument('--tx', '-t', type=str,
                                   help='Transaction hash to analyze')
        crypto_parser.add_argument('--entity', '-e', type=str,
                                   help='Entity name to search (exchange, service, etc.)')
        crypto_parser.add_argument('--blockchain', choices=['btc', 'eth', 'bsc', 'trx', 'ltc', 'doge', 'all'],
                                   default='all', help='Blockchain to query (default: all)')
        crypto_parser.add_argument('--depth', type=int, default=2,
                                   help='Transaction graph depth (default: 2)')
        crypto_parser.add_argument('--cluster', action='store_true',
                                   help='Perform address clustering analysis')

        # Social Module
        social_parser = subparsers.add_parser('social', help='Social media intelligence',
                                              formatter_class=ColoredHelpFormatter,
                                              epilog='Examples:\n'
                                                     '  vortexosint social --username johndoe\n'
                                                     '  vortexosint social --username johndoe --platforms twitter,linkedin,github\n'
                                                     '  vortexosint social --email johndoe@example.com')
        social_parser.add_argument('--username', '-u', type=str,
                                   help='Username to search across platforms')
        social_parser.add_argument('--email', '-e', type=str,
                                   help='Email to search for associated accounts')
        social_parser.add_argument('--phone', '-p', type=str,
                                   help='Phone number to search')
        social_parser.add_argument('--platforms', type=str, default='all',
                                   help='Comma-separated platforms (default: all)')
        social_parser.add_argument('--check-availability', action='store_true',
                                   help='Check username availability on platforms')

        # Metadata Module
        meta_parser = subparsers.add_parser('metadata', help='File metadata extraction',
                                            formatter_class=ColoredHelpFormatter,
                                            epilog='Examples:\n'
                                                   '  vortexosint metadata --file document.pdf\n'
                                                   '  vortexosint metadata --dir /path/to/files\n'
                                                   '  vortexosint metadata --file image.jpg --gps')
        meta_parser.add_argument('--file', '-f', type=str,
                                 help='Single file to analyze')
        meta_parser.add_argument('--dir', '-d', type=str,
                                 help='Directory to batch analyze')
        meta_parser.add_argument('--gps', action='store_true',
                                 help='Extract GPS coordinates from images')
        meta_parser.add_argument('--exif', action='store_true',
                                 help='Extract full EXIF data')
        meta_parser.add_argument('--strings', action='store_true',
                                 help='Extract strings from binary files')
        meta_parser.add_argument('--recursive', '-r', action='store_true',
                                 help='Recursively scan directories')

        # Password Module
        pass_parser = subparsers.add_parser('password', help='Secure passwords & audits',
                                            formatter_class=ColoredHelpFormatter,
                                            epilog='Examples:\n'
                                                   '  vortexosint password --length 20 --count 5\n'
                                                   '  vortexosint password --passphrase --words 6\n'
                                                   '  vortexosint password --check\n'
                                                   '  vortexosint password --hash --algo sha256')
        pass_parser.add_argument('--length', '-l', type=int, default=20,
                                 help='Generated password length (default: 20)')
        pass_parser.add_argument('--count', '-n', type=int, default=5,
                                 help='How many passwords to generate (default: 5)')
        pass_parser.add_argument('--no-symbols', action='store_true',
                                 help='Exclude symbols (!@#$...)')
        pass_parser.add_argument('--no-digits', action='store_true',
                                 help='Exclude digits')
        pass_parser.add_argument('--no-uppercase', action='store_true',
                                 help='Exclude uppercase letters')
        pass_parser.add_argument('--allow-ambiguous', action='store_true',
                                 help='Allow ambiguous chars (0O1lI)')
        pass_parser.add_argument('--passphrase', action='store_true',
                                 help='Generate a memorable passphrase instead')
        pass_parser.add_argument('--words', '-w', type=int, default=5,
                                 help='Words per passphrase (default: 5)')
        pass_parser.add_argument('--separator', type=str, default='-',
                                 help='Word separator (default: -)')
        pass_parser.add_argument('--check', nargs='?', const='__prompt__',
                                 default=None, metavar='PASSWORD',
                                 help='Audit a password (no value = hidden prompt)')
        pass_parser.add_argument('--hash', nargs='?', const='__prompt__',
                                 default=None, metavar='PASSWORD',
                                 help='Salted hash of a password (no value = hidden prompt)')
        pass_parser.add_argument('--algo',
                                 choices=['sha256', 'sha512', 'sha3_256', 'sha1', 'md5'],
                                 default='sha256', help='Hash algorithm (default: sha256)')
        pass_parser.add_argument('--salt', type=str, default=None,
                                 help='Salt (default: random 16 bytes hex)')

        return parser

    # ------------------------------------------------------------------
    # Main run
    # ------------------------------------------------------------------

    def run(self, args: Optional[list] = None) -> int:
        """Run the CLI application."""
        raw = list(args) if args is not None else sys.argv[1:]
        # Honor --no-color even for --help (parsed before the flag is applied).
        if '--no-color' in raw:
            ui.set_plain_mode(True)

        self.args = self.parser.parse_args(args)

        # Handle global options
        if self.args.no_color:
            ui.set_plain_mode(True)

        if not self.args.no_banner:
            print_banner()

        # Interactive menu: explicit flag, or no module on a real terminal.
        if self.args.menu or not self.args.module:
            if self.args.module:
                pass  # --menu combined with a module: fall through to direct run
            elif sys.stdin.isatty():
                return self._interactive_loop()
            elif not self.args.menu:
                self.parser.print_help()
                return 0
            else:
                ui.error("Menu interactif indisponible (entrée non interactive).")
                return 1

        # Route to appropriate module
        try:
            return self._route_module()
        except KeyboardInterrupt:
            ui.error("Interrupted by user")
            return 130
        except Exception as e:
            if self.args.verbose:
                import traceback
                traceback.print_exc()
            ui.error(f"Error: {e}")
            return 1

    def _route_module(self) -> int:
        """Route to the appropriate module handler (direct CLI mode)."""
        handler = MODULE_HANDLERS.get(self.args.module)
        if handler:
            return handler(self.args)
        ui.error(f"Unknown module: {self.args.module}")
        return 1

    # ------------------------------------------------------------------
    # Interactive menu
    # ------------------------------------------------------------------

    def _interactive_loop(self) -> int:
        """Guided menu loop. Returns when the user quits."""
        n = len(ui.MODULE_ORDER)
        print("Mode interactif — 'q' pour quitter.\n")
        ui.show_modules_table()
        while True:
            try:
                choice = ui.ask(f"Module (1-{n} ou nom)")
            except (EOFError, KeyboardInterrupt):
                print()
                return 0
            key, quit_requested = self._resolve_choice(choice)
            if quit_requested:
                ui.info("À bientôt.")
                return 0
            if key is None:
                ui.warning(f"Choix inconnu — tape 1-{len(ui.MODULE_ORDER)} ou le nom "
                           f"du module (q pour quitter).")
                continue
            try:
                ns = self._prompt_module_args(key)
            except (EOFError, KeyboardInterrupt):
                print()
                ui.info("Retour au menu.")
                continue
            if ns is None:  # user went back / missing required input
                continue
            try:
                MODULE_HANDLERS[key](ns)
            except KeyboardInterrupt:
                print()
                ui.warning("Interrompu — retour au menu.")
            except Exception as e:
                if getattr(self.args, 'verbose', 0):
                    import traceback
                    traceback.print_exc()
                ui.error(f"Error: {e}")
            ui.divider()
            try:
                ui.pause()
            except (EOFError, KeyboardInterrupt):
                print()
                return 0
            ui.show_modules_table()

    @staticmethod
    def _resolve_choice(raw: str):
        """Map menu input to (module_key, quit_requested)."""
        text = (raw or "").strip().lower()
        if text in ("q", "quit", "exit", "0"):
            return None, True
        if text.isdigit():
            idx = int(text) - 1
            if 0 <= idx < len(ui.MODULE_ORDER):
                return ui.MODULE_ORDER[idx], False
            return None, False
        for k in ui.MODULE_ORDER:
            if text == k or text == ui.MODULES[k]["label"].lower():
                return k, False
        return None, False

    # -- per-module guided prompts ------------------------------------

    def _global_answers(self) -> dict:
        """Common output options asked once per menu run."""
        output = ui.ask("Fichier de sortie (vide = écran)", "")
        fmt = "json"
        if output:
            fmt = ui.ask_choice("Format de sortie", ["json", "txt", "csv"], "json")
        return {"output": output or None, "format": fmt}

    def _base_ns(self, module: str) -> argparse.Namespace:
        """Namespace pre-filled with global flags for menu-driven runs."""
        g = self.args
        return argparse.Namespace(
            module=module,
            no_banner=True,
            no_color=getattr(g, 'no_color', False),
            verbose=getattr(g, 'verbose', 0),
            output=None,
            format=getattr(g, 'format', 'json'),
        )

    @staticmethod
    def _ask_int(text: str, default: int) -> int:
        raw = ui.ask(text, str(default)).strip()
        if not raw:
            return default
        try:
            return int(raw)
        except ValueError:
            ui.warning(f"Valeur invalide — '{default}' utilisé.")
            return default

    def _prompt_module_args(self, key: str) -> Optional[argparse.Namespace]:
        """Guide the user through a module's options. None = back to menu."""
        answers = self._module_answers(key)
        if answers is None:
            return None
        ns = self._base_ns(key)
        for k, v in vars(answers).items():
            setattr(ns, k, v)
        for k, v in self._global_answers().items():
            setattr(ns, k, v)
        return ns

    def _module_answers(self, key: str) -> Optional[argparse.Namespace]:
        m = argparse.Namespace()
        if key == 'osint':
            m.domain = ui.ask("Domaine (vide = ignorer)", "") or None
            m.email = ui.ask("Email", "") or None
            m.phone = ui.ask("Téléphone", "") or None
            m.username = ui.ask("Pseudo", "") or None
            m.ip = ui.ask("Adresse IP", "") or None
            if not any([m.domain, m.email, m.phone, m.username, m.ip]):
                ui.error("Aucune cible — retour au menu.")
                return None
            m.deep = ui.ask_yes_no("Reconnaissance approfondie ?", False)
            m.sources = "all"
            m.timeout = self._ask_int("Timeout requêtes (s)", 30)
        elif key == 'geosint':
            m.ip = ui.ask("Adresse IP", "") or None
            m.coords = ui.ask('Coordonnées "lat,lon"', "") or None
            m.address = ui.ask("Adresse postale", "") or None
            m.wifi = ui.ask("BSSID WiFi (MAC)", "") or None
            m.cell = ui.ask("Cellule MCC,MNC,LAC,CID", "") or None
            if not any([m.ip, m.coords, m.address, m.wifi, m.cell]):
                ui.error("Aucune cible — retour au menu.")
                return None
            m.radius = self._ask_int("Rayon de recherche (m)", 1000)
            m.map = ui.ask_yes_no("Générer une carte HTML ?", False)
            m.provider = ui.ask_choice("Fournisseur", ["all", "ipapi", "ipinfo", "geojs"], "all")
        elif key == 'network':
            m.target = ui.ask("Cible (IP, CIDR ou hôte) *", "") or None
            if not m.target:
                ui.error("Cible requise — retour au menu.")
                return None
            m.asn = ui.ask("ASN (vide = ignorer)", "") or None
            m.ports = ui.ask("Ports", "top100") or "top100"
            m.scan_type = ui.ask_choice("Type de scan", ["syn", "connect", "udp", "ack"], "syn")
            m.banner_grab = ui.ask_yes_no("Banner grabbing ?", False)
            m.os_detect = ui.ask_yes_no("Détection OS ?", False)
            m.service_detect = ui.ask_yes_no("Détection services ?", False)
            m.rate = self._ask_int("Paquets/seconde", 1000)
        elif key == 'crypto':
            m.address = ui.ask("Adresse crypto", "") or None
            m.tx = ui.ask("Hash de transaction", "") or None
            m.entity = ui.ask("Entité (ex: Binance)", "") or None
            if not any([m.address, m.tx, m.entity]):
                ui.error("Aucune cible — retour au menu.")
                return None
            m.blockchain = ui.ask_choice(
                "Blockchain", ["all", "btc", "eth", "bsc", "trx", "ltc", "doge"], "all")
            m.depth = self._ask_int("Profondeur du graphe", 2)
            m.cluster = ui.ask_yes_no("Analyse de clustering ?", False)
        elif key == 'social':
            m.username = ui.ask("Pseudo", "") or None
            m.email = ui.ask("Email", "") or None
            m.phone = ui.ask("Téléphone", "") or None
            if not any([m.username, m.email, m.phone]):
                ui.error("Aucune cible — retour au menu.")
                return None
            m.platforms = ui.ask("Plateformes (séparées par des virgules)", "all") or "all"
            m.check_availability = ui.ask_yes_no("Vérifier la disponibilité ?", False)
        elif key == 'metadata':
            m.file = ui.ask("Fichier à analyser", "") or None
            m.dir = ui.ask("Dossier à analyser", "") or None
            if not any([m.file, m.dir]):
                ui.error("Aucun fichier — retour au menu.")
                return None
            m.gps = ui.ask_yes_no("Extraire le GPS ?", False)
            m.exif = ui.ask_yes_no("Extraire l'EXIF complet ?", False)
            m.strings = ui.ask_yes_no("Extraire les strings ?", False)
            m.recursive = ui.ask_yes_no("Parcours récursif ?", False)
        elif key == 'password':
            from vortexosint.modules.password_module import PROMPT_SENTINEL
            action = ui.ask_choice("Action", ["generate", "passphrase", "check", "hash"],
                                   "generate")
            m.check, m.hash, m.passphrase = None, None, False
            if action == "check":
                m.check = PROMPT_SENTINEL  # hidden secure prompt at run time
            elif action == "hash":
                m.hash = PROMPT_SENTINEL
                m.algo = ui.ask_choice("Algorithme", ["sha256", "sha512", "sha3_256"], "sha256")
                m.salt = None
            elif action == "passphrase":
                m.passphrase = True
                m.words = self._ask_int("Nombre de mots", 5)
                m.separator = ui.ask("Séparateur", "-") or "-"
                m.length, m.count = 20, 5
                m.no_symbols = m.no_digits = m.no_uppercase = False
                m.allow_ambiguous = False
            else:
                m.length = self._ask_int("Longueur", 20)
                m.count = self._ask_int("Combien", 5)
                m.no_symbols = not ui.ask_yes_no("Inclure les symboles ?", True)
                m.no_digits = not ui.ask_yes_no("Inclure les chiffres ?", True)
                m.no_uppercase = not ui.ask_yes_no("Inclure les majuscules ?", True)
                m.allow_ambiguous = ui.ask_yes_no("Autoriser 0O1lI ?", False)
                m.words, m.separator, m.algo, m.salt = 5, "-", "sha256", None
        return m


def main():
    """Main entry point."""
    app = VortexOSINT()
    sys.exit(app.run())


if __name__ == '__main__':
    main()
