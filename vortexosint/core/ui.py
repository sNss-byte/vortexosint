"""
Central UI helpers for VortexOSINT.

Uses `rich` when available (tables, panels, prompts) and falls back
to plain printing with ANSI colors otherwise, so the CLI works
everywhere with or without optional dependencies.

All output goes through this module: banner, module headers,
status messages, tables and interactive prompts.
"""

import sys
import shutil

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.prompt import Prompt, Confirm
    from rich import box

    _HAS_RICH = True
except ImportError:  # pragma: no cover - fallback path
    _HAS_RICH = False

from vortexosint.core.colors import Colors

# Set to True by --no-color: forces plain output even if rich is present.
PLAIN_MODE = False

_console = None


def set_plain_mode(plain: bool = True):
    """Force plain (no rich / no color) output. Called for --no-color."""
    global PLAIN_MODE, _console
    PLAIN_MODE = plain
    _console = None
    if plain:
        Colors.disable()


def get_console():
    """Return a shared rich Console, or None in plain/fallback mode."""
    global _console
    if PLAIN_MODE or not _HAS_RICH:
        return None
    if _console is None:
        # Soft wrap + no highlight: we control styling explicitly.
        _console = Console(highlight=False, soft_wrap=False)
    return _console


def _box():
    """ROUNDED borders when the output encoding supports them, else ASCII.

    Prevents UnicodeEncodeError on Windows consoles piped with cp1252.
    """
    enc = getattr(sys.stdout, "encoding", None) or "utf-8"
    try:
        "─│┌┐└┘".encode(enc)
        return box.ROUNDED
    except (UnicodeEncodeError, LookupError, AttributeError):
        return box.ASCII


def _box_is_ascii() -> bool:
    return _box() is box.ASCII


def _out(text: str = "", style: str = ""):
    """Print styled text via rich, or plain print as fallback."""
    console = get_console()
    if console is not None:
        console.print(text, style=style, markup=False, highlight=False)
    else:
        print(text)


# ---------------------------------------------------------------------------
# Status / message helpers (single place for the [*, +, !, ~] conventions)
# ---------------------------------------------------------------------------

def info(text: str):
    _out(f"[*] {text}", style="cyan")


def success(text: str):
    _out(f"[+] {text}", style="green")


def error(text: str):
    _out(f"[!] {text}", style="red")


def warning(text: str):
    _out(f"[!] {text}", style="yellow")


def step(text: str):
    _out(f"[~] {text}", style="yellow")


def headline(text: str):
    """Bold section headline inside a module run."""
    console = get_console()
    if console is not None:
        console.print(text, style="bold cyan", markup=False, highlight=False)
    else:
        print(f"{Colors.CYAN}{Colors.BOLD}{text}{Colors.RESET}")


def divider():
    """Visual separator at the end of a module run."""
    console = get_console()
    if console is not None:
        if _box_is_ascii():
            console.rule(characters="-", style="cyan")
        else:
            console.rule(style="cyan")
    else:
        print(f"{Colors.CYAN}{'=' * 60}{Colors.RESET}")


# ---------------------------------------------------------------------------
# Banner & headers
# ---------------------------------------------------------------------------

LOGO = r"""
__     __         _
\ \   / /__  _ __| |_ _____  __
 \ \ / / _ \| '__| __/ _ \ \/ /
  \ V / (_) | |  | ||  __/>  <
   \_/ \___/|_|   \__\___/_/\_\
       ___  ____ ___ _   _ _____
      / _ \/ ___|_ _| \ | |_   _|
     | | | \___ \| ||  \| | | |
     | |_| |___) | || |\  | | |
      \___/|____/___|_| \_| |_|
"""

TAGLINE = "Multi-tool OSINT / GEOSINT reconnaissance framework"


def show_banner(version: str):
    """Print the main VortexOSINT banner."""
    console = get_console()
    if console is not None:
        console.print(
            Panel(
                f"[bold cyan]{LOGO}[/]\n"
                f"[yellow]{TAGLINE}[/]\n"
                f"[dim]v{version}  |  github.com/vortexosint[/dim]",
                border_style="cyan",
                box=_box(),
                padding=(1, 4),
            )
        )
    else:
        print(Colors.cyan(LOGO))
        print(Colors.yellow(f"  {TAGLINE}"))
        print(Colors.dim(f"  Version: {version}  |  https://github.com/vortexosint"))
        print()


def show_module_header(name: str, description: str):
    """Print a module-specific header."""
    console = get_console()
    if console is not None:
        console.print(
            Panel(
                f"[dim]{description}[/dim]",
                title=f"[bold cyan]{name.upper()}[/]",
                border_style="cyan",
                box=_box(),
                padding=(0, 2),
            )
        )
    else:
        print(Colors.cyan(f"\n+{'-' * 60}+"))
        print(Colors.cyan(f"|  {name.upper():<56}|"))
        print(Colors.cyan(f"+{'-' * 60}+"))
        print(Colors.dim(f"  {description}\n"))


# ---------------------------------------------------------------------------
# Module catalog (shared by --help, menu and docs)
# ---------------------------------------------------------------------------

MODULES = {
    "osint": {
        "label": "OSINT",
        "description": "Domains, emails, phones, usernames, IPs",
        "example": "osint --domain example.com",
    },
    "geosint": {
        "label": "GEOSINT",
        "description": "IP geolocation, coords, addresses, WiFi/cell",
        "example": "geosint --ip 8.8.8.8",
    },
    "network": {
        "label": "NETWORK",
        "description": "Port scans, services, OS detection, ASN",
        "example": "network --target 192.168.1.0/24",
    },
    "crypto": {
        "label": "CRYPTO",
        "description": "Addresses, transactions, entities",
        "example": "crypto --address 1A1zP1...",
    },
    "social": {
        "label": "SOCIAL",
        "description": "Usernames across 50+ platforms",
        "example": "social --username johndoe",
    },
    "metadata": {
        "label": "METADATA",
        "description": "EXIF, GPS, PDF & Office metadata",
        "example": "metadata --file document.pdf",
    },
    "password": {
        "label": "PASSWORD",
        "description": "Secure passwords, passphrases & audits",
        "example": "password --length 20 --count 5",
    },
}

MODULE_ORDER = ["osint", "geosint", "network", "crypto", "social", "metadata", "password"]


def show_modules_table():
    """Print the module catalog as a rich table (or plain list)."""
    console = get_console()
    if console is not None:
        table = Table(
            title="Available modules",
            box=_box(),
            border_style="cyan",
            header_style="bold yellow",
            show_lines=False,
        )
        table.add_column("#", justify="right", style="dim", width=3)
        table.add_column("Module", style="bold cyan", width=10)
        table.add_column("Description", style="")
        table.add_column("Example", style="dim")
        for i, key in enumerate(MODULE_ORDER, start=1):
            m = MODULES[key]
            table.add_row(str(i), m["label"], m["description"], f"vortexosint {m['example']}")
        console.print(table)
    else:
        print("\nAvailable modules:")
        for i, key in enumerate(MODULE_ORDER, start=1):
            m = MODULES[key]
            print(f"  {i}. {m['label']:<10} {m['description']}")
            print(f"     ex: vortexosint {m['example']}")
        print()


# ---------------------------------------------------------------------------
# Interactive prompts (menu mode)
# ---------------------------------------------------------------------------

def _read_plain(prompt_text: str, default: str = "") -> str:
    """input()-based prompt used when rich is unavailable."""
    suffix = f" [{default}]" if default else ""
    try:
        value = input(f"{prompt_text}{suffix}: ").strip()
    except EOFError:
        return ""
    return value if value else default


def ask(text: str, default: str = "") -> str:
    """Ask for a free-text value. Empty input returns `default`."""
    if PLAIN_MODE or not _HAS_RICH:
        return _read_plain(text, default)
    try:
        answer = Prompt.ask(f"[cyan]{text}[/]", default=default or None, show_default=bool(default))
    except (EOFError, KeyboardInterrupt):
        raise
    return (answer or "").strip() if isinstance(answer, str) else (answer or "")


def ask_yes_no(text: str, default: bool = False) -> bool:
    """Ask a yes/no question."""
    if PLAIN_MODE or not _HAS_RICH:
        hint = "Y/n" if default else "y/N"
        try:
            value = input(f"{text} [{hint}]: ").strip().lower()
        except EOFError:
            return default
        if not value:
            return default
        return value in ("y", "yes", "o", "oui")
    try:
        return Confirm.ask(f"[cyan]{text}[/]", default=default)
    except (EOFError, KeyboardInterrupt):
        raise


def ask_choice(text: str, choices: list, default: str) -> str:
    """Ask to pick one value among `choices`."""
    if PLAIN_MODE or not _HAS_RICH:
        shown = "/".join(choices)
        try:
            value = input(f"{text} [{shown}, défaut: {default}]: ").strip().lower()
        except EOFError:
            return default
        return value if value in choices else default
    try:
        answer = Prompt.ask(
            f"[cyan]{text}[/]",
            choices=choices,
            default=default,
            show_choices=True,
            show_default=True,
        )
    except (EOFError, KeyboardInterrupt):
        raise
    return answer or default


def pause():
    """Wait for Enter (used between menu runs)."""
    try:
        input("\nAppuie sur Entrée pour continuer...")
    except EOFError:
        pass


# ---------------------------------------------------------------------------
# Retro menu (paged, numbered, Kali-style prompt)
# ---------------------------------------------------------------------------

RETRO_LINK = "https://github.com/sNss-byte/vortexosint"


def show_retro_title():
    """Centered magenta title block."""
    console = get_console()
    lines = ["VortexOSINT Multi-Tool", f"[{RETRO_LINK}]"]
    if console is not None:
        width = console.width or 80
        for line in lines:
            console.print(line.center(width), style="magenta", markup=False,
                          highlight=False)
    else:
        print(Colors.cyan("VortexOSINT Multi-Tool".center(70)))
        print(Colors.dim(f"[{RETRO_LINK}]".center(70)))


def _retro_entries(cells):
    """Format [(num, label)] cells for one category column."""
    return "\n".join(f"[{n}] {label}" for n, label in cells)


def show_retro_page(title, columns):
    """Render one menu page.

    columns: list of (header, [(num_str, label), ...]).
    Numbers are global across pages (01, 02, ...).
    """
    console = get_console()
    if console is not None:
        table = Table(title=title, box=_box(), border_style="magenta",
                      header_style="bold magenta", show_lines=False)
        for header, _cells in columns:
            table.add_column(header, style="red", overflow="fold")
        table.add_row(*[_retro_entries(cells) for _header, cells in columns])
        console.print(table)
        return

    # Plain ASCII fallback (cp1252-safe).
    try:
        term_width = shutil.get_terminal_size().columns
    except Exception:
        term_width = 80
    col_w = 26
    ncols = len(columns)
    if term_width < ncols * (col_w + 1):
        # Stack vertically on narrow terminals.
        for header, cells in columns:
            print(f"+{'-' * col_w}+")
            print(f"|{header.center(col_w)}|")
            print(f"+{'-' * col_w}+")
            for num, label in cells:
                print(f"  [{num}] {label}")
            print()
        return
    print("+" + "+".join(["-" * col_w] * ncols) + "+")
    print("|" + "|".join(h.center(col_w) for h, _c in columns) + "|")
    print("+" + "+".join(["-" * col_w] * ncols) + "+")
    max_rows = max(len(cells) for _h, cells in columns)
    for i in range(max_rows):
        row = []
        for _h, cells in columns:
            cell = f"[{cells[i][0]}] {cells[i][1]}" if i < len(cells) else ""
            row.append(" " + cell[:col_w - 1].ljust(col_w - 1))
        print("|" + "|".join(row) + "|")
    print("+" + "+".join(["-" * col_w] * ncols) + "+")


def show_retro_nav(has_next, has_back):
    """Red navigation hints under the page."""
    parts = []
    if has_back:
        parts.append("[B] Back")
    if has_next:
        parts.append("[N] Next")
    parts.append("[E] Exit")
    line = "  |- " + " | ".join(parts)
    console = get_console()
    if console is not None:
        console.print(line, style="red", markup=False, highlight=False)
    else:
        print(Colors.red(line))


def retro_input():
    """Kali-style prompt. Returns stripped input, or None on EOF."""
    prompt = f"{Colors.GREEN}(vortex)-[~/menu]$ {Colors.RESET}"
    try:
        return input(prompt).strip()
    except EOFError:
        return None
