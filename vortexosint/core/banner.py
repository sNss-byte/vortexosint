"""
ASCII Banner for VortexOSINT.

Rendering is delegated to :mod:`vortexosint.core.ui` (rich panel
when available, plain ASCII otherwise). The public functions here
are kept stable: modules import them directly.
"""

from vortexosint.core import ui as _ui

try:
    from vortexosint import __version__ as _version
except ImportError:  # pragma: no cover - shadowing fallback
    try:
        from importlib.metadata import version as _pkg_version

        _version = _pkg_version("vortexosint")
    except Exception:
        _version = "1.0.0"

# Kept for backwards compatibility (plain fallback rendering).
BANNER = _ui.LOGO
SUBTITLE = _ui.TAGLINE


def print_banner():
    """Print the VortexOSINT banner."""
    _ui.show_banner(_version)


def print_module_banner(module_name: str, description: str):
    """Print a module-specific banner."""
    _ui.show_module_header(module_name, description)
