"""
VortexOSINT - Main entry point when run as module: python -m vortexosint
"""

import os
import sys

# Ensure the real package (outer project root) is importable even when
# python is launched from a parent directory whose same-named folder
# shadows the installed package as a namespace package.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# If 'vortexosint' was already loaded as a namespace package (no __init__,
# e.g. cwd shadowing), drop it so the re-import below picks up the real
# package with __version__.
_pkg = sys.modules.get("vortexosint")
if _pkg is not None and not hasattr(_pkg, "__version__"):
    del sys.modules["vortexosint"]

from vortexosint.cli import main

if __name__ == '__main__':
    main()