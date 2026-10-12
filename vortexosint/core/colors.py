"""
Color utilities for VortexOSINT CLI output.
Works on Windows with colorama and Unix terminals.
"""

import sys
import os

# Initialize colorama for Windows support
try:
    import colorama
    colorama.init(strip=False, convert=True)
    _HAS_COLORAMA = True
except ImportError:
    _HAS_COLORAMA = False

# Detect if terminal supports colors
def _supports_color():
    """Check if terminal supports colors."""
    # Check if stdout is a TTY
    if not hasattr(sys.stdout, 'isatty') or not sys.stdout.isatty():
        return False
    
    # Check for common environment variables that indicate color support
    if os.environ.get('TERM') == 'dumb':
        return False
    
    # Force color if requested
    if os.environ.get('FORCE_COLOR'):
        return True
    
    # Windows: colorama handles it
    if _HAS_COLORAMA:
        return True
    
    # Unix: check TERM
    term = os.environ.get('TERM', '')
    if any(t in term for t in ['xterm', 'screen', 'vt100', 'color', 'ansi', 'cygwin', 'linux']):
        return True
    
    return False

_COLORS_ENABLED = _supports_color()


class Colors:
    """ANSI color codes for terminal output."""
    
    # Initialize all colors as empty strings (will be set below)
    RESET = ''
    BOLD = ''
    DIM = ''
    UNDERLINE = ''
    BLINK = ''
    REVERSE = ''
    HIDDEN = ''
    
    BLACK = ''
    RED = ''
    GREEN = ''
    YELLOW = ''
    BLUE = ''
    MAGENTA = ''
    CYAN = ''
    WHITE = ''
    
    BRIGHT_BLACK = ''
    BRIGHT_RED = ''
    BRIGHT_GREEN = ''
    BRIGHT_YELLOW = ''
    BRIGHT_BLUE = ''
    BRIGHT_MAGENTA = ''
    BRIGHT_CYAN = ''
    BRIGHT_WHITE = ''
    
    BG_BLACK = ''
    BG_RED = ''
    BG_GREEN = ''
    BG_YELLOW = ''
    BG_BLUE = ''
    BG_MAGENTA = ''
    BG_CYAN = ''
    BG_WHITE = ''
    
    SUCCESS = ''
    ERROR = ''
    WARNING = ''
    INFO = ''
    DEBUG = ''
    HIGHLIGHT = ''

    _enabled = _COLORS_ENABLED

    @classmethod
    def _init_colors(cls):
        """Initialize color codes if enabled."""
        if cls._enabled:
            cls.RESET = '\033[0m'
            cls.BOLD = '\033[1m'
            cls.DIM = '\033[2m'
            cls.UNDERLINE = '\033[4m'
            cls.BLINK = '\033[5m'
            cls.REVERSE = '\033[7m'
            cls.HIDDEN = '\033[8m'
            
            cls.BLACK = '\033[30m'
            cls.RED = '\033[31m'
            cls.GREEN = '\033[32m'
            cls.YELLOW = '\033[33m'
            cls.BLUE = '\033[34m'
            cls.MAGENTA = '\033[35m'
            cls.CYAN = '\033[36m'
            cls.WHITE = '\033[37m'
            
            cls.BRIGHT_BLACK = '\033[90m'
            cls.BRIGHT_RED = '\033[91m'
            cls.BRIGHT_GREEN = '\033[92m'
            cls.BRIGHT_YELLOW = '\033[93m'
            cls.BRIGHT_BLUE = '\033[94m'
            cls.BRIGHT_MAGENTA = '\033[95m'
            cls.BRIGHT_CYAN = '\033[96m'
            cls.BRIGHT_WHITE = '\033[97m'
            
            cls.BG_BLACK = '\033[40m'
            cls.BG_RED = '\033[41m'
            cls.BG_GREEN = '\033[42m'
            cls.BG_YELLOW = '\033[43m'
            cls.BG_BLUE = '\033[44m'
            cls.BG_MAGENTA = '\033[45m'
            cls.BG_CYAN = '\033[46m'
            cls.BG_WHITE = '\033[47m'
            
            cls.SUCCESS = cls.GREEN
            cls.ERROR = cls.RED
            cls.WARNING = cls.YELLOW
            cls.INFO = cls.CYAN
            cls.DEBUG = cls.BRIGHT_BLACK
            cls.HIGHLIGHT = cls.BRIGHT_YELLOW

    @classmethod
    def disable(cls):
        """Disable all color output."""
        cls._enabled = False
        for attr in dir(cls):
            if not attr.startswith('_') and attr.isupper() and not attr.startswith('__'):
                setattr(cls, attr, '')

    @classmethod
    def enable(cls):
        """Enable color output."""
        cls._enabled = True
        cls._init_colors()

    @classmethod
    def colorize(cls, text: str, color: str) -> str:
        """Colorize text if colors are enabled."""
        if cls._enabled and color:
            return f"{color}{text}{cls.RESET}"
        return text

    @classmethod
    def red(cls, text: str) -> str:
        return cls.colorize(text, cls.RED)

    @classmethod
    def green(cls, text: str) -> str:
        return cls.colorize(text, cls.GREEN)

    @classmethod
    def yellow(cls, text: str) -> str:
        return cls.colorize(text, cls.YELLOW)

    @classmethod
    def blue(cls, text: str) -> str:
        return cls.colorize(text, cls.BLUE)

    @classmethod
    def cyan(cls, text: str) -> str:
        return cls.colorize(text, cls.CYAN)

    @classmethod
    def magenta(cls, text: str) -> str:
        return cls.colorize(text, cls.MAGENTA)

    @classmethod
    def bold(cls, text: str) -> str:
        return cls.colorize(text, cls.BOLD)

    @classmethod
    def dim(cls, text: str) -> str:
        return cls.colorize(text, cls.DIM)


# Initialize colors on import
Colors._init_colors()