"""Password + second factor + revocable JWT, with the attacks that each layer stops."""

from .config import ConfigError, Settings
from .passwords import AuthError
from .service import AuthService, Challenge

__all__ = ["AuthService", "AuthError", "Challenge", "ConfigError", "Settings"]
__version__ = "0.2.0"
