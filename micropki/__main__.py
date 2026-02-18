"""Allow running as ``python -m micropki``."""

import sys
from .cli import main

sys.exit(main())
