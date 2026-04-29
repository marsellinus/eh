"""Add project root to sys.path so all modules resolve correctly from any CWD."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
