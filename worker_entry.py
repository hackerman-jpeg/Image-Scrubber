"""Bootstrap isolated Python without adding the caller's directory to imports."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from decode_worker import main
sys.exit(main())
