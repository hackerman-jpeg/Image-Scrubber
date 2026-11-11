"""Load only the tool directory when invoked with Python isolated mode (-I)."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from scrub_image import main
sys.exit(main())
