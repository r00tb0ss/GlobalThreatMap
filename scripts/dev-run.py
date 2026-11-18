"""Development launcher: runs the app from the source tree with data in ./.devdata (not used by the installer)."""
import os
import sys

root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(root, "backend"))
os.environ.setdefault("GTI_HOME", root)
os.environ.setdefault("GTI_DATA_DIR", os.path.join(root, ".devdata"))
os.environ.setdefault("GTI_HOST", "127.0.0.1")
os.environ.setdefault("GTI_PORT", "8088")

from gti.app import main  # noqa: E402

main()
