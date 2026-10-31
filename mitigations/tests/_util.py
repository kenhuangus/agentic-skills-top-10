import shutil
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
FIXTURES = ROOT / "fixtures"
REPO = ROOT.parent
sys.path.insert(0, str(ROOT))


def copy_fixture(name: str) -> Path:
    """Copy a fixture into a fresh temp dir so tests can mutate it."""
    dst = Path(tempfile.mkdtemp(prefix="ast-test-")) / name
    shutil.copytree(FIXTURES / name, dst)
    return dst


def rules(findings) -> set:
    return {f.rule for f in findings}
