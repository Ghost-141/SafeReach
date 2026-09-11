"""The published wheel must be able to do everything the source checkout can.

0.1.0 and 0.1.1 shipped a wheel that could run the server but could not enrol a host:
``shim_main.py`` was packaged, ``shim/build.py`` was not, and nothing assembled the two.
Every test in the suite ran from the checkout, where the builder exists, so nothing
noticed. These tests install the real built wheel into a clean venv and exercise the
paths that only fail outside the source tree.

Slow (a build plus a venv), so they are skipped when ``uv`` is unavailable rather than
reimplemented with ``pip``; CI always has ``uv``.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent

pytestmark = pytest.mark.skipif(shutil.which("uv") is None, reason="uv is not installed")


def _run(*cmd: str, **kw: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(list(cmd), capture_output=True, text=True, check=False, **kw)  # type: ignore[arg-type]


@pytest.fixture(scope="module")
def wheel_venv(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Build the wheel and install it into a fresh venv. Returns the venv's bin dir."""
    root = tmp_path_factory.mktemp("wheel")
    dist = root / "dist"
    built = _run("uv", "build", "-q", "--wheel", "--out-dir", str(dist), cwd=REPO)
    if built.returncode != 0:
        pytest.fail(f"uv build failed:\n{built.stdout}\n{built.stderr}")
    wheels = list(dist.glob("*.whl"))
    assert len(wheels) == 1, wheels

    venv = root / "venv"
    created = _run("uv", "venv", "-q", "--python", sys.executable, str(venv))
    if created.returncode != 0:
        pytest.fail(f"uv venv failed:\n{created.stdout}\n{created.stderr}")
    python = venv / "bin" / "python"
    installed = _run("uv", "pip", "install", "-q", "--python", str(python), str(wheels[0]))
    if installed.returncode != 0:
        pytest.fail(f"uv pip install failed:\n{installed.stdout}\n{installed.stderr}")
    return venv / "bin"


def test_installed_wheel_builds_a_working_shim(wheel_venv: Path, tmp_path: Path) -> None:
    """The regression that shipped twice: enrolment needs a shim, and the wheel had none.

    Not just "the build command exits 0": the artifact has to run under a bare Python
    and report the same fingerprint the server in that same install expects, or the
    handshake refuses every host.
    """
    out = tmp_path / "safereach-shim"
    built = _run(str(wheel_venv / "safereach"), "shim-build", "--out", str(out))
    assert built.returncode == 0, built.stderr
    assert out.is_file()

    ran = _run(sys.executable, str(out), "--version")
    assert ran.returncode == 0, ran.stderr
    reported = ran.stdout.strip()

    expected = _run(str(wheel_venv / "safereach"), "shim-build", "--print-version")
    assert expected.returncode == 0, expected.stderr
    assert reported == expected.stdout.strip()
    assert len(reported) == 12


def test_installed_wheel_fingerprint_matches_the_checkout(wheel_venv: Path) -> None:
    """The wheel and the checkout it was built from must agree, or `doctor` on a
    developer machine says every host is stale while a user's install says it is fine."""
    from_wheel = _run(str(wheel_venv / "safereach"), "shim-build", "--print-version")
    from_repo = _run(sys.executable, str(REPO / "shim" / "build.py"), "--print-version")
    assert from_wheel.returncode == 0 and from_repo.returncode == 0
    assert from_wheel.stdout.strip() == from_repo.stdout.strip()


def test_installed_wheel_can_build_the_shim_programmatically(wheel_venv: Path) -> None:
    """`enroll`, `provision`, `shim-update` and `doctor --fix` all go through
    `_build_shim()`; this is the call that raised "cannot locate shim/build.py"."""
    code = (
        "from safereach.cli import _build_shim\n"
        "path, version = _build_shim()\n"
        "assert path.is_file(), path\n"
        "print(version)\n"
    )
    ran = _run(str(wheel_venv / "python"), "-c", code)
    assert ran.returncode == 0, ran.stderr
    assert len(ran.stdout.strip()) == 12
