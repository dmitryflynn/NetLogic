from pathlib import Path

from netlogic import _dashboard_needs_build


def test_needs_build_when_dist_missing(tmp_path: Path) -> None:
    dash = tmp_path / "dashboard"
    dash.mkdir()
    (dash / "src").mkdir()
    assert _dashboard_needs_build(dash, tmp_path / "dist") is True


def test_needs_build_when_source_newer(tmp_path: Path) -> None:
    dash = tmp_path / "dashboard"
    dist = tmp_path / "dist"
    src = dash / "src"
    src.mkdir(parents=True)
    dist.mkdir()
    built = dist / "index.html"
    built.write_text("old")
    newer = src / "index.css"
    newer.write_text("new")
    older = built.stat().st_mtime - 10
    import os
    os.utime(built, (older, older))
    os.utime(newer, None)
    assert _dashboard_needs_build(dash, dist) is True


def test_skips_build_when_dist_fresh(tmp_path: Path) -> None:
    dash = tmp_path / "dashboard"
    dist = tmp_path / "dist"
    src = dash / "src"
    src.mkdir(parents=True)
    dist.mkdir()
    old = src / "App.tsx"
    old.write_text("x")
    built = dist / "index.html"
    built.write_text("built")
    import os
    src_mtime = old.stat().st_mtime - 10
    os.utime(old, (src_mtime, src_mtime))
    assert _dashboard_needs_build(dash, dist) is False
