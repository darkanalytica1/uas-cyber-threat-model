import pytest

from uasthreat.cli import main


@pytest.mark.parametrize("cmd", ["validate", "forgery", "signing-demo", "log-demo", "update-demo"])
def test_commands_run(cmd, capsys):
    assert main([cmd]) == 0
    assert capsys.readouterr().out


def test_signing_demo_outcomes(capsys):
    main(["signing-demo"])
    out = capsys.readouterr().out
    assert out.count("ACCEPT") == 2 and out.count("REJECT") == 4


def test_render_to_tmp(tmp_path):
    md, html = tmp_path / "m.md", tmp_path / "m.html"
    assert main(["render", "--md", str(md), "--html", str(html)]) == 0
    assert "Threat matrix" in md.read_text() and html.read_text().startswith("<!doctype html>")
