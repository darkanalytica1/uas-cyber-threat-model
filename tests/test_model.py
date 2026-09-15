import copy
import os

import pytest
import yaml

from uasthreat.model import STRIDE_ORDER, from_dict, load
from uasthreat.render import to_html, to_markdown

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
YAML_PATH = os.path.join(ROOT, "data", "threat-model.yaml")
REQUIRED_SURFACES = {"AV", "CC", "DL", "GCS", "API", "SC"}


@pytest.fixture(scope="module")
def raw():
    with open(YAML_PATH, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


@pytest.fixture(scope="module")
def model():
    return load(YAML_PATH)


def test_model_is_valid_and_complete(model):
    assert model.validate() == []


def test_required_surfaces_present(model):
    assert {s.id for s in model.surfaces} == REQUIRED_SURFACES


def test_every_cell_filled(model):
    for s in model.surfaces:
        for letter in STRIDE_ORDER:
            assert model.cell(s.id, letter), f"{s.id} x {letter}"


def test_ids_unique_and_stable(model):
    ids = [t.id for t in model.threats]
    assert len(ids) == len(set(ids))
    assert "DL-S1" in ids and "DL-S2" in ids


def test_validation_catches_gap_and_bad_reference(raw):
    broken = copy.deepcopy(raw)
    broken["threats"] = [t for t in broken["threats"] if not (t["surface"] == "GCS" and t["stride"] == "R")]
    broken["threats"][0]["controls"].append("C-DOES-NOT-EXIST")
    errors = from_dict(broken).validate()
    assert any("coverage gap: GCS x R" in e for e in errors)
    assert any("unknown control C-DOES-NOT-EXIST" in e for e in errors)


def test_not_applicable_fills_a_cell(raw):
    changed = copy.deepcopy(raw)
    changed["threats"] = [t for t in changed["threats"] if not (t["surface"] == "SC" and t["stride"] == "D")]
    changed["threats"].append({"surface": "SC", "stride": "D", "not_applicable": "example rationale", "controls": []})
    errors = from_dict(changed).validate()
    assert not any("SC x D" in e for e in errors)


def test_committed_renders_are_in_sync(model):
    with open(os.path.join(ROOT, "docs", "MATRIX.md"), encoding="utf-8") as fh:
        assert fh.read() == to_markdown(model), "run: python -m uasthreat render"
    with open(os.path.join(ROOT, "docs", "matrix.html"), encoding="utf-8") as fh:
        assert fh.read() == to_html(model), "run: python -m uasthreat render"


def test_html_escapes_text(raw):
    changed = copy.deepcopy(raw)
    changed["threats"][0]["threat"] = "<script>alert(1)</script>"
    html = to_html(from_dict(changed))
    assert "<script>alert" not in html and "&lt;script&gt;" in html
