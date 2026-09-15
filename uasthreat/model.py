"""Load and validate the attack-surface x threat x control model."""
from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Dict, List

STRIDE_ORDER = ["S", "T", "R", "I", "D", "E"]


@dataclass(frozen=True)
class Surface:
    id: str
    name: str
    boundary: str
    description: str


@dataclass(frozen=True)
class Control:
    id: str
    name: str
    detail: str
    refs: tuple


@dataclass(frozen=True)
class Threat:
    id: str
    surface: str
    stride: str
    threat: str
    controls: tuple
    residual: str = ""
    not_applicable: str = ""


@dataclass
class ThreatModel:
    system: str
    stride: Dict[str, dict]
    boundaries: List[dict]
    surfaces: List[Surface]
    controls: "OrderedDict[str, Control]"
    threats: List[Threat] = field(default_factory=list)

    def surface(self, sid: str) -> Surface:
        return next(s for s in self.surfaces if s.id == sid)

    def cell(self, sid: str, letter: str) -> List[Threat]:
        return [t for t in self.threats if t.surface == sid and t.stride == letter]

    def threats_for_control(self, cid: str) -> List[Threat]:
        return [t for t in self.threats if cid in t.controls]

    def validate(self) -> List[str]:
        """Return a list of problems; empty means valid and complete."""
        errors = []
        sids = {s.id for s in self.surfaces}
        bids = {b["id"] for b in self.boundaries}
        if set(self.stride) != set(STRIDE_ORDER):
            errors.append("stride table must define exactly S, T, R, I, D, E")
        for s in self.surfaces:
            if s.boundary not in bids:
                errors.append(f"surface {s.id}: unknown trust boundary {s.boundary}")
        for t in self.threats:
            if t.surface not in sids:
                errors.append(f"{t.id}: unknown surface {t.surface}")
            if t.stride not in STRIDE_ORDER:
                errors.append(f"{t.id}: unknown STRIDE letter {t.stride}")
            if not t.not_applicable and not t.controls:
                errors.append(f"{t.id}: threat has no controls")
            for c in t.controls:
                if c not in self.controls:
                    errors.append(f"{t.id}: unknown control {c}")
        for s in self.surfaces:
            for letter in STRIDE_ORDER:
                if not self.cell(s.id, letter):
                    errors.append(f"coverage gap: {s.id} x {letter} has no threat and no not_applicable rationale")
        for cid in self.controls:
            if not self.threats_for_control(cid):
                errors.append(f"control {cid} counters no threat")
        return errors


def from_dict(data: dict) -> ThreatModel:
    surfaces = [Surface(s["id"], s["name"], s["boundary"], s.get("description", "")) for s in data["surfaces"]]
    controls = OrderedDict(
        (cid, Control(cid, c["name"], c.get("detail", ""), tuple(c.get("refs", []))))
        for cid, c in data["controls"].items()
    )
    counters: Dict[tuple, int] = {}
    threats = []
    for raw in data["threats"]:
        key = (raw["surface"], raw["stride"])
        counters[key] = counters.get(key, 0) + 1
        tid = f"{raw['surface']}-{raw['stride']}{counters[key]}"
        threats.append(Threat(
            id=tid,
            surface=raw["surface"],
            stride=raw["stride"],
            threat=raw.get("threat", ""),
            controls=tuple(raw.get("controls", [])),
            residual=raw.get("residual", ""),
            not_applicable=raw.get("not_applicable", ""),
        ))
    return ThreatModel(data["system"], data["stride"], data.get("trust_boundaries", []), surfaces, controls, threats)


def load(path: str) -> ThreatModel:
    try:
        import yaml
    except ImportError as exc:  # pragma: no cover
        raise SystemExit("PyYAML is required to read the model: pip install pyyaml") from exc
    with open(path, encoding="utf-8") as fh:
        return from_dict(yaml.safe_load(fh))
