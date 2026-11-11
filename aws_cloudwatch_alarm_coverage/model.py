"""Shared vocabulary: severities, findings, and the error the CLI turns into exit 2."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

OK = "ok"
WARN = "warn"
CRITICAL = "critical"

SEVERITY_ORDER = {OK: 0, WARN: 1, CRITICAL: 2}


class InputError(Exception):
    """Bad user input (unreadable payload, broken rules file, unknown service)."""


def worst(*severities: str) -> str:
    """Return the highest severity given, defaulting to ok."""
    best = OK
    for severity in severities:
        if SEVERITY_ORDER.get(severity, 0) > SEVERITY_ORDER[best]:
            best = severity
    return best


def at_least(severity: str, threshold: str) -> bool:
    return SEVERITY_ORDER.get(severity, 0) >= SEVERITY_ORDER.get(threshold, 0)


@dataclass
class Finding:
    """One thing that is wrong, attached to either a resource or an alarm."""

    severity: str
    code: str
    subject: str
    message: str
    fix: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        out = {
            "severity": self.severity,
            "code": self.code,
            "subject": self.subject,
            "message": self.message,
        }
        if self.fix:
            out["fix"] = self.fix
        if self.details:
            out["details"] = self.details
        return out


def dimension_string(dimensions: dict[str, str] | None) -> str:
    """Render a dimension map the way it reads in an alarm definition."""
    if not dimensions:
        return "(no dimensions)"
    return ", ".join(f"{name}={value}" for name, value in sorted(dimensions.items()))
