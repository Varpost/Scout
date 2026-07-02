"""Tests for the canonical severity ordering (models.Severity)."""

from __future__ import annotations

from scout.models import Severity, severity_rank


def test_severity_rank_orders_most_severe_first():
    assert severity_rank("CRITICAL") < severity_rank("HIGH") < severity_rank("MEDIUM") < severity_rank("LOW")


def test_enum_declaration_order_is_the_ordering():
    ranks = [severity_rank(sev.value) for sev in Severity]
    assert ranks == sorted(ranks)


def test_unknown_severity_sorts_last():
    assert severity_rank("BANANAS") > severity_rank("LOW")


def test_presentation_maps_cover_every_severity():
    # Badge/style/SARIF maps are hand-enumerated for presentation, but they
    # must never fall out of sync with the enum.
    from scout.agents.reporter_agent import _SARIF_LEVELS, _SARIF_SECURITY_SEVERITY, severity_badge
    from scout.cli import _SEVERITY_STYLES

    for sev in Severity:
        assert severity_badge(sev.value) != "⚪"
        assert sev.value in _SARIF_LEVELS
        assert sev.value in _SARIF_SECURITY_SEVERITY
        assert sev in _SEVERITY_STYLES
