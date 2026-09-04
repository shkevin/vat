"""Backend asset rollups must round the way the frontend does.

A parity run over 1,408 live assets found the two implementations agreed on
every count, worst severity and verified percentage, and differed only on
oraPct — 60 assets off by exactly 1, because Python's round() rounds halves to
even while JavaScript's Math.round rounds them up.
"""

import pytest

from app.services.assets_service import _round_half_up


@pytest.mark.parametrize(
    "value,expected",
    [
        (80.5, 81),   # python's round() gives 80 here — the actual divergence
        (81.5, 82),
        (0.5, 1),
        (1.5, 2),
        (2.5, 3),
        (80.4, 80),
        (80.6, 81),
        (100.0, 100),
        (0.0, 0),
    ],
)
def test_rounds_halves_up_like_javascript(value, expected):
    assert _round_half_up(value) == expected


def test_differs_from_python_round_on_exact_halves():
    """Pin the reason this helper exists, so nobody 'simplifies' it back."""
    halves = [v + 0.5 for v in range(0, 100)]
    disagreements = [v for v in halves if round(v) != _round_half_up(v)]
    assert disagreements, "if these ever agree, the helper is redundant"
    # Every disagreement is python rounding down to an even number.
    assert all(_round_half_up(v) == round(v) + 1 for v in disagreements)
