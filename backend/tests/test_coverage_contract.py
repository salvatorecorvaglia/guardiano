"""Coverage must measure branches explicitly, not pass against a line-only historical report."""

import pytest

from check_coverage import validate

pytestmark = pytest.mark.no_database


@pytest.mark.parametrize("lines,covered,branches", [(80, 80, 100), (95, 86, 100)])
def test_separate_line_and_branch_floors(lines, covered, branches):
    assert validate(
        {
            "totals": {
                "percent_statements_covered": lines,
                "covered_branches": covered,
                "num_branches": branches,
            }
        }
    ) == (lines, covered)


@pytest.mark.parametrize(
    "totals",
    [
        {"percent_statements_covered": 100, "covered_branches": 0, "num_branches": 0},
        {"percent_statements_covered": 100, "covered_branches": 79, "num_branches": 100},
        {"percent_statements_covered": 79, "covered_branches": 100, "num_branches": 100},
    ],
)
def test_missing_or_insufficient_branch_measurement_is_refused(totals):
    with pytest.raises(ValueError):
        validate({"totals": totals})
