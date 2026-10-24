"""The same CVE in the same package is one finding, whichever scanner's word for the ecosystem."""

import pytest

from app.core.config import settings
from app.parsers.base import NormalizedFinding
from app.services.dedup import canonical_ecosystem, sca_key


def _sca(ecosystem: str) -> NormalizedFinding:
    return NormalizedFinding(
        type="sca",
        title="CVE-2023-39325",
        severity="high",
        tool_name="t",
        package_name="golang.org/x/net",
        package_version="0.15.0",
        ecosystem=ecosystem,
        cve_id="CVE-2023-39325",
    )


@pytest.mark.parametrize("word", ["go", "golang", "gobinary", "go-module", "gomod", "GoLang"])
def test_every_scanners_word_for_go_is_one_ecosystem(word):
    assert canonical_ecosystem(word) == "golang"


def test_os_ecosystems_pass_through_unchanged():
    assert canonical_ecosystem("debian") == "debian" and canonical_ecosystem(None) == ""


def test_with_the_setting_on_three_tools_give_one_finding(monkeypatch):
    monkeypatch.setattr(settings, "dedup_canonical_ecosystems", True)
    keys = {sca_key(1, _sca(e)) for e in ("go", "golang", "go-module")}  # OSV, Trivy, Grype
    assert len(keys) == 1


def test_off_by_default_so_existing_keys_do_not_move(monkeypatch):
    monkeypatch.setattr(settings, "dedup_canonical_ecosystems", False)
    assert len({sca_key(1, _sca(e)) for e in ("go", "golang")}) == 2
    # And an ecosystem every tool already agreed on keeps exactly the key it always had.
    before = sca_key(1, _sca("npm"))
    monkeypatch.setattr(settings, "dedup_canonical_ecosystems", True)
    assert sca_key(1, _sca("npm")) == before


pytestmark = pytest.mark.no_database
