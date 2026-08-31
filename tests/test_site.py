"""
Site integrity tests for awesome-appsec-interview.

Run: pytest tests/
"""

import re
import subprocess
from pathlib import Path

REPO = Path(__file__).parent.parent
DOCS = REPO / "docs"
MKDOCS_YML = REPO / "mkdocs.yml"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mkdocs_build_warnings() -> list[str]:
    result = subprocess.run(
        ["mkdocs", "build", "--strict"],
        cwd=REPO,
        capture_output=True,
        text=True,
    )
    lines = (result.stdout + result.stderr).splitlines()
    return [l for l in lines if "WARNING" in l and "contains a link" in l]


def _mkdocs_yml_text() -> str:
    return MKDOCS_YML.read_text(encoding="utf-8")


def _nav_doc_paths() -> list[str]:
    """Extract every .md path referenced in the nav section of mkdocs.yml."""
    text = _mkdocs_yml_text()
    # Match lines like:   - Some Title: path/to/file.md
    return re.findall(r":\s+([\w/\-]+\.md)", text)


# ---------------------------------------------------------------------------
# Broken links
# ---------------------------------------------------------------------------

class TestBrokenLinks:
    def test_no_broken_internal_links(self):
        """mkdocs build --strict must produce zero broken-link warnings."""
        warnings = _mkdocs_build_warnings()
        assert warnings == [], (
            f"{len(warnings)} broken link(s) found:\n" + "\n".join(warnings)
        )


# ---------------------------------------------------------------------------
# Mermaid rendering
# ---------------------------------------------------------------------------

class TestMermaidConfig:
    def test_superfences_has_mermaid_custom_fence(self):
        """pymdownx.superfences must declare a mermaid custom fence."""
        text = _mkdocs_yml_text()
        assert "name: mermaid" in text, (
            "mkdocs.yml is missing the mermaid custom fence under pymdownx.superfences"
        )

    def test_mermaid_js_loaded(self):
        """Mermaid JS must be listed in extra_javascript."""
        text = _mkdocs_yml_text()
        assert "mermaid" in text and "extra_javascript" in text, (
            "mkdocs.yml is missing mermaid in extra_javascript"
        )

    def test_mermaid_blocks_present_in_docs(self):
        """At least one doc must contain a mermaid code block (sanity check)."""
        mermaid_docs = [f for f in DOCS.rglob("*.md") if "```mermaid" in f.read_text(encoding="utf-8")]
        assert len(mermaid_docs) > 0, "No mermaid diagrams found in docs/"


# ---------------------------------------------------------------------------
# Nav hygiene
# ---------------------------------------------------------------------------

class TestNavHygiene:
    def test_adrs_not_in_nav(self):
        """ADR files must not appear in the site navigation."""
        nav_paths = _nav_doc_paths()
        adr_in_nav = [p for p in nav_paths if "adr/" in p]
        assert adr_in_nav == [], (
            f"ADR paths found in nav (ADRs are internal guidance, not site content): {adr_in_nav}"
        )

    def test_all_nav_files_exist(self):
        """Every file referenced in mkdocs.yml nav must exist on disk."""
        nav_paths = _nav_doc_paths()
        missing = [p for p in nav_paths if not (DOCS / p).exists()]
        assert missing == [], (
            f"Nav references {len(missing)} missing file(s):\n" + "\n".join(missing)
        )

    def test_no_duplicate_nav_entries(self):
        """No doc should appear twice in the nav."""
        nav_paths = _nav_doc_paths()
        seen, dupes = set(), []
        for p in nav_paths:
            if p in seen:
                dupes.append(p)
            seen.add(p)
        assert dupes == [], f"Duplicate nav entries: {dupes}"


# ---------------------------------------------------------------------------
# Topic grouping invariants
# ---------------------------------------------------------------------------

class TestTopicGrouping:
    def test_ssrf_in_injection_not_access_control(self):
        """SSRF must be grouped under Injection, not Access Control."""
        text = _mkdocs_yml_text()
        injection_block = re.search(
            r"- Injection:(.*?)(?=\n  - [A-Z]|\Z)", text, re.DOTALL
        )
        assert injection_block, "Could not find Injection nav section"
        assert "04-ssrf.md" in injection_block.group(1), (
            "SSRF (04-ssrf.md) must be in the Injection section"
        )

    def test_ssrf_not_in_access_control(self):
        """SSRF must not appear under Access Control."""
        text = _mkdocs_yml_text()
        access_block = re.search(
            r"- Access Control:(.*?)(?=\n  - [A-Z]|\Z)", text, re.DOTALL
        )
        if access_block:
            assert "04-ssrf.md" not in access_block.group(1), (
                "SSRF (04-ssrf.md) must not be in the Access Control section"
            )

    def test_info_disclosure_in_misconfiguration_not_infra(self):
        """Information Disclosure must be under Misconfiguration, not Infrastructure."""
        text = _mkdocs_yml_text()
        infra_block = re.search(
            r"- Infrastructure:(.*?)(?=\n  - [A-Z]|\Z)", text, re.DOTALL
        )
        if infra_block:
            assert "21-information-disclosure.md" not in infra_block.group(1), (
                "Information Disclosure must not be in Infrastructure"
            )
        misconfig_block = re.search(
            r"- Misconfiguration:(.*?)(?=\n  - [A-Z]|\Z)", text, re.DOTALL
        )
        assert misconfig_block, "Could not find Misconfiguration nav section"
        assert "21-information-disclosure.md" in misconfig_block.group(1), (
            "Information Disclosure (21-information-disclosure.md) must be in Misconfiguration"
        )

    def test_authn_docs_in_authn_section(self):
        """Core auth docs must be under Authentication & Identity."""
        text = _mkdocs_yml_text()
        authn_block = re.search(
            r"- Authentication & Identity:(.*?)(?=\n  - [A-Z]|\Z)", text, re.DOTALL
        )
        assert authn_block, "Could not find Authentication & Identity nav section"
        block = authn_block.group(1)
        for doc in ["12-authentication-session.md", "13-jwt-token-security.md", "14-oauth-oidc.md"]:
            assert doc in block, f"{doc} must be in Authentication & Identity section"
