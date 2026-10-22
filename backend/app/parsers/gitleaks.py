"""Gitleaks JSON (`gitleaks detect --report-format json`).

The report contains the secrets themselves. Guardiano stores the rule, the location and a redacted
fingerprint of the match, never the secret: a vulnerability manager must not become a second place the
credential leaks from.
"""

from typing import Any

from app.parsers.base import NormalizedFinding, ParsedReport, ParseError, to_int, truncate

# Everything Gitleaks reports is a leaked credential; the rule decides how urgent.
_CRITICAL_HINTS = ("private-key", "private_key", "aws", "gcp", "azure", "stripe", "token", "secret-key")


def _severity(rule_id: str, description: str) -> str:
    text = f"{rule_id} {description}".lower()
    return "critical" if any(hint in text for hint in _CRITICAL_HINTS) else "high"


def redact(match: str | None, secret: str | None) -> str | None:
    """Keep enough of the line to recognise it, with the secret blanked out.

    Fails closed. The line is only kept when the secret is a literal substring of it, because that is
    the only case where we know which part of the line is the credential. When Gitleaks reports no
    Secret, or normalises it so it no longer appears in Match, the whole line is dropped: the promise
    at the top of this module has to hold for every report, not only the well-formed ones. The
    finding still carries the file and line, which is how you actually go and look at it.
    """
    if not match or not secret or secret not in match:
        return None
    return truncate(match.replace(secret, "*" * 12).strip(), 400)


def parse(data: Any) -> ParsedReport:
    if not isinstance(data, list):
        raise ParseError("Gitleaks reports are a JSON array of findings")

    findings: list[NormalizedFinding] = []
    for item in data:
        if not isinstance(item, dict):
            raise ParseError("Gitleaks findings must be objects")
        rule_id = str(item.get("RuleID") or "secret")
        description = str(item.get("Description") or "Hard-coded secret")
        commit = str(item.get("Commit") or "")[:12]
        author = item.get("Author") or item.get("Email")
        context = [f"Rule: {rule_id}"]
        if commit:
            context.append(f"Commit: {commit}")
        if author:
            context.append(f"Author: {author}")
        findings.append(
            NormalizedFinding(
                type="sast",
                title=truncate(description, 500),
                severity=_severity(rule_id, description),
                tool_name="Gitleaks",
                description="\n".join(context),
                remediation=("Revoke the credential, then remove it from the file and from the git history."),
                cwe=["CWE-798"],  # use of hard-coded credentials
                rule_id=rule_id,
                file_path=item.get("File"),
                line_start=to_int(item.get("StartLine")),
                line_end=to_int(item.get("EndLine")),
                # Redacted: the secret never reaches the database.
                snippet=redact(item.get("Match"), item.get("Secret")),
                fingerprint=truncate(item.get("Fingerprint"), 200),
            )
        )
    return ParsedReport("gitleaks", "sast", "Gitleaks", None, findings)
