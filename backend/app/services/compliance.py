"""Mapping findings onto the frameworks people report against.

Two static tables, both keyed by CWE, because that is the one classification every scanner already gives us:

- the **OWASP Top 10 (2021)**, using OWASP's own CWE-to-category mapping;
- the **CWE Top 25 Most Dangerous Software Weaknesses (2024)**, the MITRE/CISA list.

Nothing here is fetched at runtime: the lists change once a year at most, and a report that quietly changes
its own scale between two runs is worse than one that is a year out of date. The edition is part of the
response, so a printed report says which one it was measured against.

No CWE belongs to two OWASP categories, but a finding carrying several CWEs can still reach several
categories, so the category counts do not add up to the number of findings. ``unmapped`` counts the
findings that reach no category at all — usually SCA findings, whose CWE their scanner never filled in —
which is the honest way to show how much of the estate this view misses.
"""

from dataclasses import dataclass

OWASP_EDITION = "2021"
CWE_TOP_25_EDITION = "2024"


@dataclass(frozen=True)
class Category:
    id: str
    title: str
    cwes: frozenset[str]


def _cwes(*numbers: int) -> frozenset[str]:
    return frozenset(f"CWE-{n}" for n in numbers)


# OWASP's published mapping (owasp.org/Top10). Kept whole rather than trimmed to "the interesting ones",
# so a finding is counted wherever OWASP would count it.
OWASP_TOP_10: tuple[Category, ...] = (
    Category(
        "A01",
        "Broken Access Control",
        _cwes(
            22,
            23,
            35,
            59,
            200,
            201,
            219,
            264,
            275,
            276,
            284,
            285,
            352,
            359,
            377,
            402,
            425,
            441,
            497,
            538,
            540,
            548,
            552,
            566,
            601,
            639,
            651,
            668,
            706,
            862,
            863,
            913,
            922,
            1275,
        ),
    ),
    Category(
        "A02",
        "Cryptographic Failures",
        _cwes(
            261,
            296,
            310,
            319,
            321,
            322,
            323,
            324,
            325,
            326,
            327,
            328,
            329,
            330,
            331,
            335,
            336,
            337,
            338,
            340,
            347,
            523,
            720,
            757,
            759,
            760,
            780,
            818,
            916,
        ),
    ),
    Category(
        "A03",
        "Injection",
        _cwes(
            20,
            74,
            75,
            77,
            78,
            79,
            80,
            83,
            87,
            88,
            89,
            90,
            91,
            93,
            94,
            95,
            96,
            97,
            98,
            99,
            100,
            113,
            116,
            138,
            184,
            470,
            471,
            564,
            610,
            643,
            644,
            652,
            917,
        ),
    ),
    Category(
        "A04",
        "Insecure Design",
        _cwes(
            73,
            183,
            209,
            213,
            235,
            256,
            257,
            266,
            269,
            280,
            311,
            312,
            313,
            316,
            419,
            430,
            434,
            444,
            451,
            472,
            501,
            522,
            525,
            539,
            579,
            598,
            602,
            642,
            646,
            650,
            653,
            656,
            657,
            799,
            807,
            840,
            841,
            927,
            1021,
            1173,
        ),
    ),
    Category(
        "A05",
        "Security Misconfiguration",
        _cwes(
            2, 11, 13, 15, 16, 260, 315, 520, 526, 537, 541, 547, 611, 614, 756, 776, 942, 1004, 1032, 1174
        ),
    ),
    Category("A06", "Vulnerable and Outdated Components", _cwes(937, 1035, 1104)),
    Category(
        "A07",
        "Identification and Authentication Failures",
        _cwes(
            255,
            259,
            287,
            288,
            290,
            294,
            295,
            297,
            300,
            302,
            304,
            306,
            307,
            346,
            384,
            521,
            613,
            620,
            640,
            798,
            940,
            1216,
        ),
    ),
    Category(
        "A08",
        "Software and Data Integrity Failures",
        _cwes(345, 353, 426, 494, 502, 565, 784, 829, 830, 915),
    ),
    Category("A09", "Security Logging and Monitoring Failures", _cwes(117, 223, 532, 778)),
    Category("A10", "Server-Side Request Forgery", _cwes(918)),
)

# The 2024 list, in rank order. The name is the CWE's own, shortened to what fits in a table.
CWE_TOP_25: tuple[tuple[int, str, str], ...] = (
    (1, "CWE-79", "Cross-site Scripting"),
    (2, "CWE-787", "Out-of-bounds Write"),
    (3, "CWE-89", "SQL Injection"),
    (4, "CWE-352", "Cross-Site Request Forgery"),
    (5, "CWE-22", "Path Traversal"),
    (6, "CWE-125", "Out-of-bounds Read"),
    (7, "CWE-78", "OS Command Injection"),
    (8, "CWE-416", "Use After Free"),
    (9, "CWE-862", "Missing Authorization"),
    (10, "CWE-434", "Unrestricted Upload of Dangerous File Type"),
    (11, "CWE-94", "Code Injection"),
    (12, "CWE-20", "Improper Input Validation"),
    (13, "CWE-77", "Command Injection"),
    (14, "CWE-287", "Improper Authentication"),
    (15, "CWE-269", "Improper Privilege Management"),
    (16, "CWE-502", "Deserialization of Untrusted Data"),
    (17, "CWE-200", "Exposure of Sensitive Information"),
    (18, "CWE-863", "Incorrect Authorization"),
    (19, "CWE-918", "Server-Side Request Forgery"),
    (20, "CWE-119", "Improper Restriction of Memory Buffer Operations"),
    (21, "CWE-476", "NULL Pointer Dereference"),
    (22, "CWE-798", "Use of Hard-coded Credentials"),
    (23, "CWE-190", "Integer Overflow or Wraparound"),
    (24, "CWE-400", "Uncontrolled Resource Consumption"),
    (25, "CWE-306", "Missing Authentication for Critical Function"),
)

TOP_25_RANK: dict[str, int] = {cwe: rank for rank, cwe, _ in CWE_TOP_25}
TOP_25_NAME: dict[str, str] = {cwe: name for _, cwe, name in CWE_TOP_25}
ALL_MAPPED_CWES: frozenset[str] = frozenset().union(*(c.cwes for c in OWASP_TOP_10))


def normalise(value: str) -> str:
    """``79``, ``cwe-79`` and ``CWE-79`` are the same weakness."""
    text = str(value).strip().upper()
    return text if text.startswith("CWE-") else f"CWE-{text}"


def categories_for(cwes: list[str] | None) -> list[str]:
    """Every OWASP category a finding's weaknesses reach. Pure, so it is easy to test on its own."""
    found = {normalise(c) for c in cwes or []}
    return [c.id for c in OWASP_TOP_10 if found & c.cwes]
