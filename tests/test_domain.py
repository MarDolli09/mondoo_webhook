"""Fachregeln in ``app.domain`` und das Eingangsmodell."""

import re
import unittest

import tests  # noqa: F401  (Dummy-Umgebung)
from app.core.exceptions import PayloadParsingError
from app.domain.case_text import (
    extract_risk_from_summary,
    strip_asset_suffix,
    strip_mitigate_phrase,
)
from app.domain.finding_types import classify_finding_type, profile_for
from app.domain.identifiers import (
    count_referenced_assets,
    extract_space_id,
    is_automated_identity,
)
from app.domain.priority import determine_priority
from app.domain.scores import (
    NO_FINDING_SCORES,
    normalize_cvss_score,
    normalize_risk_score,
)
from app.models.mondoo import MondooWebhookEvent
from app.services.mondoo.findings import extract_finding_scores, highest_scores
from app.services.mondoo.queries import CVSS_FIELDS, GET_FINDING_SCORES_QUERY

PRIORITY_MAP = {
    "CRITICAL": ("1", "1"),
    "HIGH": ("2", "2"),
    "MEDIUM": ("3", "3"),
    "LOW": ("4", "4"),
}
DEFAULT = ("3", "3")


class CaseTextTest(unittest.TestCase):
    def test_mitigate_phrase_is_dropped_and_severity_kept(self) -> None:
        cases = {
            # Vulnerability
            "[HIGH] Mitigate vulnerability CVE-2026-9999 on M-VM-ProgrammingOld": (
                "[HIGH] CVE-2026-9999 on M-VM-ProgrammingOld"
            ),
            # Advisory
            "[MEDIUM] Mitigate advisory attr vulnerability on Testserver-Ubuntu": (
                "[MEDIUM] attr vulnerability on Testserver-Ubuntu"
            ),
            # End-of-Life
            "[CRITICAL] Mitigate advisory MONDOO-EOL-AZURE-DATA-STUDIO-1 on "
            "multiple assets": (
                "[CRITICAL] MONDOO-EOL-AZURE-DATA-STUDIO-1 on multiple assets"
            ),
            # Fehlkonfiguration: unveraendert
            "[CRITICAL] Enable strict mode on multiple assets": (
                "[CRITICAL] Enable strict mode on multiple assets"
            ),
            # Ohne Schweregrad-Tag und mit der Wendung mitten im Titel
            "Mitigate advisory openssl on host": "openssl on host",
            "[LOW] Fix: Mitigate advisory X": "[LOW] Fix: Mitigate advisory X",
        }
        for title, expected in cases.items():
            self.assertEqual(strip_mitigate_phrase(title), expected, title)

    def test_asset_suffix_is_cut_at_the_last_on(self) -> None:
        cases = {
            "[HIGH] CVE-2026-1 on SUBVWBN": "[HIGH] CVE-2026-1",
            "[HIGH] CVE-2026-1 on multiple assets": "[HIGH] CVE-2026-1",
            # Ein "on" im Namen der Pruefung bleibt erhalten
            "[LOW] Ensure 'Turn on Script Block Logging' is set to 'Enabled' "
            "on multiple assets": (
                "[LOW] Ensure 'Turn on Script Block Logging' is set to 'Enabled'"
            ),
            # Ohne Asset am Ende bleibt der Titel unveraendert
            "[LOW] Rotate keys": "[LOW] Rotate keys",
            "Patch on": "Patch on",
        }
        for title, expected in cases.items():
            self.assertEqual(strip_asset_suffix(title), expected, title)

    def test_risk_rating_from_v2_sentence(self) -> None:
        text = "The combined risk is **HIGH** (72/100) for this asset."
        self.assertEqual(extract_risk_from_summary(text), ("HIGH", "72"))


class IdentifiersTest(unittest.TestCase):
    def test_space_id_from_owner_mrn(self) -> None:
        mrn = "//captain.api.mondoo.app/spaces/eu-nifty-mendeleev-113214"
        self.assertEqual(extract_space_id(mrn), "eu-nifty-mendeleev-113214")
        self.assertIsNone(extract_space_id("//captain.api.mondoo.app"))

    def test_automated_identities(self) -> None:
        self.assertTrue(is_automated_identity(""))
        self.assertTrue(
            is_automated_identity("//iam.api.mondoo.app/identity/user/system")
        )
        self.assertFalse(is_automated_identity("//captain.api.mondoo.app/users/ABC"))

    def test_referenced_assets_are_counted_once(self) -> None:
        scope = "//assets.api.mondoo.app/spaces/eu-x/assets/"
        mrns = [f"{scope}A1", f"{scope}A1", f"{scope}B2", "//captain.api.mondoo.app"]
        self.assertEqual(count_referenced_assets(mrns), 2)


class ScoresTest(unittest.TestCase):
    def test_cvss_comes_from_the_api_on_the_0_to_100_scale(self) -> None:
        # Mondoo liefert 98 fuer CVSS 9.8
        self.assertEqual(normalize_cvss_score(98), (9.8, "9.8"))
        self.assertEqual(normalize_cvss_score(6.9), (6.9, "6.9"))
        self.assertEqual(normalize_cvss_score("NONE"), (None, None))
        # 0 bedeutet "kein CVSS", etwa bei End-of-Life-Hinweisen
        self.assertEqual(normalize_cvss_score(0), (None, None))

    def test_risk_score_keeps_the_0_to_100_scale(self) -> None:
        self.assertEqual(normalize_risk_score(89), "89")
        self.assertEqual(normalize_risk_score("72"), "72")
        self.assertEqual(normalize_risk_score(101), None)
        self.assertEqual(normalize_risk_score(None), None)


class FindingScoresTest(unittest.TestCase):
    """Knoten wie in den Antworten der gefilterten Findings-Abfrage."""

    def test_end_of_life_advisory_without_cvss(self) -> None:
        # MONDOO-EOL-DOTNET-8: cvss.value 0 mit Rating NONE, Risk 89 HIGH
        node = {
            "__typename": "AdvisoryFinding",
            "mrn": "//vadvisor.api.mondoo.app/advisories/MONDOO-EOL-DOTNET-8",
            "riskValue": 89,
            "rating": "HIGH",
            "advisoryCvss": {"value": 0, "rating": "NONE"},
        }

        scores = extract_finding_scores(node)

        self.assertIsNone(scores.cvss_score)
        self.assertIsNone(scores.cvss_rating)
        self.assertEqual((scores.risk_score, scores.risk_rating), ("89", "HIGH"))

    def test_cve_with_cvss_and_risk(self) -> None:
        node = {
            "__typename": "CveFinding",
            "mrn": "//vadvisor.api.mondoo.app/cves/CVE-2026-23450",
            "riskValue": 97,
            "rating": "CRITICAL",
            "cveCvss": {"value": 98, "rating": "CRITICAL"},
        }

        scores = extract_finding_scores(node)

        self.assertEqual((scores.cvss_score, scores.cvss_rating), ("9.8", "CRITICAL"))
        self.assertEqual((scores.risk_score, scores.risk_rating), ("97", "CRITICAL"))

    def test_check_finding_has_a_risk_but_no_cvss(self) -> None:
        # CheckFinding tragen kein cvss-Objekt; baseValue 100 ist kein CVSS-Wert
        node = {
            "__typename": "CheckFinding",
            "mrn": "//policy.api.mondoo.app/queries/cis-azure--8.3.2",
            "riskValue": 100,
            "rating": "CRITICAL",
            "baseValue": 100,
        }

        scores = extract_finding_scores(node)

        self.assertIsNone(scores.cvss_score)
        self.assertEqual((scores.risk_score, scores.risk_rating), ("100", "CRITICAL"))

    def test_highest_risk_of_all_asset_nodes_counts(self) -> None:
        # Die API liefert einen Knoten je betroffenem Asset
        nodes = [
            {"riskValue": 60, "rating": "MEDIUM", "cveCvss": {"value": 75}},
            {"riskValue": 89, "rating": "HIGH", "cveCvss": {"value": 75}},
        ]

        scores = highest_scores(nodes)

        self.assertEqual((scores.risk_score, scores.risk_rating), ("89", "HIGH"))
        self.assertEqual(scores.cvss_score, "7.5")

    def test_without_nodes_there_are_no_scores(self) -> None:
        self.assertEqual(highest_scores([]), NO_FINDING_SCORES)

    def test_cvss_is_requested_under_one_alias_per_type(self) -> None:
        # cvss ist je Typ mal CvssScore!, mal CvssScore. Ohne Alias lehnt Mondoo
        # die ganze Abfrage ab (HTTP 422, GRAPHQL_VALIDATION_FAILED).
        aliases = re.findall(r"(\w+):\s*cvss\s*\{", GET_FINDING_SCORES_QUERY)
        self.assertEqual(tuple(aliases), CVSS_FIELDS)
        self.assertNotRegex(GET_FINDING_SCORES_QUERY, r"(?m)^\s*cvss\s*\{")


class PriorityTest(unittest.TestCase):
    def test_sources(self) -> None:
        cvss = determine_priority("[LOW] x", "HIGH", None, PRIORITY_MAP, DEFAULT)
        risk = determine_priority("x", None, "CRITICAL", PRIORITY_MAP, DEFAULT)
        title = determine_priority("[HIGH] x", None, None, PRIORITY_MAP, DEFAULT)
        default = determine_priority("x", None, None, PRIORITY_MAP, DEFAULT)
        self.assertEqual((cvss.urgency, cvss.source), ("2", "cvss"))
        self.assertEqual((risk.urgency, risk.source), ("1", "mondoo_risk"))
        self.assertEqual((title.urgency, title.source), ("2", "title"))
        self.assertEqual((default.urgency, default.source), ("3", "default"))

    def test_mondoo_risk_takes_precedence_over_cvss(self) -> None:
        # CVE-2026-65775: CVSS 7.8 (HIGH), Mondoo-Risk 100 (CRITICAL)
        both = determine_priority(
            "[CRITICAL] x", "HIGH", "CRITICAL", PRIORITY_MAP, DEFAULT
        )
        self.assertEqual(
            (both.urgency, both.impact, both.source), ("1", "1", "mondoo_risk")
        )
        # Ein Rating ohne Zuordnung wird uebersprungen, dann gilt das CVSS
        unmapped = determine_priority("x", "HIGH", "NONE", PRIORITY_MAP, DEFAULT)
        self.assertEqual((unmapped.urgency, unmapped.source), ("2", "cvss"))

    def test_medium_title_counts_as_default(self) -> None:
        medium = determine_priority("[MEDIUM] x", None, None, PRIORITY_MAP, DEFAULT)
        self.assertEqual(medium.source, "default")
        self.assertEqual(medium.match.kind, "title")


class FindingTypeTest(unittest.TestCase):
    def test_classification_and_profiles(self) -> None:
        patterns = {
            "/cves/": "vulnerability",
            "/advisories/MONDOO-EOL-": "end-of-life",
            "/advisories/": "advisories",
            "/queries/": "misconfiguration",
        }
        eol = "//vadvisor.api.mondoo.app/advisories/MONDOO-EOL-WIN-2012"
        self.assertEqual(classify_finding_type([eol], patterns), "end-of-life")
        self.assertEqual(classify_finding_type(["//x/checks/1"], patterns), "other")
        self.assertEqual(profile_for("end-of-life").servicenow_type, "end-of-life")
        self.assertEqual(profile_for("unbekannt").servicenow_type, "other")


class WebhookEventTest(unittest.TestCase):
    def test_body_wrapper_is_optional_and_nulls_are_ignored(self) -> None:
        case = {"mrn": "m", "title": None, "vulnerabilityRefs": None}
        wrapped = MondooWebhookEvent.from_payload({"body": {"type": "T", "case": case}})
        flat = MondooWebhookEvent.from_payload({"type": "T", "case": case})
        self.assertEqual(wrapped, flat)
        self.assertEqual(wrapped.case.title, "")
        self.assertEqual(wrapped.case.finding_refs, [])

    def test_missing_mrn_is_rejected(self) -> None:
        with self.assertRaises(PayloadParsingError):
            MondooWebhookEvent.from_payload({"body": {"case": {"title": "x"}}})


if __name__ == "__main__":
    unittest.main()
