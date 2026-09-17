"""Fachregeln in ``app.domain`` und das Eingangsmodell."""

import unittest

import tests  # noqa: F401  (Dummy-Umgebung)
from app.core.exceptions import PayloadParsingError
from app.domain.case_text import extract_risk_from_summary, strip_severity_prefix
from app.domain.cvss import calculate_rating_from_score, normalize_cvss_score
from app.domain.finding_types import classify_finding_type, profile_for
from app.domain.identifiers import (
    count_referenced_assets,
    extract_space_id,
    is_automated_identity,
)
from app.domain.priority import determine_priority
from app.models.mondoo import MondooWebhookEvent

PRIORITY_MAP = {
    "CRITICAL": ("1", "1"),
    "HIGH": ("2", "2"),
    "MEDIUM": ("3", "3"),
    "LOW": ("4", "4"),
}
DEFAULT = ("3", "3")


class CaseTextTest(unittest.TestCase):
    def test_strip_severity_prefix_removes_only_leading_tag(self) -> None:
        self.assertEqual(strip_severity_prefix("[CRITICAL] Patch host"), "Patch host")
        self.assertEqual(strip_severity_prefix("[NONE] Ensure keys"), "Ensure keys")
        self.assertEqual(
            strip_severity_prefix("Patch [HIGH] host"), "Patch [HIGH] host"
        )

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


class CvssTest(unittest.TestCase):
    def test_normalize_scales_tenths(self) -> None:
        self.assertEqual(normalize_cvss_score(81), (8.1, "8.1"))
        self.assertEqual(normalize_cvss_score("NONE"), (None, None))
        self.assertEqual(normalize_cvss_score(150), (None, None))

    def test_rating_from_thresholds(self) -> None:
        thresholds = {"CRITICAL": 9.0, "HIGH": 7.0, "MEDIUM": 4.0, "LOW": 0.1}
        self.assertEqual(calculate_rating_from_score(7.5, thresholds), "HIGH")
        self.assertIsNone(calculate_rating_from_score(0.0, thresholds))


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
        self.assertFalse(profile_for("misconfiguration").resolves_cvss)
        self.assertFalse(profile_for("unbekannt").resolves_cvss)


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
