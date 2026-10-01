"""ServiceNow-Mapping: Titel, Katalogvariablen, RITM-Felder und Beobachter."""

import unittest

import tests  # noqa: F401  (Dummy-Umgebung)
from app.models.case import NormalizedCase
from app.models.mondoo import MondooEventType
from app.services.servicenow import mapping

ALEXANDER = "//captain.api.mondoo.app/users/2nZF38ZPg7vhizUrgIHqRF1aUwu"

# Variablen des ServiceNow-Formulars "Mondoo Vulnerability" in Formularreihenfolge
FORM_VARIABLES = [
    "cve",
    "cvss_score",
    "cvss_risk_rating",
    "mondoo_risk_rating",
    "mondoo_risk_score",
    "mondoo_space",
    "finding_type",
    "mondoo_ticket_url",
    "number_of_affected_assets",
    "created_by",
    "urgency",
    "impact",
    "mondoo_mrn",
]


def make_case(**overrides: object) -> NormalizedCase:
    values: dict[str, object] = {
        "raw_event_type": "TYPE_CREATED",
        "event_type": MondooEventType.CREATED,
        "mrn": "//policy.api.mondoo.app/spaces/s/cases/C1",
        "owner_mrn": "//captain.api.mondoo.app/spaces/s",
        "mondoo_space": "Server",
        "finding_type": "vulnerability",
        "finding_cve": "CVE-2024-0056",
        "assets_count": 4,
        "urgency": "1",
        "impact": "1",
        "priority_source": "title",
        "title": "[CRITICAL] Mitigate vulnerability CVE-2024-0056 on multiple assets",
        "ticket_url": "https://app.mondoo.com/space/tickets/x",
        "created_at": "2026-08-13T15:05:10Z",
        "updated_at": "2026-08-14T09:00:00Z",
        "created_by": ALEXANDER,
    }
    values.update(overrides)
    return NormalizedCase.model_validate(values)


class TitleTest(unittest.TestCase):
    def test_title_keeps_severity_and_drops_mitigate_phrase_and_asset(self) -> None:
        # Originaltitel aus Mondoo und der erwartete Titel in ServiceNow
        cases = {
            "[CRITICAL] Mitigate advisory MONDOO-EOL-ORACLE-JDK-18 on SUBVWBN": (
                "Mondoo - [CRITICAL] MONDOO-EOL-ORACLE-JDK-18"
            ),
            "[CRITICAL] Mitigate advisory MONDOO-EOL-DOTNET-6 on multiple assets": (
                "Mondoo - [CRITICAL] MONDOO-EOL-DOTNET-6"
            ),
            "[CRITICAL] Ensure 'Configures LSASS to run as a protected process' is "
            "set to 'Enabled: Enabled with UEFI Lock' on multiple assets": (
                "Mondoo - [CRITICAL] Ensure 'Configures LSASS to run as a protected "
                "process' is set to 'Enabled: Enabled with UEFI Lock'"
            ),
            "[CRITICAL] Mitigate advisory August 11, 2026—KB5120233 (OS Build "
            "26100.33296) on multiple assets": (
                "Mondoo - [CRITICAL] August 11, 2026—KB5120233 (OS Build 26100.33296)"
            ),
            "[CRITICAL] Mitigate vulnerability CVE-2026-49179 on multiple assets": (
                "Mondoo - [CRITICAL] CVE-2026-49179"
            ),
        }
        for title, expected in cases.items():
            self.assertEqual(mapping.ticket_title(make_case(title=title)), expected)

    def test_long_title_is_truncated_to_short_description_limit(self) -> None:
        title = mapping.ticket_title(make_case(title="[LOW] " + "x" * 300))
        self.assertEqual(len(title), 160)
        self.assertTrue(title.endswith("…"))


class CatalogVariablesTest(unittest.TestCase):
    def test_variables_match_servicenow_form(self) -> None:
        variables = mapping.build_catalog_variables(make_case())
        self.assertEqual(list(variables), FORM_VARIABLES)
        self.assertEqual(variables["number_of_affected_assets"], "4")
        self.assertEqual((variables["urgency"], variables["impact"]), ("1", "1"))
        self.assertEqual(variables["created_by"], "Alexander Haller")


class TaskFieldsTest(unittest.TestCase):
    def test_create_fields_without_assignment_group(self) -> None:
        body = mapping.build_create_fields(
            make_case(), opened_by_sys_id="u1", watcher_sys_ids=["w1", "w2"]
        )
        self.assertNotIn("assignment_group", body)
        # Wie die Katalogvariablen, sonst bliebe das RITM auf 3 - Low
        self.assertEqual((body["urgency"], body["impact"]), ("1", "1"))
        self.assertEqual(body["watch_list"], "w1,w2")
        self.assertEqual(body["state"], "1")

    def test_update_fields_with_asset_count_and_default_priority(self) -> None:
        case = make_case(
            raw_event_type="TYPE_DELETED",
            event_type=MondooEventType.DELETED,
            priority_source="default",
        )
        body = mapping.build_update_fields(case)
        self.assertTrue(body["work_notes"].endswith("| Betroffene Assets: 4"))
        self.assertNotIn("urgency", body)
        self.assertEqual(body["state"], "7")

    def test_watchers_add_mapped_human_creator(self) -> None:
        watchers = mapping.watcher_identifiers(make_case())
        self.assertEqual(watchers, ["lars.siefert@mosca.com", "Alexander Haller"])
        automated = make_case(is_automated=True)
        self.assertEqual(
            mapping.watcher_identifiers(automated), ["lars.siefert@mosca.com"]
        )
        self.assertEqual(mapping.creator_display_name(automated), "Mondoo-Drift")


if __name__ == "__main__":
    unittest.main()
