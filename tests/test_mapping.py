"""ServiceNow-Mapping: Titel, Katalogvariablen, RITM-Felder und Beobachter."""

import unittest

import tests  # noqa: F401  (Dummy-Umgebung)
from app.models.case import NormalizedCase
from app.models.mondoo import MondooEventType
from app.services.servicenow import mapping

ALEXANDER = "//captain.api.mondoo.app/users/2nZF38ZPg7vhizUrgIHqRF1aUwu"

# Variablen des ServiceNow-Formulars "Mondoo Vulnerability" in Formularreihenfolge
FORM_VARIABLES = [
    "mondoo_title",
    "mondoo_cve",
    "cvss_score",
    "cvss_rating",
    "risk_rating",
    "risk_score",
    "urgency",
    "impact",
    "mondoo_space",
    "finding_type",
    "ticket_url",
    "assets_count",
    "mondoo_created_by",
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
    def test_title_has_mondoo_prefix_without_severity(self) -> None:
        self.assertEqual(
            mapping.ticket_title(make_case()),
            "Mondoo - Mitigate vulnerability CVE-2024-0056 on multiple assets",
        )

    def test_long_title_is_truncated_to_short_description_limit(self) -> None:
        title = mapping.ticket_title(make_case(title="[LOW] " + "x" * 300))
        self.assertEqual(len(title), 160)
        self.assertTrue(title.endswith("…"))


class CatalogVariablesTest(unittest.TestCase):
    def test_variables_match_servicenow_form(self) -> None:
        variables = mapping.build_catalog_variables(make_case())
        self.assertEqual(list(variables), FORM_VARIABLES)
        self.assertEqual(variables["assets_count"], "4")
        self.assertEqual((variables["urgency"], variables["impact"]), ("1", "1"))
        self.assertEqual(variables["mondoo_created_by"], "Alexander Haller")
        self.assertTrue(variables["mondoo_title"].startswith("Mondoo - "))


class TaskFieldsTest(unittest.TestCase):
    def test_create_fields_without_assignment_group(self) -> None:
        body = mapping.build_create_fields(
            make_case(), opened_by_sys_id="u1", watcher_sys_ids=["w1", "w2"]
        )
        self.assertNotIn("assignment_group", body)
        self.assertNotIn("urgency", body)
        self.assertNotIn("impact", body)
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
