"""
AutoSOC Day 8 - Normalized Event Query Contract Tests

Verifies:
- Representative synthetic query examples for Suricata, Sysmon, and Zeek
- Valid query combinations and defaults
- Invalid filters, unknown query parameters, and SQL-injection-safe constraints
- Allowlisted sort_by / sort_order validation
- Pagination boundaries (limit [1, 100], offset [0, 10000])
- Timezone normalization and reversed time-range rejection
- Search allowlist (raw_payload explicitly excluded) and LIKE escaping
- Response schema consistency with api_schemas.py
"""

from pathlib import Path
import sys
import unittest

# Ensure backend root is on sys.path
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from app.events.query_contract import (
    DEFAULT_QUERY_LIMIT,
    DEFAULT_QUERY_OFFSET,
    EXPLICITLY_FORBIDDEN_SEARCH_FIELDS,
    MAX_QUERY_LIMIT,
    MAX_QUERY_OFFSET,
    MAX_SEARCH_LENGTH,
    NormalizedEventQueryParams,
    NormalizedEventSortField,
    SEARCHABLE_NORMALIZED_EVENT_FIELDS,
    SORT_FIELD_TO_ORM_COLUMN,
    SortOrderEnum,
    escape_like_pattern,
    validate_normalized_event_query,
)
from app.events.schemas import (
    EventCategoryEnum,
    NormalizationStatusEnum,
    SourceTypeEnum,
)


# ---------------------------------------------------------------------------
# Representative Synthetic Query Fixtures (Suricata, Sysmon, Zeek)
# ---------------------------------------------------------------------------

SYNTHETIC_SURICATA_QUERY = {
    "source_type": "suricata",
    "normalization_status": "normalized",
    "event_category": "alert",
    "event_type": "alert.ids",
    "severity": 4,
    "start_time": "2026-09-21T06:00:00Z",
    "end_time": "2026-09-21T08:00:00Z",
    "search": "198.51.100.42",
    "sort_by": "timestamp",
    "sort_order": "desc",
    "limit": 25,
    "offset": 0,
}

SYNTHETIC_SYSMON_QUERY = {
    "source_type": "sysmon",
    "normalization_status": "normalized_with_warnings",
    "event_category": "process",
    "event_type": "process.create",
    "severity": 1,
    "search": "cmd.exe",
    "sort_by": "created_at",
    "sort_order": "desc",
    "limit": 50,
    "offset": 50,
}

SYNTHETIC_ZEEK_QUERY = {
    "source_type": "zeek",
    "event_category": "network",
    "event_type": "network.dns",
    "start_time": "2026-09-21T12:30:00+05:30",
    "end_time": "2026-09-21T08:00:00Z",
    "search": "sub.example.invalid",
    "sort_by": "severity",
    "sort_order": "asc",
    "limit": 10,
    "offset": 0,
}


class TestValidQueryCombinationsAndFixtures(unittest.TestCase):
    """Verify defaults and representative Suricata, Sysmon, and Zeek queries."""

    def test_default_query_params(self):
        params = NormalizedEventQueryParams()
        self.assertIsNone(params.source_type)
        self.assertIsNone(params.normalization_status)
        self.assertIsNone(params.event_category)
        self.assertIsNone(params.event_type)
        self.assertIsNone(params.severity)
        self.assertIsNone(params.start_time)
        self.assertIsNone(params.end_time)
        self.assertIsNone(params.search)
        self.assertEqual(params.sort_by, NormalizedEventSortField.CREATED_AT)
        self.assertEqual(params.sort_order, SortOrderEnum.DESC)
        self.assertEqual(params.limit, DEFAULT_QUERY_LIMIT)
        self.assertEqual(params.offset, DEFAULT_QUERY_OFFSET)

    def test_synthetic_suricata_sysmon_zeek_queries_accepted(self):
        res_suri = validate_normalized_event_query(SYNTHETIC_SURICATA_QUERY)
        self.assertTrue(res_suri.valid)
        self.assertEqual(res_suri.params.source_type, SourceTypeEnum.SURICATA)
        self.assertEqual(res_suri.params.severity, 4)
        self.assertEqual(res_suri.params.sort_by, NormalizedEventSortField.TIMESTAMP)

        res_sysmon = validate_normalized_event_query(SYNTHETIC_SYSMON_QUERY)
        self.assertTrue(res_sysmon.valid)
        self.assertEqual(res_sysmon.params.source_type, SourceTypeEnum.SYSMON)
        self.assertEqual(
            res_sysmon.params.normalization_status,
            NormalizationStatusEnum.NORMALIZED_WITH_WARNINGS,
        )

        res_zeek = validate_normalized_event_query(SYNTHETIC_ZEEK_QUERY)
        self.assertTrue(res_zeek.valid)
        self.assertEqual(res_zeek.params.source_type, SourceTypeEnum.ZEEK)
        # +05:30 converted cleanly to UTC
        self.assertEqual(res_zeek.params.start_time, "2026-09-21T07:00:00.000Z")
        self.assertEqual(res_zeek.params.sort_order, SortOrderEnum.ASC)

    def test_empty_optional_strings_normalized_to_none(self):
        res = validate_normalized_event_query(
            {
                "source_type": "   ",
                "normalization_status": "",
                "event_category": "",
                "event_type": "  ",
                "start_time": "",
                "end_time": " ",
                "search": "   ",
            }
        )
        self.assertTrue(res.valid)
        self.assertIsNone(res.params.source_type)
        self.assertIsNone(res.params.normalization_status)
        self.assertIsNone(res.params.event_category)
        self.assertIsNone(res.params.event_type)
        self.assertIsNone(res.params.start_time)
        self.assertIsNone(res.params.end_time)
        self.assertIsNone(res.params.search)


class TestInvalidFiltersAndSortValidation(unittest.TestCase):
    """Verify rejection of invalid filter values, unknown keys, and unapproved sort fields."""

    def test_invalid_enum_and_severity_filters_rejected(self):
        for bad_query in (
            {"source_type": "unknown_siem"},
            {"normalization_status": "invented_status"},
            {"event_category": "ransomware"},
            {"severity": 0},
            {"severity": 6},
            {"severity": True},
            {"event_type": "alert.ids; DROP TABLE normalized_events;--"},
        ):
            res = validate_normalized_event_query(bad_query)
            self.assertFalse(res.valid, f"Expected failure for {bad_query}")
            self.assertTrue(len(res.errors) >= 1)

    def test_unknown_query_parameter_rejected(self):
        res = validate_normalized_event_query({"raw_payload": "secret"})
        self.assertFalse(res.valid)
        self.assertEqual(res.errors[0].field, "raw_payload")

    def test_invalid_sort_fields_and_direction_rejected(self):
        for bad_sort in ("raw_payload", "host", "metadata", "id; DROP TABLE"):
            res = validate_normalized_event_query({"sort_by": bad_sort})
            self.assertFalse(res.valid, f"Expected failure for sort_by={bad_sort}")

        res_order = validate_normalized_event_query({"sort_order": "random"})
        self.assertFalse(res_order.valid)

    def test_all_supported_statuses_accepted(self):
        for status_val in ("normalized", "normalized_with_warnings", "failed", "unsupported"):
            res = validate_normalized_event_query({"normalization_status": status_val})
            self.assertTrue(res.valid, f"Status {status_val} should be accepted")
            self.assertEqual(res.params.normalization_status.value, status_val)


class TestPaginationAndTimeRangeBoundaries(unittest.TestCase):
    """Verify pagination bounds and UTC time-range validation."""

    def test_pagination_boundaries(self):
        self.assertTrue(validate_normalized_event_query({"limit": 1, "offset": 0}).valid)
        self.assertTrue(
            validate_normalized_event_query(
                {"limit": MAX_QUERY_LIMIT, "offset": MAX_QUERY_OFFSET}
            ).valid
        )

        for bad_page in (
            {"limit": 0},
            {"limit": -1},
            {"limit": MAX_QUERY_LIMIT + 1},
            {"limit": True},
            {"offset": -1},
            {"offset": MAX_QUERY_OFFSET + 1},
            {"offset": False},
        ):
            res = validate_normalized_event_query(bad_page)
            self.assertFalse(res.valid, f"Expected failure for {bad_page}")

    def test_time_range_validation_and_tz_rules(self):
        # Naive timestamps without timezone must be rejected
        for naive_field in ("start_time", "end_time"):
            res = validate_normalized_event_query({naive_field: "2026-09-21T06:00:00"})
            self.assertFalse(res.valid)

        # Unparseable timestamp rejected
        self.assertFalse(
            validate_normalized_event_query({"start_time": "not-a-timestamp"}).valid
        )

        # Reversed time range rejected
        reversed_range = {
            "start_time": "2026-09-21T09:00:00Z",
            "end_time": "2026-09-21T08:00:00Z",
        }
        self.assertFalse(validate_normalized_event_query(reversed_range).valid)

        # Equal start_time == end_time accepted
        equal_range = {
            "start_time": "2026-09-21T08:00:00Z",
            "end_time": "2026-09-21T08:00:00Z",
        }
        self.assertTrue(validate_normalized_event_query(equal_range).valid)


class TestSearchSecurityAndResponseConsistency(unittest.TestCase):
    """Verify search field allowlist, wildcard escaping, and schema alignment."""

    def test_raw_payload_excluded_from_searchable_fields(self):
        searchable = set(SEARCHABLE_NORMALIZED_EVENT_FIELDS)
        self.assertTrue(searchable.isdisjoint(EXPLICITLY_FORBIDDEN_SEARCH_FIELDS))
        self.assertNotIn("raw_payload", searchable)
        self.assertNotIn("raw_event", searchable)

    def test_search_length_and_like_escaping(self):
        too_long = "a" * (MAX_SEARCH_LENGTH + 1)
        self.assertFalse(validate_normalized_event_query({"search": too_long}).valid)

        escaped = escape_like_pattern("100%_admin\\test")
        self.assertEqual(escaped, "100\\%\\_admin\\\\test")

    def test_sort_mapping_covers_all_sort_enum_members(self):
        self.assertEqual(
            set(SORT_FIELD_TO_ORM_COLUMN.keys()), set(NormalizedEventSortField)
        )

    def test_api_schemas_list_response_includes_pagination_fields(self):
        api_schemas_path = (
            backend_dir / "app" / "events" / "api_schemas.py"
        ).read_text(encoding="utf-8")
        for expected_field in ("items:", "count:", "total:", "limit:", "offset:", "has_more:"):
            self.assertIn(expected_field, api_schemas_path)


if __name__ == "__main__":
    unittest.main()
