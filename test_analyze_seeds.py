import contextlib
import io
import tempfile
import unittest

import analyze_seeds


class ClassifyAgentTest(unittest.TestCase):
    def test_classifies_any_satoshi_user_agent_as_core(self):
        self.assertEqual(analyze_seeds.classify_agent("/Satoshi:30.0.0/"), "core")
        self.assertEqual(
            analyze_seeds.classify_agent("/Satoshi:30.0.0/Alternative:1.0/"),
            "core",
        )

    def test_classifies_non_satoshi_user_agents_as_other(self):
        self.assertEqual(analyze_seeds.classify_agent("/Alternative:1.0/"), "other")
        self.assertEqual(analyze_seeds.classify_agent("/FakeSatoshi:1.0/"), "other")

    def test_classifies_empty_reported_user_agent_as_other(self):
        self.assertEqual(analyze_seeds.classify_agent(""), "other")


class BuildDataTest(unittest.TestCase):
    def test_builds_generic_core_and_other_statistics(self):
        rows = [
            {
                "address": "192.0.2.1:8333",
                "good": 1,
                "last_seen": 1_000,
                "reliability": {"2h": 1.0, "8h": 1.0, "1d": 1.0, "1w": 0.9, "1m": 0.8},
                "blocks": 900_000,
                "services": 0x849,
                "protocol_version": 70016,
                "user_agent": "/Satoshi:30.0.0/Alternative:1.0/",
                "last_tried": 10_000,
                "try_count": 10,
            },
            {
                "address": "198.51.100.1:8333",
                "good": 1,
                "last_seen": 900,
                "reliability": {"2h": 0.9, "8h": 0.8, "1d": 0.7, "1w": 0.6, "1m": 0.5},
                "blocks": 899_995,
                "services": 0x9,
                "protocol_version": 70015,
                "user_agent": "/Alternative:1.0/",
                "last_tried": 5_000,
                "try_count": 5,
            },
            {
                "address": "203.0.113.1:8333",
                "good": 0,
                "last_seen": 0,
                "reliability": {"2h": 0.0, "8h": 0.0, "1d": 0.0, "1w": 0.0, "1m": 0.0},
                "blocks": 0,
                "services": 0,
                "protocol_version": 0,
                "user_agent": "",
                "last_tried": 1,
                "try_count": 1,
            },
        ]
        asmap = {
            "tables": {4: {0: {0: "AS64500"}}, 6: {}},
            "lengths": {4: [0], 6: []},
            "masks": {4: {0: 0}, 6: {}},
        }

        with contextlib.redirect_stdout(io.StringIO()):
            data = analyze_seeds.build_data(
                rows,
                asmap,
                {"AS64500": {"name": "Example", "category": "hosting"}},
            )

        self.assertEqual(
            data["summary"],
            {"attempted": 3, "contacted": 2, "good": 2, "no_handshake": 1},
        )
        self.assertEqual(data["classification"]["labels"], ["Bitcoin Core", "Other"])
        self.assertEqual(data["classification"]["keys"], ["core", "other"])
        self.assertEqual(data["classification"]["contacted"], [1, 1])
        self.assertEqual(data["networks"]["attempted"], [3, 0, 0, 0])
        self.assertEqual(data["freshness"]["counts"], [2, 0, 0, 0, 0])
        self.assertEqual(data["activity"]["attempts"]["counts"], [1, 2, 3, 3])
        self.assertEqual(data["activity"]["handshakes"]["counts"], [2, 2, 2, 2])
        self.assertEqual(data["chain_health"]["counts"], [1, 1, 0, 0, 0])
        self.assertEqual(data["service_flags"]["scope_count"], 2)
        self.assertEqual(data["infrastructure"]["distinct_prefixes"], 2)
        self.assertEqual(data["infrastructure"]["distinct_asns"], 1)
        self.assertEqual(
            set(data),
            {
                "generated_at",
                "summary",
                "classification",
                "top_user_agents",
                "networks",
                "freshness",
                "activity",
                "reliability",
                "chain_health",
                "service_flags",
                "infrastructure",
                "prefix_table",
                "asn_categories",
                "asn_table",
                "custom_user_agents",
                "overlay_fingerprints",
            },
        )
        self.assertEqual(
            set(data["prefix_table"]["rows"][0]),
            {
                "prefix",
                "asn",
                "asn_name",
                "asn_category",
                "asn_country",
                "asn_country_code",
                "asn_tooltip",
                "total",
                "core",
                "other",
                "distinct_fingerprints",
                "dominant_fingerprint_share",
            },
        )
        self.assertEqual(
            set(data["asn_table"]["rows"][0]),
            {
                "asn",
                "name",
                "category",
                "country",
                "country_code",
                "tooltip",
                "total",
                "core",
                "other",
                "distinct_prefixes",
                "largest_prefix_share",
                "distinct_fingerprints",
                "dominant_fingerprint_share",
            },
        )


class ParseSeedsTest(unittest.TestCase):
    def test_parses_all_dumped_node_fields(self):
        line = (
            '192.0.2.1:8333 1 1234 100.00% 75.50% 50.00% 25.00% 12.50% '
            '900000 0000000000000849 70016 "/Satoshi:30.0.0/" 1235 7\n'
        )
        with tempfile.NamedTemporaryFile(mode="w") as seeds:
            seeds.write(line)
            seeds.flush()
            row = analyze_seeds.parse_seeds(seeds.name)[0]

        self.assertEqual(row["last_seen"], 1234)
        self.assertEqual(row["reliability"]["8h"], 0.755)
        self.assertEqual(row["blocks"], 900000)
        self.assertEqual(row["services"], 0x849)
        self.assertEqual(row["protocol_version"], 70016)
        self.assertEqual(row["last_tried"], 1235)
        self.assertEqual(row["try_count"], 7)


if __name__ == "__main__":
    unittest.main()
