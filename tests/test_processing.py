import hashlib
import json
import os
from tempfile import NamedTemporaryFile
from unittest.mock import ANY, MagicMock, patch

import pytest

from lib.cuckoo.common.objects import File
from modules.processing.CAPE import CAPE, PARSER_EXTRACTED, PARSER_EXTRACTED_TYPE, TYPE_STRING
from modules.processing.deduplication import reindex_screenshots


@pytest.fixture
def cape_processor():
    retval = CAPE()
    retval._set_dict_keys()
    yield retval


@pytest.fixture
def dumping_processor(tmp_path):
    """A CAPE processor with just the paths _dump_parser_files needs."""
    retval = CAPE()
    retval._set_dict_keys()
    retval.CAPE_path = str(tmp_path / "CAPE")
    retval.files_metadata = str(tmp_path / "files.json")
    yield retval


DUMPED_BLOB = b"MZ\x90\x00 parser dumped stage2"
DUMPED_SHA256 = hashlib.sha256(DUMPED_BLOB).hexdigest()
PARSER_METADATA = f"{PARSER_EXTRACTED};?;?;?"


def assert_no_raw_bytes(node, path="configs"):
    """The invariant: no bytes value may survive anywhere in the stored configs.

    Raw parser-dumped bytes must only ever exist as a file under CAPE/ -- never in
    self.cape["configs"], and therefore never in report.json or Mongo.
    """
    if isinstance(node, dict):
        for key, value in node.items():
            assert not isinstance(key, bytes), f"bytes used as a key at {path}"
            assert_no_raw_bytes(value, f"{path}[{key!r}]")
    elif isinstance(node, (list, tuple)):
        for index, item in enumerate(node):
            assert_no_raw_bytes(item, f"{path}[{index}]")
    else:
        assert not isinstance(node, bytes), f"raw bytes survived at {path}: {node!r}"


class TestConfigUpdates:
    def test_update_no_config(self, cape_processor):
        cape_processor.update_cape_configs("Family", None, MagicMock())
        assert cape_processor.cape["configs"] == []

    def test_update_empty_config(self, cape_processor):
        cape_processor.update_cape_configs("Family", {}, MagicMock())
        assert cape_processor.cape["configs"] == []

    def test_update_single_config(self, cape_processor):
        cfg = {"Family": {"SomeKey": "SomeValue"}}
        cape_processor.update_cape_configs("Family", cfg, MagicMock())
        expected_cfgs = [cfg]
        assert cape_processor.cape["configs"] == expected_cfgs

    def test_update_multiple_configs(self, cape_processor):
        cfg1 = {"Family": {"SomeKey": "SomeValue"}}
        cfg2 = {"Family": {"AnotherKey": "AnotherValue"}}
        cape_processor.update_cape_configs("Family", cfg1, MagicMock())
        cape_processor.update_cape_configs("Family", cfg2, MagicMock())
        expected_cfgs = [{"Family": {"AnotherKey": "AnotherValue", "SomeKey": "SomeValue"}, "_associated_config_hashes": ANY}]
        assert cape_processor.cape["configs"] == expected_cfgs

    def test_update_different_families(self, cape_processor):
        cfg1 = {"Family1": {"SomeKey": "SomeValue"}}
        cfg2 = {"Family2": {"SomeKey": "SomeValue"}}
        cape_processor.update_cape_configs("Family", cfg1, MagicMock())
        cape_processor.update_cape_configs("Family", cfg2, MagicMock())
        expected_cfgs = [
            {"Family1": {"SomeKey": "SomeValue"}, "_associated_config_hashes": ANY},
            {"Family2": {"SomeKey": "SomeValue"}, "_associated_config_hashes": ANY},
        ]
        assert cape_processor.cape["configs"] == expected_cfgs

    def test_update_same_family_overwrites(self, cape_processor):
        # see https://github.com/kevoreilly/CAPEv2/pull/1357
        cfg1 = {"Family": {"SomeKey": "SomeValue"}}
        cfg2 = {"Family": {"SomeKey": "DifferentValue"}}
        cape_processor.update_cape_configs("Family", cfg1, MagicMock())
        cape_processor.update_cape_configs("Family", cfg2, MagicMock())
        expected_cfg = [
            {"Family": {"SomeKey": "DifferentValue"}, "_associated_config_hashes": ANY},
        ]
        assert cape_processor.cape["configs"] == expected_cfg

    def test_update_config_file_obj(self, cape_processor):
        with NamedTemporaryFile(mode="wb") as f:
            f.write(b"fake file for configs")
            file_obj = File(f.name).get_all_hashes()
            cfg = {"Family": {"SomeKey": "SomeValue"}}
            cape_processor.update_cape_configs("Family", cfg, file_obj)
        actual_cfg = cape_processor.cape["configs"]
        assert "Family" in actual_cfg[0]
        assert "_associated_config_hashes" in actual_cfg[0]
        hashes = actual_cfg[0]["_associated_config_hashes"]
        assert len(hashes) == 1
        assert hashes[0]["md5"].startswith("d41")
        assert hashes[0]["sha1"].startswith("da3")
        assert hashes[0]["sha256"].startswith("e3b")
        assert hashes[0]["sha512"].startswith("cf8")
        assert hashes[0]["sha3_384"].startswith("0c6")


class TestParserDumpedFiles:
    def test_blob_written_recorded_and_queued(self, dumping_processor, tmp_path):
        cfg = {"Family": {"C2": ["http://example.tld/gate"], "dump_files": [{"decrypted stage2": DUMPED_BLOB}]}}
        dumping_processor.update_cape_configs("Family", cfg, MagicMock())

        stored = dumping_processor.cape["configs"][0]["Family"]
        assert_no_raw_bytes(dumping_processor.cape["configs"])
        assert "dump_files" not in stored
        assert "description" not in stored
        # recorded by hash only, under the non-normalized "raw" key
        assert stored["raw"][0]["Parsed Files"] == {DUMPED_SHA256: "decrypted stage2"}
        # normalized fields untouched
        assert stored["C2"] == ["http://example.tld/gate"]

        # written to CAPE/, not files/, so it satisfies the payload + download contract
        assert (tmp_path / "CAPE" / DUMPED_SHA256).read_bytes() == DUMPED_BLOB

        entries = [json.loads(line) for line in (tmp_path / "files.json").read_text().splitlines()]
        assert len(entries) == 1
        assert entries[0]["path"] == f"CAPE/{DUMPED_SHA256}"
        assert entries[0]["category"] == "CAPE"
        assert entries[0]["metadata"] == PARSER_METADATA

        expected_dest = os.path.join(dumping_processor.CAPE_path, DUMPED_SHA256)
        assert dumping_processor.queued_payloads == [(expected_dest, {"metadata": PARSER_METADATA})]

    def test_parser_raw_fields_and_multiple_blobs_coexist(self, dumping_processor):
        second_blob = b"a different second stage"
        second_sha256 = hashlib.sha256(second_blob).hexdigest()
        cfg = {
            "Family": {
                "raw": [{"ParserNote": "recorded by the parser itself"}],
                "dump_files": [{"stage2": DUMPED_BLOB, "stage3": second_blob}],
            }
        }
        dumping_processor.update_cape_configs("Family", cfg, MagicMock())

        raw = dumping_processor.cape["configs"][0]["Family"]["raw"][0]
        assert raw["ParserNote"] == "recorded by the parser itself"
        assert raw["Parsed Files"] == {DUMPED_SHA256: "stage2", second_sha256: "stage3"}
        assert len(dumping_processor.queued_payloads) == 2

    def test_merge_path_does_not_store_bytes(self, dumping_processor):
        # The regression this fix exists for: on the second hit of a family,
        # update_cape_configs merges into the stored dict, so a strip that happened
        # after the merge left the raw bytes behind in Mongo.
        dumping_processor.update_cape_configs("Family", {"Family": {"C2": ["first"]}}, MagicMock())
        dumping_processor.update_cape_configs(
            "Family", {"Family": {"C2": ["second"], "dump_files": [{"stage2": DUMPED_BLOB}]}}, MagicMock()
        )

        assert_no_raw_bytes(dumping_processor.cape["configs"])
        stored = dumping_processor.cape["configs"][0]["Family"]
        assert "dump_files" not in stored
        assert stored["raw"][0]["Parsed Files"] == {DUMPED_SHA256: "stage2"}

    def test_malformed_dump_files_is_contained(self, dumping_processor):
        # A parser that returned dump_files as a list gets double-wrapped to [[{...}]].
        # That must be logged and stripped, not raised -- an exception here would escape
        # process_file and make RunProcessing discard the whole CAPE result.
        cfg = {"Family": {"dump_files": [[{"stage2": DUMPED_BLOB}]]}}
        dumping_processor.update_cape_configs("Family", cfg, MagicMock())

        stored = dumping_processor.cape["configs"][0]["Family"]
        assert "dump_files" not in stored
        assert_no_raw_bytes(dumping_processor.cape["configs"])
        assert dumping_processor.queued_payloads == []

    def test_write_failure_still_strips_bytes(self, dumping_processor):
        cfg = {"Family": {"dump_files": [{"stage2": DUMPED_BLOB}]}}
        with patch("modules.processing.CAPE.Path") as mock_path:
            mock_path.return_value.write_bytes.side_effect = OSError("no space left on device")
            dumping_processor.update_cape_configs("Family", cfg, MagicMock())

        stored = dumping_processor.cape["configs"][0]["Family"]
        assert "dump_files" not in stored
        assert_no_raw_bytes(dumping_processor.cape["configs"])

    def test_dump_files_without_description_does_not_raise(self, dumping_processor):
        # The old code did an unconditional del config["description"].
        cfg = {"Family": {"dump_files": [{"stage2": DUMPED_BLOB}]}}
        dumping_processor.update_cape_configs("Family", cfg, MagicMock())
        assert dumping_processor.cape["configs"][0]["Family"]["raw"][0]["Parsed Files"]

    def test_merge_keeps_parsed_files_from_both_calls(self, dumping_processor):
        # Both calls dump: the second must not replace the whole raw list and lose the first
        # blob's Parsed Files row. This is the case test_merge_path_does_not_store_bytes misses,
        # because there the first call has no dump_files and so no stored raw to clobber.
        second_blob = b"a different second stage"
        second_sha256 = hashlib.sha256(second_blob).hexdigest()
        dumping_processor.update_cape_configs(
            "Family", {"Family": {"dump_files": [{"stage1": DUMPED_BLOB}]}}, MagicMock()
        )
        dumping_processor.update_cape_configs(
            "Family", {"Family": {"dump_files": [{"stage2": second_blob}]}}, MagicMock()
        )

        parsed = dumping_processor.cape["configs"][0]["Family"]["raw"][0]["Parsed Files"]
        assert parsed == {DUMPED_SHA256: "stage1", second_sha256: "stage2"}
        assert_no_raw_bytes(dumping_processor.cape["configs"])

    def test_merge_keeps_parser_raw_fields_from_first_call(self, dumping_processor):
        dumping_processor.update_cape_configs(
            "Family", {"Family": {"raw": [{"ParserNote": "from the first file"}]}}, MagicMock()
        )
        dumping_processor.update_cape_configs(
            "Family", {"Family": {"dump_files": [{"stage2": DUMPED_BLOB}]}}, MagicMock()
        )

        raw = dumping_processor.cape["configs"][0]["Family"]["raw"][0]
        assert raw["ParserNote"] == "from the first file"
        assert raw["Parsed Files"] == {DUMPED_SHA256: "stage2"}

    def test_merge_does_not_accumulate_normal_list_values(self, dumping_processor):
        # Guard against over-merging: ordinary config values are list-wrapped by
        # static_config_parsers and must stay last-write-wins per PR #1357.
        dumping_processor.update_cape_configs("Family", {"Family": {"C2": ["first"]}}, MagicMock())
        dumping_processor.update_cape_configs("Family", {"Family": {"C2": ["second"]}}, MagicMock())

        assert dumping_processor.cape["configs"][0]["Family"]["C2"] == ["second"]

    def test_str_blob_is_coerced(self, dumping_processor):
        # A parser handing back a decoded script rather than bytes still hashes/writes.
        cfg = {"Family": {"dump_files": [{"decoded script": "plain string stage"}]}}
        dumping_processor.update_cape_configs("Family", cfg, MagicMock())
        expected = hashlib.sha256(b"plain string stage").hexdigest()
        assert dumping_processor.cape["configs"][0]["Family"]["raw"][0]["Parsed Files"] == {
            expected: "decoded script"
        }

    def test_same_blob_written_once(self, dumping_processor, tmp_path):
        for family in ("FamilyA", "FamilyB"):
            dumping_processor.update_cape_configs(
                family, {family: {"dump_files": [{"stage2": DUMPED_BLOB}]}}, MagicMock()
            )

        assert len((tmp_path / "files.json").read_text().splitlines()) == 1
        assert (tmp_path / "CAPE" / DUMPED_SHA256).read_bytes() == DUMPED_BLOB


class TestParserExtractedCapeType:
    @pytest.fixture
    def typed_processor(self, cape_processor):
        cape_processor.options = MagicMock()
        cape_processor.options.replace_patterns = []
        yield cape_processor

    def test_neutral_type_seeded_without_a_clobbering_type_string(self, typed_processor):
        file_info = {"type": "PE32 executable (GUI) Intel 80386, for MS Windows"}

        type_string, append_file = typed_processor._metadata_processing(
            {"metadata": PARSER_METADATA}, file_info, False
        )

        # Neutral label -- the blob must not inherit the family of the parser that dumped
        # it, since one family routinely drops another.
        assert file_info["cape_type"] == f"{PARSER_EXTRACTED_TYPE}: 32-bit executable"
        # Crucial: no type_string, so the branch in process_file that assigns
        # file_info["cape_type"] = type_string *after* the yara loop never runs and cannot
        # overwrite a family the blob's own CAPE scan identified.
        assert type_string == ""

    @pytest.mark.parametrize("incoming", [True, False])
    def test_append_file_passes_through(self, typed_processor, incoming):
        # The neutral code deliberately isn't in code_mapping, so it must not force
        # append_file either way; the caller decides. run()'s queue drain passes True, and
        # on reprocess the CAPE_path walk passes True for a 64-char name.
        file_info = {"type": "PE32 executable (GUI) Intel 80386, for MS Windows"}
        _, append_file = typed_processor._metadata_processing(
            {"metadata": PARSER_METADATA}, file_info, incoming
        )
        assert append_file is incoming

    def test_blob_own_yara_family_wins_over_neutral_seed(self, typed_processor):
        """Regression: the neutral type must not be re-applied on top of a yara hit.

        _cape_type_string() re-applies code_mapping on *every* call, including the call
        from the yara loop at CAPE.py:394-395. Putting the neutral code in code_mapping
        therefore clobbered a family the blob's own scan had just identified -- exactly the
        cross-family mislabelling this is meant to prevent.
        """
        file_info = {"type": "PE32+ executable (DLL) (GUI) x86-64, for MS Windows"}
        typed_processor._metadata_processing({"metadata": PARSER_METADATA}, file_info, True)
        assert file_info["cape_type"].startswith(PARSER_EXTRACTED_TYPE)

        # Simulate CAPE.py:388 -- a CAPE yara hit on the blob names a different family --
        # then the bitness pass that follows it at CAPE.py:394-395.
        file_info["cape_type"] = "OtherFamily Payload"
        append_file = typed_processor._cape_type_string(file_info["type"].split(), file_info, True)

        assert file_info["cape_type"] == "OtherFamily Payload: 64-bit DLL"
        assert PARSER_EXTRACTED_TYPE not in file_info["cape_type"]
        assert append_file is True


class TestConfigParserDedup:
    """process_file must not run the same config parser twice on the same buffer.

    A payload commonly has both a monitor TYPE_STRING (e.g. "Emotet Config") and a CAPE yara hit
    (e.g. "Emotet Payload"), which reduce to the same family. executed_config_parsers is keyed by
    path, so the type_string fallback has to test membership per buffer.
    """

    def _drive(self, cape_processor, tmp_path, cape_yara, metadata):
        """Run process_file with the heavy collaborators stubbed.

        Returns the (family, path) tuples static_config_parsers was called with.
        """
        target = tmp_path / "payload.bin"
        target.write_bytes(b"MZ payload")
        calls = []

        class FakeFile:
            yara_rules_hash = "yhash"
            guest_paths = []

            def __init__(self, path, metadata=""):
                self._path = str(path)

            def get_sha256(self):
                return "a" * 64

            def get_all(self):
                return (
                    {
                        "sha256": "a" * 64,
                        "name": "payload.bin",
                        "path": self._path,
                        "size": 10,
                        "type": "PE32 executable (GUI) Intel 80386, for MS Windows",
                        "cape_yara": list(cape_yara),
                        "yara": [],
                    },
                    None,
                )

            def get_type(self):
                return "PE32 executable (GUI) Intel 80386, for MS Windows"

            def get_name(self):
                return "payload.bin"

            @staticmethod
            def yara_hit_provides_detection(hit):
                return True

            @staticmethod
            def get_cape_name_from_yara_hit(hit):
                return hit["meta"]["cape_type"].rsplit(" ", 1)[0]

            @staticmethod
            def get_cape_name_from_cape_type(cape_type):
                return cape_type.rsplit(" ", 1)[0] if " " in cape_type else ""

        def fake_parsers(cape_name, path, data):
            calls.append((cape_name, path))
            return {cape_name: {"SomeKey": "SomeValue"}}

        cape_processor.task = {"id": 1, "category": "CAPE", "target": str(target), "options": ""}
        cape_processor.results = {}
        cape_processor.options = MagicMock()
        cape_processor.options.replace_patterns = []
        cape_processor.self_extracted = str(tmp_path / "selfextracted")
        with patch("modules.processing.CAPE.File", FakeFile), patch(
            "modules.processing.CAPE.static_config_parsers", fake_parsers
        ), patch("modules.processing.CAPE.static_file_info"), patch(
            "modules.processing.CAPE.add_family_detection"
        ), patch("modules.processing.CAPE.mongo_find_one", return_value=None):
            cape_processor.process_file(
                str(target), False, metadata, category="CAPE", duplicated={"sha256": set()}
            )
        return calls

    def test_same_family_from_yara_and_type_string_parses_once(self, cape_processor, tmp_path):
        # capemon says "Emotet Config", Emotet.yar says "Emotet Payload" -> both are Emotet.
        calls = self._drive(
            cape_processor,
            tmp_path,
            cape_yara=[{"name": "Emotet", "meta": {"cape_type": "Emotet Payload"}}],
            metadata={"metadata": f"{TYPE_STRING};?;?;?Emotet Config;?"},
        )
        assert [family for family, _ in calls] == ["Emotet"]

    def test_type_string_alone_still_parses(self, cape_processor, tmp_path):
        # No yara hit: the fallback is the only source and must still fire.
        calls = self._drive(
            cape_processor,
            tmp_path,
            cape_yara=[],
            metadata={"metadata": f"{TYPE_STRING};?;?;?Emotet Config;?"},
        )
        assert [family for family, _ in calls] == ["Emotet"]

    def test_different_families_both_parse(self, cape_processor, tmp_path):
        # The dedup must not over-suppress a genuinely different family.
        calls = self._drive(
            cape_processor,
            tmp_path,
            cape_yara=[{"name": "Zloader", "meta": {"cape_type": "Zloader Payload"}}],
            metadata={"metadata": f"{TYPE_STRING};?;?;?Emotet Config;?"},
        )
        assert sorted(family for family, _ in calls) == ["Emotet", "Zloader"]


class TestAnalysisConfigLinks:
    @pytest.mark.parametrize("category", ["static", "file"])
    def test_analysis_linkability(self, category, cape_processor):
        cape_processor.results = {"target": {"category": category}}
        hashes = {
            "md5": "fake-md5",
            "sha1": "fake-sha1",
            "sha256": "fake-sha256",
            "sha512": "fake-sha512",
            "sha3_384": "fake-sha3_384",
        }
        cape_processor.results["target"]["file"] = hashes
        cfg = {"Family": {"SomeKey": "DifferentValue"}}
        cape_processor.cape["configs"] = [cfg]
        cape_processor.link_configs_to_analysis()
        assert "_associated_analysis_hashes" in cfg
        assert cfg["_associated_analysis_hashes"] == hashes

    @pytest.mark.parametrize("category", ["resubmit", "sample", "pcap", "url", "dlnexec", "vtdl"])
    def test_static_links(self, category, cape_processor):
        cape_processor.results = {"target": {"category": category}}
        cfg = {"Family": {"SomeKey": "DifferentValue"}}
        cape_processor.cape["configs"] = [cfg]
        cape_processor.link_configs_to_analysis()
        assert "_associated_analysis_hashes" not in cfg


class TestPcapProcessing:
    @patch("modules.processing.CAPE.path_exists")
    @patch("modules.processing.CAPE.File")
    def test_pcap_category_processing(self, mock_file_cls, mock_path_exists, cape_processor):
        mock_path_exists.return_value = True

        mock_file_instance = MagicMock()
        mock_file_cls.return_value = mock_file_instance
        mock_file_instance.get_sha256.return_value = "fake-pcap-sha256"
        mock_file_instance.get_all.return_value = ({"sha256": "fake-pcap-sha256", "path": "/fake/path"}, None)
        mock_file_instance.get_type.return_value = "pcap capture file"
        mock_file_instance.get_name.return_value = "target.pcap"
        mock_file_instance.guest_paths = ["target.pcap"]

        cape_processor.task = {
            "id": 123,
            "category": "pcap",
            "target": "/fake/path/target.pcap",
            "options": ""
        }
        cape_processor.results = {}
        cape_processor.options = MagicMock()
        cape_processor.options.replace_patterns = []
        cape_processor.self_extracted = []

        cape_processor.process_file(
            "/fake/path/target.pcap",
            False,
            {},
            category="pcap",
            duplicated={"sha256": set()}
        )

        assert "target" in cape_processor.results
        assert cape_processor.results["target"]["category"] == "pcap"
        assert cape_processor.results["target"]["file"]["sha256"] == "fake-pcap-sha256"


class TestDeduplication:
    @patch("os.rename")
    @patch("os.listdir")
    def test_reindex(self, os_listdir, os_rename):
        dirlist = ["foo.jpg", "bar.jpg", "baz.jpg"]
        os_listdir.return_value = dirlist
        reindex_screenshots("shots")
        assert os_rename.call_count == 3
        os_rename.assert_any_call("shots/bar.jpg", "shots/0000.jpg")
        os_rename.assert_any_call("shots/baz.jpg", "shots/0001.jpg")
        os_rename.assert_any_call("shots/foo.jpg", "shots/0002.jpg")


class TestJsLogNetworkProcessing:
    @patch("modules.processing.network.path_exists")
    def test_js_log_parsing_and_mapping(self, mock_path_exists):
        from unittest.mock import patch
        from modules.processing.network import NetworkAnalysis

        # Mock results with parsed js_log events
        events = [
            {"event": "init", "pid": 1234, "exec_path": "C:\\Program Files\\nodejs\\node.exe", "ts": "2026-05-16T00:56:10.059Z"},
            {"event": "dns_query", "host": "example.com", "ts": "2026-05-16T00:56:20.961Z"},
            {"event": "dns_result", "host": "example.com", "result": {"text": "[[{\"address\":\"1.2.3.4\",\"family\":4}]]"}, "ts": "2026-05-16T00:56:22.496Z"},
            {"event": "tcp_connect", "host": "1.2.3.4", "port": 443, "ts": "2026-05-16T00:56:23.000Z"},
            {"event": "http_request", "url": "https://example.com/api", "method": "POST", "ts": "2026-05-16T00:56:24.000Z"}
        ]

        processor = NetworkAnalysis()
        processor.results = {
            "js_log": {
                "exists": True,
                "events": events
            }
        }

        # Test _parse_js_log
        js_map = processor._parse_js_log()
        assert 1234 in [p["process_id"] for p in js_map["endpoint_map"][("1.2.3.4", 443)]]
        assert "node.exe" in [p["process_name"] for p in js_map["http_host_map"]["example.com"]]
        assert "example.com" in js_map["dns_intents"]
        assert len(js_map["http_requests"]) == 1
        assert js_map["http_requests"][0]["url"] == "https://example.com/api"

        # Test _process_map process mappings fallback
        network = {
            "tcp": [{"dst": "1.2.3.4", "dport": 443}],
            "dns": [{"request": "example.com"}],
            "http": [{"host": "example.com", "uri": "/api"}],
            "hosts": [{"ip": "1.2.3.4"}]
        }
        processor._process_map(network)

        assert network["tcp"][0]["process_id"] == 1234
        assert network["tcp"][0]["process_name"] == "node.exe"
        assert network["dns"][0]["process_id"] == 1234
        assert network["http"][0]["process_id"] == 1234

        # Test _merge_js_log_network
        empty_network = {
            "tcp": [],
            "dns": [],
            "http": [],
            "hosts": []
        }
        processor._merge_js_log_network(empty_network)
        assert len(empty_network["dns"]) == 1
        assert empty_network["dns"][0]["request"] == "example.com"
        assert empty_network["dns"][0]["source"] == "js_log"
        assert empty_network["dns"][0]["process_id"] == 1234

        assert len(empty_network["http"]) == 1
        assert empty_network["http"][0]["host"] == "example.com"
        assert empty_network["http"][0]["source"] == "js_log"

        assert len(empty_network["tcp"]) == 1
        assert empty_network["tcp"][0]["dst"] == "1.2.3.4"
        assert empty_network["tcp"][0]["dport"] == 443
        assert empty_network["tcp"][0]["source"] == "js_log"

