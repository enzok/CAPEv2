from tempfile import NamedTemporaryFile
from unittest.mock import ANY, MagicMock, patch

import pytest

from lib.cuckoo.common.objects import File
from modules.processing.CAPE import CAPE
from modules.processing.deduplication import reindex_screenshots


@pytest.fixture
def cape_processor():
    retval = CAPE()
    retval._set_dict_keys()
    yield retval


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

