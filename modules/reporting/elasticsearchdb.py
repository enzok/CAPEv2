# Copyright (C) 2010-2015 Jose Palanco (jose.palanco@drainware.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import os
import logging
import json
import re

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooDependencyError
from lib.cuckoo.common.objects import File

try:
    from elasticsearch import Elasticsearch, ElasticsearchException
    HAVE_ELASTICSEARCH = True
except ImportError as e:
    HAVE_ELASTICSEARCH = False

log = logging.getLogger("elasticsearch").setLevel(logging.WARNING)


class ElasticsearchDB(Report):
    """Stores report in Elastic Search."""
    order = 9997

    def connect(self):
        """Connects to Elasticsearch database, loads options and set connectors.
        @raise CuckooReportError: if unable to connect.
        """
        self.es = Elasticsearch(
            hosts = [{
                'host': self.options.get("host", "127.0.0.1"),
                'port': self.options.get("port", 9200),
            }],
            timeout = 60
        )

    def replace_dots(self, signatures):
        """Removes $ and . from key
        @param signatures: original signatures dictionary
        """
        new_sigs = []
        for sig in signatures:
            temp = {}
            for key, val in sig.items():
                if key != 'data':
                    temp[key] = val
                else:
                    new_data = []
                    for data in val:
                        data_temp = {}
                        for oldkey, dval in data.items():
                            newkey = oldkey.replace(".", "_")
                            data_temp[newkey] = dval
                        new_data.append(data_temp)
                    temp[key] = new_data
            new_sigs.append(temp)

        return new_sigs

    def run(self, results):
        """Writes report.
        @param results: analysis results dictionary.
        @raise CuckooReportError: if fails to connect or write to Elasticsearch.
        """
        # We put the raise here and not at the import because it would
        # otherwise trigger even if the module is not enabled in the config.
        if not HAVE_ELASTICSEARCH:
            raise CuckooDependencyError("Unable to import elasticsearch "
                                        "(install with `pip3 install elasticsearch`)")

        self.connect()
        index_prefix  = self.options.get("index", "cuckoo")
        search_only   = self.options.get("searchonly", False)

        # Create a copy of the dictionary. This is done in order to not modify
        # the original dictionary and possibly compromise the following
        # reporting modules.
        esreport = dict(results)

        idxdate = esreport["info"]["started"].split(" ")[0]
        self.index_name = '{0}-{1}'.format(index_prefix, idxdate)

        if not search_only:
            if not "network" in esreport:
                esreport["network"] = {}

            # Store API calls in chunks for pagination in Django
            if "behavior" in esreport and "processes" in esreport["behavior"]:
                new_processes = []
                for process in esreport["behavior"]["processes"]:
                    new_process = dict(process)
                    chunk = []
                    chunks_ids = []
                    # Loop on each process call.
                    for index, call in enumerate(process["calls"]):
                        # If the chunk size is 100 or if the loop is completed then
                        # store the chunk in Elastcisearch.
                        if len(chunk) == 100:
                            to_insert = {"pid": process["process_id"],
                                         "calls": chunk}
                            pchunk = self.es.index(index=self.index_name,
                                                   doc_type="calls", body=to_insert)
                            chunk_id = pchunk['_id']
                            chunks_ids.append(chunk_id)
                            # Reset the chunk.
                            chunk = []

                        # Append call to the chunk.
                        chunk.append(call)

                    # Store leftovers.
                    if chunk:
                        to_insert = {"pid": process["process_id"], "calls": chunk}
                        pchunk = self.es.index(index=self.index_name, 
                                               doc_type="calls", body=to_insert)
                        chunk_id = pchunk['_id']
                        chunks_ids.append(chunk_id)

                    # Add list of chunks.
                    new_process["calls"] = chunks_ids
                    new_processes.append(new_process)

                # Store the results in the report.
                esreport["behavior"] = dict(esreport["behavior"])
                esreport["behavior"]["processes"] = new_processes

            # Add screenshot paths
            esreport["shots"] = []
            shots_path = os.path.join(self.analysis_path, "shots")
            if os.path.exists(shots_path):
                shots = [shot for shot in os.listdir(shots_path)
                         if shot.endswith(".jpg")]
                for shot_file in sorted(shots):
                    shot_path = os.path.join(self.analysis_path, "shots",
                                             shot_file)
                    screenshot = File(shot_path)
                    if screenshot.valid():
                        # Strip the extension as it's added later 
                        # in the Django view
                        esreport["shots"].append(shot_file.replace(".jpg", ""))

            # Other info we want Quick access to from the web UI
            if "virustotal" in results and results["virustotal"] and "positives" in results["virustotal"] and \
                    "total" in results["virustotal"]:
                esreport["virustotal_summary"] = "%s/%s" % (results["virustotal"]["positives"],
                                                          results["virustotal"]["total"])

            if "suricata" in results and results["suricata"]:
                if "tls" in results["suricata"] and len(results["suricata"]["tls"]) > 0:
                    esreport["suri_tls_cnt"] = len(results["suricata"]["tls"])
                if results["suricata"] and "alerts" in results["suricata"] and len(results["suricata"]["alerts"]) > 0:
                    esreport["suri_alert_cnt"] = len(results["suricata"]["alerts"])
                if "files" in results["suricata"] and len(results["suricata"]["files"]) > 0:
                    esreport["suri_file_cnt"] = len(results["suricata"]["files"])
                if "http" in results["suricata"] and len(results["suricata"]["http"]) > 0:
                    esreport["suri_http_cnt"] = len(results["suricata"]["http"])
        else:
            esreport = dict()
            esreport["task_id"] = results["info"]["id"]
            esreport["info"] = results.get("info", {})
            if esreport.get("info", {}).get("machine", {}):
                esreport["info"]["machine"] = json.dumps(esreport["info"]["machine"])
            esreport["target"] = results.get("target", {})
            esreport["summary"] = results.get("behavior", {}).get("summary", {})
            esreport["network"] = results.get("network", {})
            esreport["malfamily"] = results.get("malfamily", "")
            esreport["malscore"] = results.get("malscore", 0)
            esreport["virustotal"] = results.get("virustotal", {})
            esreport["virustotal_summary"] = results.get("virustotal_summary", {})
            esreport["cape"] = results.get("cape", "")
            cape_result = results.get("CAPE", [])
            if cape_result:
                for cape in cape_result:
                    if "cape_config" in cape:
                        esreport["CAPE"] = cape
            esreport["signatures"] = self.replace_dots(results.get("signatures", []))
            esreport["strings"] = results.get("strings", [])
            esreport["mmbot"] = results.get("mmbot", {})

            # Store unique list of API calls
            if results.get("behavior", False).get("processes", False):
                esreport["apicalls"] = []
                for process in results["behavior"]["processes"]:
                    # Loop on each process call.
                    for index, call in enumerate(process["calls"]):
                        if call["api"] not in esreport["apicalls"]:
                            esreport["apicalls"].append(call["api"])

        # Create index and set maximum fields limit to 5000
        settings = dict()
        settings["settings"] = {"index": {"mapping": {"total_fields": {"limit": "5000"}}}}
        if self.es.indices.exists(index=self.index_name):
            self.es.indices.put_settings(index=self.index_name, body=settings)
        else:
            self.es.indices.create(index=self.index_name, body=settings)

        # Store the report and retrieve its object id.
        try:
            self.es.index(index=self.index_name, doc_type="analysis", id=esreport["info"]["id"], body=esreport)
        except ElasticsearchException as cept:
            log.warning(cept)
            error_saved = True
            dropdead = 1
            while error_saved and dropdead < 20:
                if "mapper_parsing_exception" in cept.args[1] or "illegal_argument_exception" in cept.args[1]:
                    reason = cept.args[2]['error']['reason']

                    try:
                        keys = re.findall(r'\[([^]]*)\]', reason)[0].split(".")
                    except IndexError as cept:
                        log.error("Failed to save results to elasticsearch db.")
                        error_saved = False
                        continue

                    if "yara" in keys and "date" in keys:
                        for rule in esreport['target']['file']['yara']:
                            if "date" in rule['meta']:
                                del rule['meta']['date']
                    else:
                        delcmd = "del report"
                        for k in keys:
                            delcmd += "['{}']".format(k)
                        try:
                            exec(compile(delcmd, '', 'exec')) in locals()

                        except Exception as cept:
                            log.error(cept)
                            error_saved = False

                    try:
                        self.es.index(index=self.index_name,
                                      doc_type="analysis",
                                      id=esreport["info"]["id"],
                                      body=esreport)
                        error_saved = False
                    except ElasticsearchException as cept:
                        dropdead += 1
                        log.error(cept)
                else:
                    log.error("Failed to save results to elasticsearch db.")
                    error_saved = False

