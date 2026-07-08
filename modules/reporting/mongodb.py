# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import gc
import hashlib
import json
import logging

from bson import BSON
from bson.binary import Binary
from contextlib import suppress
from lib.cuckoo.common.iocs import dump_iocs
from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooDependencyError, CuckooReportError
from modules.reporting.report_doc import ensure_valid_utf8, get_json_document, insert_calls
from lib.cuckoo.common.config import Config

try:
    from pymongo.errors import InvalidDocument, OperationFailure

    from dev_utils.mongodb import (
        mongo_collection_names,
        mongo_delete_data,
        mongo_delete_many,
        mongo_find_one,
        mongo_insert_one,
        mongo_update_one,
    )

    HAVE_MONGO = True
except ImportError:
    HAVE_MONGO = False

MONGOSIZELIMIT = 0x1000000
MEGABYTE = 0x100000
ANALYSIS_CHUNKS_COLL = "analysis_chunks"
DEFAULT_TARGET_DOC_SIZE = 14 * MEGABYTE
DEFAULT_MIN_SECTION_SIZE = 1 * MEGABYTE
DEFAULT_CHUNKABLE_NON_QUERY_FIELDS = (
    "strings",
    "behavior.processtree",
    "behavior.processes",
    "behavior.summary",
    "procdump",
    "static",
    "dropped",
    "suricata",
    "signatures",
    "network",
    "target",
    "CAPE",
    "statistics",
    "memory",
    "js_log",
)

log = logging.getLogger(__name__)
reporting_conf = Config("reporting")

CHUNKABLE_NON_QUERY_FIELDS = DEFAULT_CHUNKABLE_NON_QUERY_FIELDS
if hasattr(reporting_conf, "mongodb") and hasattr(reporting_conf.mongodb, "chunkable_non_query_fields"):
    cfg_val = reporting_conf.mongodb.chunkable_non_query_fields
    if isinstance(cfg_val, str) and cfg_val.strip():
        CHUNKABLE_NON_QUERY_FIELDS = tuple(f.strip() for f in cfg_val.split(",") if f.strip())


class MongoDB(Report):
    """Stores report in MongoDB."""

    order = 9999

    # Mongo schema version, used for data migration.
    SCHEMA_VERSION = "1"

    @staticmethod
    def _bson_size(doc):
        return len(BSON.encode(doc))

    @staticmethod
    def _is_doc_too_large(exc):
        if isinstance(exc, OperationFailure) and getattr(exc, "code", None) in (10334, 15):
            return True
        msg = str(exc)
        return "BSONObjectTooLarge" in msg or "BSONObj size" in msg

    @staticmethod
    def _get_path(doc, dotted):
        cur = doc
        for part in dotted.split("."):
            if not isinstance(cur, dict) or part not in cur:
                return None
            cur = cur[part]
        return cur

    @staticmethod
    def _set_path(doc, dotted, value):
        parts = dotted.split(".")
        cur = doc
        for part in parts[:-1]:
            cur = cur[part]
        cur[parts[-1]] = value

    def _delete_chunk_part_ids(self, part_ids):
        if part_ids:
            mongo_delete_many(ANALYSIS_CHUNKS_COLL, {"_id": {"$in": list(part_ids)}})

    def _cleanup_chunk_orphans(self, task_id, dotted_path, keep_part_ids=None):
        query = {"task_id": int(task_id), "path": dotted_path}
        if keep_part_ids:
            query["_id"] = {"$nin": list(keep_part_ids)}
        mongo_delete_many(ANALYSIS_CHUNKS_COLL, query)

    def _build_chunk_pointer(self, task_id, dotted_path, value):
        raw = json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        digest = hashlib.sha256(raw).hexdigest()
        chunk_size = int(self.options.get("analysis_chunks_bytes", 2 * MEGABYTE))
        chunk_ids = []
        total = (len(raw) + chunk_size - 1) // chunk_size
        try:
            for seq in range(total):
                part = raw[seq * chunk_size : (seq + 1) * chunk_size]
                doc = {
                    "task_id": int(task_id),
                    "path": dotted_path,
                    "seq": seq,
                    "total": total,
                    "codec": "json-v1",
                    "sha256": digest,
                    "data": Binary(part),
                }
                chunk_ids.append(mongo_insert_one(ANALYSIS_CHUNKS_COLL, doc).inserted_id)
        except Exception:
            self._delete_chunk_part_ids(chunk_ids)
            raise
        return {
            "__chunked__": True,
            "collection": ANALYSIS_CHUNKS_COLL,
            "codec": "json-v1",
            "parts": chunk_ids,
            "path": dotted_path,
            "sha256": digest,
            "orig_bytes": len(raw),
            "stored_bytes": len(raw),
        }

    def _store_chunked_section(self, report, task_id, dotted_path, value):
        pointer = self._build_chunk_pointer(task_id=task_id, dotted_path=dotted_path, value=value)
        self._set_path(report, dotted_path, pointer)
        self._cleanup_chunk_orphans(task_id=task_id, dotted_path=dotted_path, keep_part_ids=pointer["parts"])

    def _set_analysis_field_with_chunk_fallback(self, obj_id, task_id, field_path, value):
        first_exc = None
        try:
            mongo_update_one("analysis", {"_id": obj_id}, {"$set": {field_path: value}}, bypass_document_validation=True)
            self._cleanup_chunk_orphans(task_id=task_id, dotted_path=field_path)
            return
        except (InvalidDocument, OperationFailure) as exc:
            first_exc = exc
            if not self._is_doc_too_large(exc):
                raise

        if field_path not in CHUNKABLE_NON_QUERY_FIELDS:
            raise first_exc

        pointer = self._build_chunk_pointer(task_id=task_id, dotted_path=field_path, value=value)
        try:
            mongo_update_one("analysis", {"_id": obj_id}, {"$set": {field_path: pointer}}, bypass_document_validation=True)
            self._cleanup_chunk_orphans(task_id=task_id, dotted_path=field_path, keep_part_ids=pointer["parts"])
        except Exception:
            self._delete_chunk_part_ids(pointer["parts"])
            raise

    def _insert_analysis_non_lossy(self, report):
        from dev_utils.mongo_hooks import normalize_files

        report = normalize_files(report)
        task_id = report["info"]["id"]
        target_size = int(self.options.get("chunk_large_docs_target_bytes", DEFAULT_TARGET_DOC_SIZE))
        min_section = int(self.options.get("chunk_large_docs_min_section_bytes", DEFAULT_MIN_SECTION_SIZE))
        candidates = list(CHUNKABLE_NON_QUERY_FIELDS)

        created = []
        try:
            while self._bson_size(report) > target_size:
                sized = []
                for path in candidates:
                    value = self._get_path(report, path)
                    if value is None or (isinstance(value, dict) and value.get("__chunked__")):
                        continue
                    sec_size = self._bson_size({"v": value})
                    if sec_size >= min_section:
                        sized.append((sec_size, path, value))

                if not sized:
                    log.error(
                        "Report for task %s is too large (%s bytes), but no chunkable sections remain to be processed.",
                        task_id,
                        self._bson_size(report),
                    )
                    raise CuckooReportError("Report too large and no chunkable section remains")

                log.debug("Large report chunking candidates for task %s (current size: %s bytes):", task_id, self._bson_size(report))
                for s, p, _ in sorted(sized, key=lambda x: x[0], reverse=True):
                    log.debug("  - %s: %s bytes", p, s)

                sec_size, path, value = max(sized, key=lambda x: x[0])
                log.info("Chunking largest section for task %s: '%s' (%s bytes)", task_id, path, sec_size)

                before_ids = set(created)
                self._store_chunked_section(report, task_id, path, value)
                ptr = self._get_path(report, path)
                created.extend(ptr.get("parts", []))
                if set(created) == before_ids:
                    log.error("Failed to chunk section '%s' for task %s, it seems to have produced no parts.", path, task_id)
                    raise CuckooReportError(f"Failed chunking section: {path}")

            mongo_insert_one("analysis", report)
        except Exception:
            if created:
                from dev_utils.mongodb import mongo_delete_many

                mongo_delete_many(ANALYSIS_CHUNKS_COLL, {"_id": {"$in": created}})
            raise

    def debug_dict_size(self, dct):
        if isinstance(dct, list):
            dct = dct[0]

        totals = dict((k, 0) for k in dct)

        def walk(root, key, val):
            if isinstance(val, dict):
                for k, v in val.items():
                    walk(root, k, v)

            elif isinstance(val, (list, tuple, set)):
                for el in val:
                    walk(root, None, el)

            elif isinstance(val, str):
                totals[root] += len(val)

        for key, val in dct.items():
            walk(key, key, val)

        return sorted(list(totals.items()), key=lambda item: item[1], reverse=True)

    # use this function to hunt down non string key
    def fix_int2str(self, dictionary, current_key_tree=""):
        for k, v in dictionary.iteritems():
            if not isinstance(k, str):
                log.error("BAD KEY: %s", ".".join([current_key_tree, str(k)]))
                dictionary[str(k)] = dictionary.pop(k)
            elif isinstance(v, dict):
                self.fix_int2str(v, ".".join([current_key_tree, k]))
            elif isinstance(v, list):
                for d in v:
                    if isinstance(d, dict):
                        self.fix_int2str(d, ".".join([current_key_tree, k]))

    def loop_saver(self, report):
        keys = list(report.keys())
        if "info" not in keys:
            log.error("Missing 'info' key: %s", keys)
            return
        if "_id" in keys:
            keys.remove("_id")

        # We insert the info section first to get an _id
        obj_id = mongo_insert_one("analysis", {"info": report["info"]}).inserted_id
        task_id = report["info"]["id"]
        keys.remove("info")

        for key in keys:
            try:
                if key == "behavior" and isinstance(report[key], dict):
                    try:
                        self._set_analysis_field_with_chunk_fallback(
                            obj_id=obj_id, task_id=task_id, field_path=key, value=report[key]
                        )
                    except (InvalidDocument, OperationFailure) as exc:
                        if not self._is_doc_too_large(exc):
                            raise
                        processtree = report[key].get("processtree")
                        if processtree is None:
                            raise
                        pointer = self._build_chunk_pointer(
                            task_id=task_id,
                            dotted_path="behavior.processtree",
                            value=processtree,
                        )
                        behavior_with_pointer = dict(report[key])
                        behavior_with_pointer["processtree"] = pointer
                        try:
                            mongo_update_one(
                                "analysis",
                                {"_id": obj_id},
                                {"$set": {"behavior": behavior_with_pointer}},
                                bypass_document_validation=True,
                            )
                            self._cleanup_chunk_orphans(
                                task_id=task_id,
                                dotted_path="behavior.processtree",
                                keep_part_ids=pointer["parts"],
                            )
                        except Exception:
                            self._delete_chunk_part_ids(pointer["parts"])
                            raise
                else:
                    self._set_analysis_field_with_chunk_fallback(obj_id=obj_id, task_id=task_id, field_path=key, value=report[key])
            except InvalidDocument:
                log.warning("Investigate your key: %s", key)
            except Exception as e:
                log.error("Failed to update key %s in loop_saver: %s", key, e)

    def run(self, results):
        """Writes report.
        @param results: analysis results dictionary.
        @raise CuckooReportError: if fails to connect or write to MongoDB.
        """
        # We put the raise here and not at the import because it would
        # otherwise trigger even if the module is not enabled in the config.
        if not HAVE_MONGO:
            raise CuckooDependencyError("Unable to import pymongo (install with `pip3 install pymongo`)")

        # move to startup
        # Set mongo schema version.
        # TODO: This is not optimal because it run each analysis. Need to run only one time at startup.
        if "cuckoo_schema" in mongo_collection_names():
            if mongo_find_one("cuckoo_schema", {}, {"version": 1})["version"] != self.SCHEMA_VERSION:
                raise CuckooReportError("Mongo schema version not expected, check data migration tool")
        else:
            mongo_insert_one("cuckoo_schema", {"version": self.SCHEMA_VERSION})

        # Create a copy of the dictionary. This is done in order to not modify
        # the original dictionary and possibly compromise the following
        # reporting modules.
        report = get_json_document(results, self.analysis_path)
        if not report or "info" not in report:
            log.error("Failed to get JSON document or 'info' key is missing for Task")
            return

        local_task_id = int(report["info"].get("id", 0))
        if not local_task_id:
            log.error("Task ID is missing in report['info']")
            return

        # trick for distributed api
        main_task_id = results.get("info", {}).get("options", {}).get("main_task_id")
        if main_task_id:
            with suppress(ValueError, TypeError):
                report["info"]["id"] = int(main_task_id)

        if "network" not in report:
            report["network"] = {}

        if "behavior" not in report or not isinstance(report["behavior"], dict):
            report["behavior"] = {"processes": [], "processtree": [], "summary": {}}

        # Delete old data just before inserting new one to avoid "missing report" window
        # or data loss if insertion fails during preparation (e.g. OOM)
        ids_to_delete = {local_task_id, int(report["info"]["id"])}
        log.debug("Deleting previous MongoDB data for Task IDs: %s", ids_to_delete)
        mongo_delete_data(list(ids_to_delete))

        new_processes = insert_calls(report, mongodb=True)
        # Store the results in the report.
        report["behavior"]["processes"] = new_processes

        # Store iocs as file
        if reporting_conf.mongodb.dump_iocs:
            dump_iocs(report, local_task_id)

        ensure_valid_utf8(report)
        gc.collect()

        # Add this line to debug the report size
        log.debug("Report key sizes for task %s: %s", report["info"]["id"], self.debug_dict_size(report))

        # Store the report and retrieve its object id.
        try:
            log.debug("Inserting new MongoDB report for Task %s", report["info"]["id"])
            mongo_insert_one("analysis", report)
        except (OperationFailure, InvalidDocument) as e:
            if str(e).startswith("cannot encode object") or "must not contain" in str(e):
                self.loop_saver(report)
                return

            if self.options.get("chunk_large_docs", True):
                log.warning("Large analysis document detected; switching to chunked storage: %s", e)
                self._insert_analysis_non_lossy(report)
            else:
                raise CuckooReportError(
                    f"Failed to insert MongoDB report for task {report['info']['id']}: {e}"
                ) from e