import itertools
import json
import logging
from contextlib import suppress

from pymongo import UpdateOne, errors
from pymongo.errors import InvalidDocument, BulkWriteError
import bson

from dev_utils.mongodb import (
    mongo_bulk_write,
    mongo_delete_data,
    mongo_delete_data_range,
    mongo_delete_many,
    mongo_find,
    mongo_find_one,
    mongo_hook,
    mongo_insert_one,
    mongo_update_many,
    mongo_update_one,
)

log = logging.getLogger(__name__)

FILES_COLL = "files"
FILE_KEY = "sha256"
TASK_IDS_KEY = "_task_ids"
FILE_REF_KEY = "file_ref"
ANALYSIS_CHUNKS_COLL = "analysis_chunks"


def normalize_file(file_dict, task_id):
    """Pull out the detonation-independent attributes of the given file and
    return an UpdateOne object usable by bulk_write to upsert a
    document into the FILES_COLL collection with its _id set to the FILE_KEY of
    the file. The given file_dict is updated in place to remove those
    attributes and add a FILE_REF_KEY key containing the FILE_KEY that can be
    used as a lookup in the FILES_COLL collection.
    If the file has already been "normalized," then it is not modified and
    None is returned.
    """
    if FILE_REF_KEY in file_dict:
        # This has already been normalized.
        return
    key = file_dict.get(FILE_KEY, None)
    if not key:
        return
    static_fields = (
        # hashes
        "crc32",
        "md5",
        "sha1",
        "sha256",
        "sha512",
        "sha3_384",
        "ssdeep",
        "tlsh",
        "rh_hash",
        # other metadata & static analysis fields
        "size",
        "pe",
        "ep_bytes",
        "entrypoint",
        "data",
        "strings",
        "type",
        "yara",
        "cape_yara",
        "yara_hash",
        "options_hash",
        "clamav",
        # static/enrichment outputs that should be reusable on file_cache hits
        "trid",
        "die",
        "msi",
        "office",
        "pdf",
        "wsf",
        "lnk",
        "java",
        "rdp",
        "dotnet",
        "dotnet_strings",
        "flare_capa",
        "floss",
        "virustotal",
        "wildfire",
        "zscaler",
        "selfextract",
        "executed_tools",
    )
    new_dict = {}
    for fld in static_fields:
        with suppress(KeyError):
            new_dict[fld] = file_dict.pop(fld)

    new_dict["_id"] = key
    file_dict[FILE_REF_KEY] = key

    return UpdateOne({"_id": key}, {"$set": new_dict, "$addToSet": {TASK_IDS_KEY: task_id}}, upsert=True, hint=[("_id", 1)])


@mongo_hook((mongo_insert_one, mongo_update_one), "analysis")
def normalize_files(report):
    """Take the detonation-independent file data from various parts of
    the report and extract them out to a separate collection, keeping a
    reference to it (along with the detonation-dependent fields) in the
    report.
    """
    task_id = report.get("info", {}).get("id")
    if not task_id:
        # Partial update payloads (e.g., {"procdump": [...]}) don't carry full analysis
        # context. Skip normalization hook in that case.
        return report

    requests = []
    for file_dict in collect_file_dicts(report):
        request = normalize_file(file_dict, task_id)
        if request:
            requests.append(request)

    try:
        if requests:
            mongo_bulk_write(FILES_COLL, requests, ordered=False)
    except (errors.OperationFailure, InvalidDocument, BulkWriteError) as exc:
        log.warning("Mongo hook 'normalize_files' failed: %s. Attempting to sanitize strings and retry.", exc)
        for req in requests:
            # req._doc is the update document: {"$set": new_dict, ...}
            # Accessing private attribute _doc to modify in place for retry
            try:
                if hasattr(req, "_doc") and "$set" in req._doc:
                    # Check if the entire update document is too large (buffer safe 15MB)
                    if len(bson.encode(req._doc)) > 15 * 1024 * 1024:
                        def prune_data_keys(node, limit):
                            if isinstance(node, dict):
                                for k in list(node.keys()):
                                    if k == "data":
                                        if limit > 0:
                                            val = node[k]
                                            if isinstance(val, (str, bytes)):
                                                node[k] = val[:limit]
                                        else:
                                            node.pop(k, None)
                                    else:
                                        prune_data_keys(node[k], limit)
                            elif isinstance(node, list):
                                for item in node:
                                    prune_data_keys(item, limit)

                        # Iterative pruning of the 'data' subkey
                        for limit in (1024, 512, 256, 128, 64, 32, 16, 0):
                            if len(bson.encode(req._doc)) <= 15 * 1024 * 1024:
                                break
                            log.warning("Truncating 'data' subkeys to %d bytes to fit BSON size limits.", limit)
                            prune_data_keys(req._doc["$set"], limit)

                        # Final fallback if still too large
                        if len(bson.encode(req._doc)) > 15 * 1024 * 1024:
                            log.warning("Document is still too large; applying fallback list truncation.")
                            # Sort other fields by size
                            field_sizes = []
                            for key, val in req._doc["$set"].items():
                                try:
                                    field_sizes.append((len(bson.encode({key: val})), key))
                                except Exception:
                                    pass
                            field_sizes.sort(reverse=True)
                            
                            for _, field in field_sizes:
                                if len(bson.encode(req._doc)) <= 15 * 1024 * 1024:
                                    break
                                if field in ("_id", "sha256", "md5", "sha1", "size"):
                                    continue
                                val = req._doc["$set"][field]
                                if not val:
                                    continue
                                log.warning("Pruning large field '%s' as fallback.", field)
                                # Recursive list truncation helper
                                def truncate_lists(node, max_len=100):
                                    if isinstance(node, list):
                                        if len(node) > max_len:
                                            node[:] = node[:max_len]
                                        for item in node:
                                            truncate_lists(item, max_len)
                                    elif isinstance(node, dict):
                                        for v in node.values():
                                            truncate_lists(v, max_len)

                                truncate_lists(val, 100)
                                            
                                # If still too large, clear it entirely
                                if len(bson.encode(req._doc)) > 15 * 1024 * 1024:
                                    req._doc["$set"][field] = [] if isinstance(val, list) else ({} if isinstance(val, dict) else None)
            except Exception as e:
                log.error("Failed to sanitize request during retry: %s", e)

        # Retry the bulk write
        try:
            mongo_bulk_write(FILES_COLL, requests, ordered=False)
        except Exception as retry_exc:
            log.error("Retry of 'normalize_files' failed: %s", retry_exc)

    return report


@mongo_hook(mongo_find, "analysis")
def denormalize_files_from_reports(reports):
    """Pull the file info from the FILES_COLL collection in to associated parts of
    the reports.
    """
    def denormalize_generator(reports_iterable):
        # Optimization: Ensure we have an iterator to avoid infinite loops on lists
        reports_iter = iter(reports_iterable)
        batch_size = 50
        while True:
            # Grab a batch of reports from the cursor
            reports_batch = list(itertools.islice(reports_iter, batch_size))
            if not reports_batch:
                break

            file_dicts = [
                file_dict
                for file_dict in itertools.chain.from_iterable(collect_file_dicts(report) for report in reports_batch)
                if FILE_REF_KEY in file_dict
            ]

            if file_dicts:
                file_refs = {file_dict[FILE_REF_KEY] for file_dict in file_dicts}
                file_docs = {}
                file_ref_batch_size = 50
                file_ref_iter = iter(file_refs)
                while batch := tuple(itertools.islice(file_ref_iter, file_ref_batch_size)):
                    # Reduce the size of the $in clause when there are large numbers of file refs by
                    # making multiple requests, passing batches of refs in.
                    for file_doc in mongo_find(FILES_COLL, {"_id": {"$in": batch}}, {TASK_IDS_KEY: 0}):
                        file_docs[file_doc.pop("_id")] = file_doc

                for file_dict in file_dicts:
                    if file_dict[FILE_REF_KEY] not in file_docs:
                        log.warning("Failed to find %s in %s collection.", FILES_COLL, file_dict[FILE_REF_KEY])
                        continue
                    file_doc = file_docs[file_dict.pop(FILE_REF_KEY)]
                    file_dict.update(file_doc)

            yield from reports_batch

    return denormalize_generator(reports)


@mongo_hook(mongo_find_one, "analysis")
def denormalize_files(report):
    """Pull the file info from the FILES_COLL collection in to associated parts of
    the report.
    """
    # Consume the generator so the report is denormalized in-place
    list(denormalize_files_from_reports([report]))
    return report


def _is_chunk_pointer(node):
    return isinstance(node, dict) and node.get("__chunked__") is True and node.get("collection") == ANALYSIS_CHUNKS_COLL


def _rehydrate_chunk_pointer(pointer):
    part_ids = pointer.get("parts") or []
    if not part_ids:
        return None
    docs = list(mongo_find(ANALYSIS_CHUNKS_COLL, {"_id": {"$in": part_ids}}, {"_id": 1, "seq": 1, "data": 1}, sort=[("seq", 1)]))
    by_id = {d["_id"]: d for d in docs}
    payload = b"".join(bytes(by_id[_id]["data"]) for _id in part_ids if _id in by_id)
    return json.loads(payload.decode("utf-8"))


def _rehydrate_inplace(node):
    if isinstance(node, dict):
        for key, value in list(node.items()):
            if _is_chunk_pointer(value):
                node[key] = _rehydrate_chunk_pointer(value)
            else:
                _rehydrate_inplace(value)
    elif isinstance(node, list):
        for idx, value in enumerate(node):
            if _is_chunk_pointer(value):
                node[idx] = _rehydrate_chunk_pointer(value)
            else:
                _rehydrate_inplace(value)


@mongo_hook(mongo_find_one, "analysis")
def rehydrate_analysis_chunks(report):
    _rehydrate_inplace(report)
    return report


@mongo_hook(mongo_find, "analysis")
def rehydrate_analysis_chunks_many(reports):
    reports = list(reports)
    for report in reports:
        _rehydrate_inplace(report)
    return reports


@mongo_hook(mongo_delete_data, "analysis")
def remove_task_references_from_files(task_ids):
    """Remove the given task_ids from the TASK_IDS_KEY field on "files"
    documents that were referenced by those tasks that are being deleted.
    """
    mongo_update_many(
        FILES_COLL,
        {TASK_IDS_KEY: {"$in": task_ids}},
        {"$pullAll": {TASK_IDS_KEY: task_ids}},
    )


@mongo_hook(mongo_delete_data_range, "analysis")
def remove_task_references_from_files_range(*, range_start: int = 0, range_end: int = 0):
    """Remove the given task_ids from the TASK_IDS_KEY field on "files"
    documents that were referenced by those tasks that are being deleted.
    """
    range_query = {}
    if range_start > 0:
        range_query["$gte"] = range_start
    if range_end > 0:
        range_query["$lt"] = range_end
    if range_query:
        mongo_update_many(
            FILES_COLL,
            {TASK_IDS_KEY: {"$elemMatch": range_query}},
            {"$pull": {TASK_IDS_KEY: range_query}},
        )


def delete_unused_file_docs():
    """Delete entries in the FILES_COLL collection that are no longer
    referenced by any analysis tasks. This should typically be invoked
    via utils/cleaners.py in a cron job.
    """
    # Using exact empty array match is much faster than $size: 0
    return mongo_delete_many(FILES_COLL, {TASK_IDS_KEY: []})


NORMALIZED_FILE_FIELDS = ("target.file", "dropped", "CAPE.payloads", "procdump", "procmemory")


def collect_file_dicts(report) -> itertools.chain:
    """Return an iterable containing all of the candidates for files
    from various parts of the report to be normalized.
    """
    # ToDo extend to self extract
    file_dicts = []
    target_file = report.get("target", {}).get("file", None)
    if target_file and not _is_chunk_pointer(target_file):
        file_dicts.append([target_file])

    dropped = report.get("dropped", None)
    if dropped and not _is_chunk_pointer(dropped):
        file_dicts.append(dropped)

    cape = report.get("CAPE", {})
    if cape and not _is_chunk_pointer(cape):
        payloads = cape.get("payloads", None)
        if payloads and not _is_chunk_pointer(payloads):
            file_dicts.append(payloads)

    procdump = report.get("procdump", None)
    if procdump and not _is_chunk_pointer(procdump):
        file_dicts.append(procdump)

    suricata = report.get("suricata", {})
    if suricata and not _is_chunk_pointer(suricata):
        files = suricata.get("files", [])
        if files and not _is_chunk_pointer(files):
            file_dicts.append(list(filter(None, [file_info.get("file_info", []) for file_info in files])))

    return itertools.chain.from_iterable(file_dicts)



# --------- Configs normalization helpers ---------

CONFIGS_COLL = "configs"


def _collect_leaf_values(node, out_set: set[str]) -> None:
    """Recursively collect leaf values from dicts/lists into out_set as strings."""
    if node is None:
        return
    if isinstance(node, dict):
        for v in node.values():
            _collect_leaf_values(v, out_set)
    elif isinstance(node, (list, tuple, set)):
        for v in node:
            _collect_leaf_values(v, out_set)
    else:
        sval = str(node)
        if sval and len(sval) >= 2:  # avoid trivial tokens
            out_set.add(sval)


def collect_config_values(report: dict) -> set[str]:
    """
    Extract all leaf values from CAPE.configs.
    Schema looks like: [{family1: {...}}, {family2: {...}}, ...]
    Returns a deduped set of strings.
    """
    values: set[str] = set()
    cape = report.get("CAPE", {})
    cfgs = cape.get("configs", [])
    if not isinstance(cfgs, list):
        return values
    for entry in cfgs:
        if not isinstance(entry, dict):
            continue
        for _, cfgdict in entry.items():
            if isinstance(cfgdict, dict):
                _collect_leaf_values(cfgdict, values)
    return values


@mongo_hook((mongo_insert_one, mongo_update_one), "analysis")
def normalize_configs(report):
    """Extract unique config values from CAPE.configs and insert into CONFIGS_COLL."""
    task_id = report.get("info", {}).get("id")
    if not task_id:
        return report

    values = collect_config_values(report)
    if not values:
        return report

    # Prepare bulk upserts (one per value)
    requests = [
        UpdateOne(
            {"task_id": int(task_id), "value": val},
            {"$setOnInsert": {"task_id": int(task_id), "value": val}},
            upsert=True,
        )
        for val in values
    ]

    try:
        if requests:
            mongo_bulk_write(CONFIGS_COLL, requests, ordered=False)
    except errors.BulkWriteError as exc:
        log.debug("Bulk write error in normalize_configs: %s", exc.details)

    return report


@mongo_hook(mongo_delete_data, "analysis")
def remove_configs_on_delete(task_ids):
    """Remove all configs tied to deleted task(s)."""
    if isinstance(task_ids, int):
        task_ids = [task_ids]
    if task_ids:
        mongo_delete_many(CONFIGS_COLL, {"task_id": {"$in": task_ids}})


@mongo_hook(mongo_delete_data_range, "analysis")
def remove_configs_on_delete_range(*, range_start: int = 0, range_end: int = 0):
    """Remove all configs tied to deleted tasks in the given range."""
    task_id_query = {}
    if range_start > 0:
        task_id_query["$gte"] = range_start
    if range_end > 0:
        task_id_query["$lt"] = range_end
    if task_id_query:
        mongo_delete_many(CONFIGS_COLL, {"task_id": task_id_query})


# Ensure rehydrate_analysis_chunks runs before other find hooks
from dev_utils.mongodb import hooks

if rehydrate_analysis_chunks in hooks[mongo_find_one]["analysis"]:
    hooks[mongo_find_one]["analysis"].remove(rehydrate_analysis_chunks)
    hooks[mongo_find_one]["analysis"].insert(0, rehydrate_analysis_chunks)

if rehydrate_analysis_chunks_many in hooks[mongo_find]["analysis"]:
    hooks[mongo_find]["analysis"].remove(rehydrate_analysis_chunks_many)
    hooks[mongo_find]["analysis"].insert(0, rehydrate_analysis_chunks_many)
