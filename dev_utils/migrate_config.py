import json
import logging
import os
import sys

from pymongo import UpdateOne, errors

sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), ".."))

from dev_utils.mongodb import mongo_bulk_write, mongo_find, results_db


log = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

CONFIGS_COLL = "configs"


def _walk_values(node):
    """Recursively walk a JSON-compatible structure and yield clean string leaves."""
    if node is None:
        return
    if isinstance(node, (list, tuple, set)):
        for item in node:
            yield from _walk_values(item)
    elif isinstance(node, dict):
        for v in node.values():
            yield from _walk_values(v)
    else:
        sval = str(node).strip()
        if not sval or sval in ("[]", "['']", '[""]'):
            return
        yield sval


def extract_config_values(doc: dict) -> set[str]:
    """Extract and normalize CAPE.configs values from a single analysis doc."""
    values = set()
    configs = doc.get("CAPE", {}).get("configs", [])

    for entry in configs:
        if not isinstance(entry, dict):
            continue
        for _, cfg in entry.items():
            if not isinstance(cfg, dict):
                continue
            for _, v in cfg.items():
                # try to parse stringified JSON-like values
                if isinstance(v, str) and v.strip().startswith("[") and v.strip().endswith("]"):
                    try:
                        parsed = json.loads(v.replace("'", '"'))
                        for item in _walk_values(parsed):
                            values.add(item)
                        continue
                    except Exception:
                        pass
                for item in _walk_values(v):
                    values.add(item)

    return values


def ingest_configs(task_id: int, values: set[str]):
    """Bulk upsert clean config values into the configs collection."""
    if not values:
        return
    requests = [
        UpdateOne(
            {"task_id": int(task_id), "value": val},
            {"$setOnInsert": {"task_id": int(task_id), "value": val}},
            upsert=True,
        )
        for val in values
    ]
    try:
        mongo_bulk_write(CONFIGS_COLL, requests, ordered=False)
    except errors.BulkWriteError:
        pass


def migrate_configs(limit: int | None = None):
    """Migrate CAPE.configs from analysis into configs collection (fresh)."""
    try:
        results_db.drop_collection(CONFIGS_COLL)
        log.info("Dropped entire '%s' collection before migration.", CONFIGS_COLL)
    except Exception as e:
        log.warning("Could not drop '%s' collection: %s", CONFIGS_COLL, e)

    projection = {"info.id": 1, "CAPE.configs": 1, "_id": 0}
    cursor = mongo_find("analysis", {}, projection=projection, sort=[("info.id", 1)], limit=limit)

    count = 0
    for doc in cursor:
        task_id = doc.get("info", {}).get("id")
        if not task_id:
            continue
        values = extract_config_values(doc)
        ingest_configs(task_id, values)
        count += 1
        if count % 100 == 0:
            log.info("Migrated configs for %d tasks...", count)

    log.info("Finished migrating configs for %d tasks", count)


if __name__ == "__main__":
    migrate_configs(limit=None)
