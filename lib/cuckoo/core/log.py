# Copyright (C) 2016-2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import copy
import json
import logging
import logging.handlers
import os
import threading
import time

import gevent.thread

from lib.cuckoo.common.colors import cyan, red, yellow
from lib.cuckoo.common.misc import cwd
from lib.cuckoo.common.path_utils import path_exists
from lib.cuckoo.core.database import Database

_task_threads = {}
_tasks = {}
_loggers = {}

_tasks_lock = threading.Lock()

# Current GMT+x.
if time.localtime().tm_isdst:
    tz = time.altzone / -3600.0
else:
    tz = time.timezone / -3600.0

# The greenlet library (used by Gevent) also creates some state per thread,
# so we can (ab)use this for both multi-threading and Gevent code
task_key = gevent.thread.get_ident


class DatabaseHandler(logging.Handler):
    """Logging to database handler.
    Used to log errors related to tasks in database.
    """

    def emit(self, record):
        # TODO Should this also attempt to guess the task ID from _tasks?
        if hasattr(record, "task_id"):
            Database().add_error(self.format(record), int(record.task_id))


class TaskHandler(logging.Handler):
    """Per-task logger.
    Used to log all task specific events to a per-task cuckoo.log log file.
    """

    def emit(self, record):
        task = _tasks.get(task_key())
        if not task:
            return

        task[1].write(f"{self.format(record)}\n".encode())


class ConsoleHandler(logging.StreamHandler):
    """Logging to console handler."""

    def emit(self, record):
        colored = copy.copy(record)

        if record.levelname == "WARNING":
            colored.msg = yellow(record.msg)
        elif record.levelname in ("ERROR", "CRITICAL"):
            colored.msg = red(record.msg)
        else:
            # Hack for pymongo.logger.LogMessage
            if not isinstance(record.msg, str):
                record.msg = str(record.msg)

            if "analysis procedure completed" in record.msg:
                colored.msg = cyan(record.msg)
            else:
                colored.msg = record.msg

        logging.StreamHandler.emit(self, colored)


class JsonFormatter(logging.Formatter):
    """Logging Cuckoo logs to JSON."""

    def format(self, record):
        action = record.__dict__.get("action")
        status = record.__dict__.get("status")
        task = _tasks.get(task_key())
        task_id = task[0] if task else record.__dict__.get("task_id")
        d = {
            "action": action,
            "task_id": task_id,
            "status": status,
            "time": record.created,
            "level": record.levelname.lower(),
            "message": record.getMessage(),
        }
        base = logging.makeLogRecord({})
        for key, value in record.__dict__.items():
            if key not in base.__dict__:
                d[key] = value
        return json.dumps(d)

    def filter(self, record):
        action = record.__dict__.get("action")
        status = record.__dict__.get("status")
        return action and status


def task_log_start(task_id):
    """Associate a thread with a task."""
    _tasks_lock.acquire()
    try:
        if task_id not in _task_threads:
            task_path = cwd(analysis=task_id)
            if not path_exists(task_path):
                return

            _task_threads[task_id] = []
            fp = open(os.path.join(task_path, "cuckoo.log"), "a+b")
            _tasks[task_key()] = (task_id, fp)
        else:
            existing_key = _task_threads[task_id][0]
            _tasks[task_key()] = _tasks[existing_key]

        _task_threads[task_id].append(task_key())
    finally:
        _tasks_lock.release()


def task_log_stop(task_id):
    """Disassociate a thread from a task."""
    _tasks_lock.acquire()
    try:
        thread_key = task_key()
        if thread_key not in _tasks:
            return

        _, fp = _tasks.pop(thread_key)
        _task_threads[task_id].remove(thread_key)
        if not _task_threads[task_id]:
            fp.close()
            _task_threads.pop(task_id)
    finally:
        _tasks_lock.release()


def init_logger(name, level=None):
    formatter = logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s")

    if name == "console":
        logger = ConsoleHandler()
        logger.setFormatter(formatter)
        logger.setLevel(level)

    elif name == "database":
        logger = DatabaseHandler()
        logger.setLevel(logging.ERROR)

    elif name == "task":
        logger = TaskHandler()
        logger.setFormatter(formatter)
        logger.setLevel(logging.DEBUG)

    _loggers[name] = logger
    logging.getLogger().addHandler(logger)


def logger(message, *args, **kwargs):
    """Log a message to specific logger instance."""
    logfile = kwargs.pop("logfile", None)
    record = logging.LogRecord(None, logging.INFO, None, None, message, args, None, None)
    record.asctime = f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(record.created))},{record.msecs:03d}"
    record.message = record.getMessage()
    record.__dict__.update(kwargs)

    for key, value in _loggers.items():
        if logfile and key == logfile:
            value.handle(record)
        if logfile is None and key.endswith(".json"):
            value.handle(record)
