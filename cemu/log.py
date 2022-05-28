from typing import Callable

import cemu.const

loggers = set()


def register_sink(cb: Callable):
    global loggers
    loggers.add(cb)


def unregister_sink(cb: Callable):
    global loggers
    loggers.remove(cb)


def log(msg: str):
    for callback in loggers:
        callback(msg)


def error(msg: str) -> None:
    log(f"[ERROR] {msg}")


def warn(msg: str) -> None:
    log(f"[WARNING] {msg}")


def info(msg: str) -> None:
    log(f"[INFO] {msg}")


def ok(msg: str) -> None:
    log(f"[SUCCESS] {msg}")


def dbg(msg: str) -> None:
    if cemu.const.DEBUG:
        log(f"[DEBUG] {msg}")
