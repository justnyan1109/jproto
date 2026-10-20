"""CLI узла jproto (docker-модуль): python -m jproto_ref [флаги].

Флаги дублируются переменными среды JP_* (env имеет приоритет ниже флага).
Без аргументов и без JP_* — печатает справку и выходит (exit 0).
"""

import argparse
import asyncio
import os
import sys


def _env(name: str) -> str | None:
    v = os.environ.get(name)
    return v if v not in (None, "") else None


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m jproto_ref",
        description="jproto federation node (Python reference). Без аргументов — справка, exit 0.")
    p.add_argument("--port", type=int, help="TCP wire-порт (env JP_PORT, деф. 9100)")
    p.add_argument("--host", help="bind-адрес (env JP_HOST, деф. 0.0.0.0)")
    p.add_argument("--publish-host", help="адрес для dir-entry (env JP_PUBLISH_HOST, деф. 127.0.0.1)")
    p.add_argument("--http-port", type=int, default=None,
                   help="HTTP dev-порт, 0 = выкл (env JP_HTTP_PORT, деф. 9200)")
    p.add_argument("--peer", action="append", default=[], metavar="HOST:PORT",
                   help="bootstrap-пир, можно повторять (env JP_PEERS: CSV host:port)")
    p.add_argument("--name", help="имя узла для логов (env JP_NAME)")
    p.add_argument("--data-dir", help="каталог состояния BS (env JP_DATA_DIR, деф. /tmp/jp-data)")
    p.add_argument("--pow-lib", help="путь к libjppow.so (env JPPOW_LIB, деф. build/libjppow.so)")
    return p


def _parse_peers(items: list[str]) -> list[tuple[str, int]]:
    out: list[tuple[str, int]] = []
    for raw in items:
        for tok in raw.split(","):
            tok = tok.strip()
            if not tok:
                continue
            host, sep, port = tok.rpartition(":")
            if not sep or not host or not port.isdigit():
                raise SystemExit(f"ошибка: ожидался HOST:PORT, получено: {tok!r}")
            out.append((host, int(port)))
    return out


def _cfg_from_cli() -> dict:
    """cfg = DEFAULTS ⊕ flag-значения ⊕ env-значения (env слабее флага)."""
    over: dict = {}
    argv = sys.argv[1:]
    env_seen = any(_env(k) for k in ("JP_PORT", "JP_HTTP_PORT", "JP_PEERS", "JP_NAME", "JP_DATA_DIR"))
    if not argv and not env_seen:
        _build_parser().print_help()
        raise SystemExit(0)
    p = _build_parser()
    a = p.parse_args(argv)

    if a.port is not None:
        over["port"] = int(a.port)
    elif (v := _env("JP_PORT")) is not None:
        over["port"] = int(v)

    if a.host is not None:
        over["host"] = a.host
    elif (v := _env("JP_HOST")) is not None:
        over["host"] = v

    if a.publish_host is not None:
        over["publish_host"] = a.publish_host
    elif (v := _env("JP_PUBLISH_HOST")) is not None:
        over["publish_host"] = v

    if a.http_port is not None:
        over["http_port"] = int(a.http_port)
    elif (v := _env("JP_HTTP_PORT")) is not None:
        over["http_port"] = int(v)

    peers = _parse_peers(a.peer)
    if not peers and (v := _env("JP_PEERS")) is not None:
        peers = _parse_peers([v])
    if peers:
        over["peers"] = peers

    if a.name:
        over["name"] = a.name
    elif (v := _env("JP_NAME")) is not None:
        over["name"] = v

    if a.data_dir:
        over["data_dir"] = a.data_dir
    else:
        v = _env("JP_DATA_DIR")
        over["data_dir"] = v if v is not None else "/tmp/jp-data"

    if a.pow_lib:
        os.environ["JPPOW_LIB"] = a.pow_lib
    elif (v := _env("JPPOW_LIB")) is not None:
        os.environ["JPPOW_LIB"] = v
    return over


async def _amain(over: dict) -> None:
    # импорт внутри: JPPOW_LIB должен быть выставлен до загрузки .pow
    from .node import DEFAULTS, Node
    cfg = dict(DEFAULTS)
    cfg.update(over)
    node = Node(cfg)
    try:
        await node.run()
    finally:
        await node.stop()


def main() -> int:
    over = _cfg_from_cli()
    try:
        asyncio.run(_amain(over))
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
