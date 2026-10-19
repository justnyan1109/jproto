"""Общие фикстуры и утилиты pytest для python/tests.

- sys.path на <repo>/python (импорт jproto_ref), как договаривались.
- уникальные порты через get_free_port() — без хардкода.
"""

import secrets
import socket
import sys
from pathlib import Path

import pytest

_PY = Path(__file__).resolve().parent.parent          # <repo>/python
if str(_PY) not in sys.path:
    sys.path.insert(0, str(_PY))
sys.path.insert(0, str(Path(__file__).resolve().parent))  # импорт common-хелперов


def get_free_port() -> int:
    """Свободный TCP порт (bind-закрытие — пул портов схлопывать не страшно)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def get_free_ports(n: int) -> list[int]:
    ports = []
    while len(ports) < n:
        p = get_free_port()
        if p not in ports:
            ports.append(p)
    return ports


@pytest.fixture
def fresh_seed_hour() -> bytes:
    """Единый seed_hour для PoW-контекста теста (cache дорог — строим один)."""
    return secrets.token_bytes(32)
