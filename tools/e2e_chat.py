#!/usr/bin/env python3
"""e2e-chat: два клиента jchat (host→docker федерация) — onion+v2, secchan, PoW.

fedA:9101 wire-порт fedA (host-mapped). Alice (fedA) шлёт маркер Bob'у
(fedA, same-node чат). Bob ждёт маркер, отвечает reply, alice ждёт reply.
Требует: docker compose up (make docker-up), venv python с cryptography.

Usage: tools/e2e_chat.py [node_host:port] [marker]
"""

import subprocess
import sys
import tempfile
import os
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PY = str(REPO / "python/.venv/bin/python")
if not os.path.exists(PY):
    PY = sys.executable

NODE = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1:9101"
MARK = sys.argv[2] if len(sys.argv) > 2 else f"e2e-{os.getpid()}-маркер"
REPLY = f"got:{MARK}"


def chat(*args, timeout: float) -> subprocess.Popen:
    cmd = [PY, "-m", "jproto_ref.chat", *args]
    env = dict(os.environ, PYTHONPATH=str(REPO / "python"))
    print("$$", " ".join(str(a) for a in cmd))
    return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, cwd=str(REPO / "python"), env=env)


def run(cmd, timeout: float) -> int:
    env = dict(os.environ, PYTHONPATH=str(REPO / "python"))
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         text=True, cwd=str(REPO / "python"), env=env)
    try:
        out, _ = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        p.kill()
        out, _ = p.communicate()
        print("!! timeout", *cmd)
        return 3
    sys.stdout.write(out)
    return p.returncode


def main() -> int:
    tmp = tempfile.mkdtemp(prefix="jchat-e2e-")
    pins = os.path.join(tmp, "pins")
    os.makedirs(pins, exist_ok=True)

    r = run([PY, "-m", "jproto_ref.chat", "keygen", os.path.join(tmp, "alice.json")], 30)
    if r: return r
    r = run([PY, "-m", "jproto_ref.chat", "keygen", os.path.join(tmp, "bob.json")], 30)
    if r: return r

    wait = float(os.environ.get("E2E_WAIT", "45"))

    # Alice: посылает маркер bob'у; потом ждёт reply (bob отвечен тем же ключом
    # alice'а через --to alice.json…, но для MVP bob шлёт reply один: alice
    # просто печатает входящее и выходит).
    p_alice = chat("oneshot", "--node", NODE,
                   "--me", os.path.join(tmp, "alice.json"),
                   "--to", os.path.join(tmp, "bob.json"),
                   "--msg", MARK, "--expect", REPLY,
                   "--pin-dir", pins, timeout=wait + 10)
    # Bob: ждёт маркер, отвечает alice (reply).
    p_bob = chat("oneshot", "--node", NODE,
                 "--me", os.path.join(tmp, "bob.json"),
                 "--to", os.path.join(tmp, "alice.json"),
                 "--expect", MARK, "--reply", REPLY,
                 "--pin-dir", pins, timeout=wait + 10)

    outs = {}
    for name, p in (("alice", p_alice), ("bob", p_bob)):
        out, _ = p.communicate(timeout=wait + 15)
        outs[name] = out
        print(f"--- {name} rc={p.returncode} ---")
        sys.stdout.write(out[-1500:] if len(out) > 1500 else out)

    ok = p_alice.returncode == 0 and p_bob.returncode == 0
    print("E2E-CHAT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
