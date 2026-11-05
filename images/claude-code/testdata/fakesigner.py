"""A stand-in for the box's signer socket (/run/tkbox/signer.sock) for the image test: it answers the frames Tracekit's
hook client sends at SessionStart well enough for the hook to register its run and write its state, and logs each
method it was sent. Usage: python3 -I fakesigner.py SOCKET LOG"""
import json
import os
import socket
import sys
import threading

ANSWERS = {
    "hello": {"proto": [15, 21], "version": "1.6.0", "pid": 1},
    "register_run": {"run_id": "run-1", "run_token": "tok-1", "fail_modes": {"default": "closed"}},
    "status": {"rpc_version": 21, "signer": {"name": "fake", "version": "1.6.0"},
               "identity": {"scheme": "uid", "subject": "0", "attested": True}},
}


def serve(conn, log):
    with conn, conn.makefile("rb") as r:
        for line in r:
            method = json.loads(line).get("method", "")
            with open(log, "a") as f:
                f.write(method + "\n")
            conn.sendall(json.dumps(ANSWERS.get(method, {"ok": True})).encode() + b"\n")


def main(path, log):
    s = socket.socket(socket.AF_UNIX)
    s.bind(path)
    os.chmod(path, 0o666)
    s.listen()
    while True:
        conn, _ = s.accept()
        threading.Thread(target=serve, args=(conn, log), daemon=True).start()


if __name__ == "__main__":
    main(*sys.argv[1:3])
