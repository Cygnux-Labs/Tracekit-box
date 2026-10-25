import io
import json
import os

import pytest

from fake_daemon import FakeDaemon
from tracekit_box import (
    BadRequest,
    Cancelled,
    Client,
    Conflict,
    DaemonUnreachable,
    Denied,
    LimitError,
    Limits,
    NotFound,
    Secret,
    TkboxError,
    Unavailable,
    default_socket,
    frames,
)


@pytest.fixture
def daemon():
    d = FakeDaemon().start()
    yield d
    d.stop()


@pytest.fixture
def client(daemon):
    return Client(socket=daemon.path, timeout=10)


@pytest.fixture
def box(client):
    return client.create_box("python:3.12-slim", name="demo", allow=["pypi"])


def test_health(client):
    h = client.health()
    assert h["api"] == "v1"
    assert h["signer_ok"] is True


def test_create_list_get(client, daemon, tmp_path):
    b = client.run(
        "python:3.12-slim",
        name="demo",
        allow="pypi",
        secrets={
            "GH": Secret("ghp_real", ["API.github.com"], "Authorization"),
            "OTHER": {"value": "v", "hosts": ["example.com"]},
        },
        env={"A": "1"},
        workspace=str(tmp_path),
        limits=Limits(cpus=4, timeout="2h", exec_timeout=600),
        inspect="all",
        task="fix the test",
    )
    assert b["name"] == "demo" and b["state"] == "running"
    assert b["secrets"] == ["GH", "OTHER"]
    sent = daemon.requests[-1]
    assert sent["method"] == "POST" and sent["path"] == "/v1/boxes"
    assert sent["headers"]["content-type"] == "application/json"
    body = sent["body"]
    assert body["allow"] == ["pypi"]
    assert body["secrets"]["GH"] == {"value": "ghp_real", "hosts": ["api.github.com"], "header": "Authorization"}
    assert body["limits"] == {"cpus": 4, "timeout": "2h", "exec_timeout": 600}
    assert body["workspace"] == str(tmp_path) and os.path.isabs(body["workspace"])
    assert body["inspect"] == "all" and body["task"] == "fix the test"
    assert [x["name"] for x in client.list_boxes()] == ["demo"]
    assert client.get_box("demo")["id"] == b["id"]
    assert client.get_box(b["id"])["name"] == "demo"


def test_secret_repr_hides_value():
    assert "ghp_real" not in repr(Secret("ghp_real", ["api.github.com"]))


def test_secret_without_hosts_is_refused_locally(client):
    with pytest.raises(ValueError):
        client.create_box("alpine", secrets={"X": {"value": "v"}})


def test_conflict(client, box):
    with pytest.raises(Conflict) as e:
        client.create_box("alpine", name="demo")
    assert e.value.status == 409
    assert "tkbox rm demo" in e.value.hint
    assert isinstance(e.value, TkboxError)


def test_not_found(client):
    with pytest.raises(NotFound) as e:
        client.get_box("nope")
    assert e.value.code == "not_found" and "tkbox ls" in str(e.value)


def test_unavailable_fails_closed(client, daemon):
    daemon.signer_ok = False
    with pytest.raises(Unavailable) as e:
        client.create_box("alpine")
    assert "tracekit up" in e.value.hint


def test_limit(client, daemon):
    daemon.max_boxes = 1
    client.create_box("alpine", name="a")
    with pytest.raises(LimitError) as e:
        client.create_box("alpine", name="b")
    assert e.value.hint


def test_non_json_error(client):
    with pytest.raises(TkboxError) as e:
        client._json("GET", "/nope")
    assert e.value.status == 404 and "404 page not found" in e.value.message


def test_exec_echo(client, box, daemon):
    r = client.exec("demo", ["echo", "hello", "world"])
    assert r.exit_code == 0 and r.ok
    assert r.stdout == b"hello world\n" and r.stdout_text == "hello world\n"
    assert r.stderr == b""
    assert [e["state"] for e in r.events] == ["deciding", "deciding", "running"]
    assert r.events[1]["decision"] == "allow"
    assert r.duration_ms == 3
    sent = daemon.requests[-1]
    assert sent["path"] == "/v1/boxes/demo/exec"
    assert sent["headers"]["upgrade"] == "tkbox-exec/1"
    assert sent["headers"]["connection"].lower() == "upgrade"
    assert sent["body"] == {"argv": ["echo", "hello", "world"]}


@pytest.mark.parametrize("stdin", [b"bytes in\n", "text in\n", io.BytesIO(b"file in\n")])
def test_exec_stdin(client, box, daemon, stdin):
    r = client.exec("demo", ["cat"], stdin=stdin)
    expected = stdin.getvalue() if isinstance(stdin, io.BytesIO) else stdin
    if isinstance(expected, str):
        expected = expected.encode()
    assert r.stdout == expected
    assert daemon.exec_requests[-1]["stdin"] is True


def test_exec_stdin_larger_than_a_frame(client, box):
    data = os.urandom(frames.MAX_FRAME * 2 + 123)
    r = client.exec("demo", ["cat"], stdin=data)
    assert r.stdout == data


def test_exec_stdin_not_read(client, box):
    # the process exits without reading stdin: the result still arrives and the stdin writer gives up quietly
    r = client.exec("demo", ["echo", "done"], stdin=b"y" * (frames.MAX_FRAME * 3))
    assert r.stdout == b"done\n" and r.exit_code == 0


def test_exec_request_fields(client, box):
    r = client.exec("demo", ["showreq"], env={"K": "V"}, cwd="/workspace/sub", timeout=90)
    req = json.loads(r.stdout)
    assert req == {"argv": ["showreq"], "env": {"K": "V"}, "cwd": "/workspace/sub", "timeout": 90}
    r = client.exec("demo", ["showreq"], timeout="5m")
    assert json.loads(r.stdout)["timeout"] == "5m"


def test_exec_nonzero_exit(client, box):
    r = client.exec("demo", ["fail", "3"])
    assert r.exit_code == 3 and not r.ok
    assert r.stderr == b"boom\n"


def test_exec_denied(client, box):
    with pytest.raises(Denied) as e:
        client.exec("demo", ["deny"])
    assert e.value.rule_ids == ["TK-D001"]
    assert e.value.stdout == b""
    assert e.value.events[-1]["decision"] == "deny"
    assert "TK-D001" in str(e.value)


def test_exec_unavailable(client, box):
    with pytest.raises(Unavailable):
        client.exec("demo", ["nosigner"])


def test_exec_cancelled(client, box):
    with pytest.raises(Cancelled) as e:
        client.exec("demo", ["cancelled"])
    assert e.value.code == "cancelled" and "nothing ran" in e.value.message
    assert isinstance(e.value, TkboxError)


def test_exec_missing_executable(client, box):
    with pytest.raises(NotFound) as e:
        client.exec("demo", ["nosuchcmd"])
    assert e.value.message.startswith("start ") and e.value.hint


def test_exec_timed_out(client, box):
    r = client.exec("demo", ["sleep"])
    assert r.timed_out and r.signal == "SIGKILL" and r.exit_code == -1 and not r.ok


def test_exec_notice_and_callbacks(client, box):
    seen_events, seen_out = [], []
    r = client.exec(
        "demo",
        ["curl", "example.com"],
        on_event=seen_events.append,
        on_output=lambda stream, data: seen_out.append((stream, data)),
    )
    assert r.exit_code == 56
    assert len(r.notices) == 1 and "not on the allowlist" in r.notices[0]
    waiting = [e for e in r.events if e["state"] == "waiting_approval"]
    assert waiting[0]["approval_id"] == "ap_2"
    assert seen_events == r.events
    assert seen_out == [("stderr", b"curl: (56) CONNECT tunnel failed, response 403\n")]


def test_exec_large_output(client, box):
    n = frames.MAX_FRAME * 2 + 5
    r = client.exec("demo", ["big", str(n)])
    assert len(r.stdout) == n


def test_exec_unknown_box(client):
    with pytest.raises(NotFound):
        client.exec("nope", ["echo"])


def test_exec_argv_must_be_a_list(client, box):
    with pytest.raises(ValueError):
        client.exec("demo", "echo hi")


def test_stop_diff_apply_export_rm(client, box, tmp_path):
    assert client.stop("demo", reason="done")["state"] == "stopped"
    d = client.diff("demo")
    assert "+++ b/x.txt" in d.patch
    assert d.files == [{"path": "x.txt", "status": "added", "new_mode": 0o644}]
    assert d.summary["bytes"] == len(d.patch)
    assert client.apply("demo", check=True) == {
        "applied": [],
        "patch": "/state/boxes/b_1/diff.patch",
        "checked": True,
        "sha256": "ab" * 32,
    }
    assert client.apply("demo", dir=str(tmp_path))["applied"] == ["x.txt"]
    out = tmp_path / "demo.tkb"
    ex = client.export("demo", str(out))
    assert ex["bundle"] == str(out) and ex["trust"] == str(out) + ".trust.json"
    assert ex["verify"].startswith("tracekit verify ")
    client.rm("demo")
    assert client.list_boxes() == []


def test_apply_running_box_is_a_conflict(client, box):
    with pytest.raises(Conflict) as e:
        client.apply("demo")
    assert "tkbox stop demo" in e.value.hint


def test_apply_sensitive(client, box, daemon):
    client.stop("demo")
    daemon.sensitive = [".github/workflows/ci.yml"]
    daemon.ignored = ["build/out.bin"]
    with pytest.raises(BadRequest) as e:
        client.apply("demo")
    assert ".github/workflows/ci.yml" in e.value.message and "--allow-sensitive" in e.value.hint
    assert "allow_sensitive" not in daemon.requests[-1]["body"]
    r = client.apply("demo", allow_sensitive=True)
    assert daemon.requests[-1]["body"] == {"allow_sensitive": True}
    assert r["sensitive"] == [".github/workflows/ci.yml"]
    assert r["ignored"] == ["build/out.bin"]
    assert r["applied"] == ["x.txt", ".github/workflows/ci.yml"]
    assert r["sha256"] == "ab" * 32


def test_stop_kill(client, box, daemon):
    client.stop("demo", kill=True)
    assert daemon.requests[-1]["body"] == {"kill": True}


def test_events(client, box):
    evs = list(client.events("demo"))
    assert [e["kind"] for e in evs] == ["box.created", "exec.decided", "egress.denied"]


def test_events_follow_sends_query(client, box, daemon):
    list(client.events("demo", follow=True))
    assert daemon.requests[-1]["query"] == "follow=1"


def test_approvals(client, daemon):
    pending = client.approvals()
    assert [a["id"] for a in pending] == ["ap_1"]
    assert client.approve("ap_1", scope="box")["state"] == "approved"
    assert daemon.requests[-1]["body"] == {"decision": "approve", "scope": "box"}
    assert client.approvals() == []
    daemon.approvals["ap_1"]["state"] = "pending"
    assert client.reject("ap_1")["state"] == "rejected"
    with pytest.raises(NotFound):
        client.approve("ap_9")


def test_box_names_are_escaped(client, daemon):
    with pytest.raises(NotFound):
        client.get_box("a/b c")
    assert daemon.requests[-1]["path"] == "/v1/boxes/a%2Fb%20c"


def test_daemon_unreachable(daemon):
    c = Client(socket=os.path.join(daemon.dir, "missing.sock"))
    with pytest.raises(DaemonUnreachable) as e:
        c.health()
    assert "tkbox daemon" in e.value.hint


def test_default_socket(monkeypatch, tmp_path):
    monkeypatch.setenv("TKBOX_SOCKET", "/x/tkbox.sock")
    assert default_socket() == "/x/tkbox.sock"
    monkeypatch.delenv("TKBOX_SOCKET")
    if os.geteuid() == 0:
        assert default_socket() == "/var/lib/tkbox/run/tkbox.sock"
    else:
        monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
        assert default_socket() == str(tmp_path / "tkbox" / "run" / "tkbox.sock")
        monkeypatch.delenv("XDG_STATE_HOME")
        assert default_socket() == os.path.expanduser("~/.local/state/tkbox/run/tkbox.sock")


def test_frames_roundtrip():
    buf = io.BytesIO(frames.encode(frames.TYPE_STDOUT, b"abc") + frames.encode_json(frames.TYPE_EXIT, {"code": 0}))
    f = frames.read(buf)
    assert f == frames.Frame(frames.TYPE_STDOUT, b"abc")
    assert frames.read(buf).json() == {"code": 0}
    assert frames.read(buf) is None


def test_frames_limits():
    with pytest.raises(frames.FrameError):
        frames.encode(frames.TYPE_STDIN, b"x" * (frames.MAX_FRAME + 1))
    too_big = bytes([2]) + (frames.MAX_FRAME + 1).to_bytes(4, "big")
    with pytest.raises(frames.FrameError):
        frames.read(io.BytesIO(too_big))
    with pytest.raises(frames.FrameError):
        frames.read(io.BytesIO(frames.encode(frames.TYPE_STDOUT, b"abc")[:-1]))
    assert len(list(frames.chunks(frames.TYPE_STDIN, b"x" * (frames.MAX_FRAME + 1)))) == 2


def test_exec_stdin_truncated_is_a_failure(client, box):
    r = client.exec(box, ["stdin-unread"])
    assert r.stdin_truncated and r.stdin_dropped_bytes == 4096
    assert not r.ok
