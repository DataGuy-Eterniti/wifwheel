"""Offline tests for app.py: scanner and payment checks are faked; no network."""
import pytest
from fastapi.testclient import TestClient

import app as appmod

TOKEN = "0x" + "ab" * 20
TX = "0x" + "cd" * 32


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(appmod, "CACHE_DIR", str(tmp_path))
    monkeypatch.setattr(appmod, "USED_FILE", str(tmp_path / "used.txt"))
    monkeypatch.setattr(appmod, "WIFWHEEL", "0x" + "ee" * 20)
    appmod.used_txs.clear(); appmod.jobs.clear(); appmod._hits.clear()
    calls = []

    class R:  # minimal stand-in for scanner.Report
        pass

    def fake_scan(addr, deep=True):
        calls.append(deep)
        return {"address": addr, "verdict": "CAUTION", "score": 30, "findings": [], "not_checked": [],
                "facts": {"holders": 10}, "explorer": "x", "name": "T", "symbol": "T", "seconds": 0.1}

    monkeypatch.setattr(appmod.scanner, "scan", fake_scan)
    monkeypatch.setattr(appmod.scanner, "to_dict", lambda r: dict(r))
    c = TestClient(appmod.app)
    c.calls = calls
    return c


def test_quick_check_and_cache(client):
    r = client.post("/api/check", json={"address": TOKEN})
    assert r.status_code == 200 and r.json()["deep"] is False
    client.post("/api/check", json={"address": TOKEN})
    assert client.calls == [False]                     # second call served from cache


def test_bad_address(client):
    assert client.post("/api/check", json={"address": "nope"}).status_code == 400


def test_deep_requires_valid_payment(client, monkeypatch):
    monkeypatch.setattr(appmod, "verify_payment", lambda tx, t: (False, "That transaction did not pay for a check of this token."))
    r = client.post("/api/deep", json={"address": TOKEN, "tx": TX})
    assert r.status_code == 402


def test_deep_runs_once_per_payment(client, monkeypatch):
    monkeypatch.setattr(appmod, "verify_payment", lambda tx, t: (True, ""))
    r = client.post("/api/deep", json={"address": TOKEN, "tx": TX})
    assert r.status_code == 200
    job = r.json()["job"]
    import time
    for _ in range(50):
        j = client.get(f"/api/job/{job}").json()
        if j["status"] != "running":
            break
        time.sleep(0.05)
    assert j["status"] == "done" and j["result"]["deep"] is True
    assert client.post("/api/deep", json={"address": TOKEN, "tx": TX}).status_code == 409   # replay blocked


def test_verify_payment_reads_checkpaid_log(monkeypatch):
    monkeypatch.setattr(appmod, "WIFWHEEL", "0x" + "ee" * 20)
    log = {"address": "0x" + "ee" * 20, "topics": [appmod.CHECK_PAID, "0x" + "0" * 64, "0x" + "0" * 24 + TOKEN[2:]]}
    monkeypatch.setattr(appmod, "pay_rpc", lambda m, p: {"status": "0x1", "logs": [log]})
    assert appmod.verify_payment(TX, TOKEN)[0] is True
    assert appmod.verify_payment(TX, "0x" + "12" * 20)[0] is False


def test_index_served(client):
    r = client.get("/")
    assert r.status_code == 200 and "WifWheel" in r.text


def test_incomplete_deep_scan_frees_payment_and_is_not_cached(client, monkeypatch):
    monkeypatch.setattr(appmod, "verify_payment", lambda tx, t: (True, ""))
    monkeypatch.setattr(appmod.scanner, "scan", lambda a, deep=True: {"address": a, "verdict": "INCOMPLETE CHECK", "score": 0,
        "findings": [], "not_checked": ["Transfer history (429)"], "facts": {"incomplete": True}, "explorer": "x"})
    import time
    job = client.post("/api/deep", json={"address": TOKEN, "tx": TX}).json()["job"]
    for _ in range(50):
        j = client.get(f"/api/job/{job}").json()
        if j["status"] != "running":
            break
        time.sleep(0.05)
    assert j["status"] == "error" and j["retry"] is True
    assert appmod.cache_get(TOKEN, True) is None
    assert client.post("/api/deep", json={"address": TOKEN, "tx": TX}).status_code == 200   # same payment retries


def test_used_payments_survive_restart(client, monkeypatch, tmp_path):
    monkeypatch.setattr(appmod, "verify_payment", lambda tx, t: (True, ""))
    client.post("/api/deep", json={"address": TOKEN, "tx": TX})
    assert TX.lower() in open(appmod.USED_FILE).read()


def test_healthz(client):
    assert client.get("/healthz").json() == {"ok": True}
