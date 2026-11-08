"""WifWheel web app.

    uvicorn app:app --port 8000      ->  http://localhost:8000

Routes
    GET  /                      the app
    GET  /api/config            contract addresses, chain and fees for the page
    POST /api/check             {"address"}                  quick check (free, rate-limited)
    POST /api/deep              {"address", "tx"}            deep check, after a payForCheck transaction
    GET  /api/job/{id}          deep-check progress / result
    GET  /api/register          recent scam reports and flagged tokens (read from the contract)

Payments run on Robinhood Chain testnet with a mock $WIF; token checks read mainnet. A deep check is only
started for a transaction that really emitted CheckPaid for that token on the WifWheel contract, and each
transaction can be used once.
"""
import json
import os
import re
import threading
import time
import uuid
from collections import defaultdict, deque

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse

load_dotenv()

import scanner  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
PAY_NETWORKS = {
    "testnet": {"chain_id": 46630, "rpc": "https://rpc.testnet.chain.robinhood.com",
                "explorer": "https://explorer.testnet.chain.robinhood.com", "name": "Robinhood Chain Testnet"},
    "mainnet": {"chain_id": 4663, "rpc": "https://rpc.mainnet.chain.robinhood.com",
                "explorer": "https://robinhoodchain.blockscout.com", "name": "Robinhood Chain"},
}
PAY = PAY_NETWORKS[os.getenv("NETWORK", "testnet")]
PAY_RPC = os.getenv("RPC_URL") or PAY["rpc"]
WIFWHEEL = (os.getenv("WIFWHEEL_ADDRESS") or "").strip()
WIF = (os.getenv("WIF_ADDRESS") or "").strip()
CACHE_DIR = os.path.join(HERE, "data", "cache")
CACHE_HOURS = float(os.getenv("CACHE_HOURS", "6"))
ADDR_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")


def _topic(sig):
    from eth_utils import keccak
    return "0x" + keccak(text=sig).hex()


CHECK_PAID = _topic("CheckPaid(address,address,uint256,uint256,uint256)")

app = FastAPI(title="WifWheel")
jobs = {}                 # job id -> {"status", "address", "result", "error", "started"}
used_txs = set()          # payment transactions already redeemed
_lock = threading.Lock()
_hits = defaultdict(deque)


# ------------------------------------------------------------------ helpers
def _rate_ok(ip, limit=20, window=600):
    now = time.time()
    q = _hits[ip]
    while q and now - q[0] > window:
        q.popleft()
    if len(q) >= limit:
        return False
    q.append(now)
    return True


def _ip(request: Request):
    fwd = request.headers.get("x-forwarded-for", "")
    return fwd.split(",")[0].strip() or (request.client.host if request.client else "?")


def _cache_path(addr, deep):
    return os.path.join(CACHE_DIR, f"{addr.lower()}{'.deep' if deep else ''}.json")


def cache_get(addr, deep):
    p = _cache_path(addr, deep)
    try:
        if time.time() - os.path.getmtime(p) < CACHE_HOURS * 3600:
            with open(p, encoding="utf-8") as f:
                return json.load(f)
    except OSError:
        pass
    return None


def cache_put(addr, deep, result):
    os.makedirs(CACHE_DIR, exist_ok=True)
    with open(_cache_path(addr, deep), "w", encoding="utf-8") as f:
        json.dump(result, f, default=str)


def run_scan(addr, deep):
    result = scanner.to_dict(scanner.scan(addr, deep=deep))
    result["checked_at"] = int(time.time())
    result["deep"] = deep
    cache_put(addr, deep, result)
    return result


def pay_rpc(method, params):
    import requests
    r = requests.post(PAY_RPC, json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params}, timeout=30).json()
    return r.get("result")


def verify_payment(tx, token):
    """True if `tx` emitted CheckPaid(user, token, …) from the WifWheel contract."""
    if not WIFWHEEL:
        raise HTTPException(503, "Payments are not configured yet (WIFWHEEL_ADDRESS).")
    rcpt = pay_rpc("eth_getTransactionReceipt", [tx])
    if not rcpt:
        return False, "Transaction not found yet. Wait a few seconds and try again."
    if int(rcpt.get("status", "0x0"), 16) != 1:
        return False, "That transaction failed onchain."
    want = "0x" + "0" * 24 + token.lower()[2:]
    for lg in rcpt.get("logs", []):
        t = lg.get("topics") or []
        if (lg.get("address", "").lower() == WIFWHEEL.lower() and len(t) >= 3
                and t[0].lower() == CHECK_PAID and t[2].lower() == want):
            return True, ""
    return False, "That transaction did not pay for a check of this token."


def _deep_worker(job_id, addr):
    try:
        res = run_scan(addr, deep=True)
        jobs[job_id].update(status="done", result=res)
    except Exception as e:  # never leave a job hanging
        jobs[job_id].update(status="error", error=str(e)[:200])


# ------------------------------------------------------------------ routes
@app.get("/", include_in_schema=False)
def index():
    return FileResponse(os.path.join(HERE, "static", "index.html"))


@app.get("/api/config")
def config():
    return {"network": os.getenv("NETWORK", "testnet"), "chain_id": PAY["chain_id"], "chain_name": PAY["name"],
            "rpc": PAY["rpc"], "explorer": PAY["explorer"], "wifwheel": WIFWHEEL, "wif": WIF,
            "scan_explorer": scanner.EXPLORER, "mock_wif": os.getenv("NETWORK", "testnet") == "testnet"}


@app.post("/api/check")
async def check(request: Request):
    body = await request.json()
    addr = str(body.get("address", "")).strip()
    if not ADDR_RE.match(addr):
        raise HTTPException(400, "Paste a 0x… token address (42 characters).")
    deep_cached = cache_get(addr, True)
    if deep_cached:
        return deep_cached
    cached = cache_get(addr, False)
    if cached:
        return cached
    if not _rate_ok(_ip(request)):
        raise HTTPException(429, "Lots of checks from you. Please wait a few minutes.")
    return run_scan(addr, deep=False)


@app.post("/api/deep")
async def deep(request: Request):
    body = await request.json()
    addr = str(body.get("address", "")).strip()
    tx = str(body.get("tx", "")).strip()
    if not ADDR_RE.match(addr):
        raise HTTPException(400, "Invalid token address.")
    if not re.fullmatch(r"0x[0-9a-fA-F]{64}", tx):
        raise HTTPException(400, "Invalid transaction hash.")
    with _lock:
        if tx.lower() in used_txs:
            raise HTTPException(409, "This payment has already been used.")
    ok, why = verify_payment(tx, addr)
    if not ok:
        raise HTTPException(402, why)
    with _lock:
        if tx.lower() in used_txs:
            raise HTTPException(409, "This payment has already been used.")
        used_txs.add(tx.lower())
    job_id = uuid.uuid4().hex[:12]
    cached = cache_get(addr, True)
    if cached:
        jobs[job_id] = {"status": "done", "address": addr, "result": cached, "started": time.time()}
    else:
        jobs[job_id] = {"status": "running", "address": addr, "started": time.time()}
        threading.Thread(target=_deep_worker, args=(job_id, addr), daemon=True).start()
    return {"job": job_id}


@app.get("/api/job/{job_id}")
def job(job_id: str):
    j = jobs.get(job_id)
    if not j:
        raise HTTPException(404, "Unknown job.")
    out = {"status": j["status"], "elapsed": round(time.time() - j["started"], 1)}
    if j["status"] == "done":
        out["result"] = j["result"]
    if j["status"] == "error":
        out["error"] = j["error"]
    return out


REGISTER_ABI = [
    {"name": "recentReports", "type": "function", "stateMutability": "view",
     "inputs": [{"name": "limit", "type": "uint256"}],
     "outputs": [{"name": "out", "type": "tuple[]", "components": [
         {"name": "reporter", "type": "address"}, {"name": "token", "type": "address"},
         {"name": "stake", "type": "uint96"}, {"name": "status", "type": "uint8"},
         {"name": "createdAt", "type": "uint64"}, {"name": "evidence", "type": "string"}]},
         {"name": "ids", "type": "uint256[]"}]},
    {"name": "rewardPool", "type": "function", "stateMutability": "view", "inputs": [], "outputs": [{"type": "uint256"}]},
    {"name": "totalBurned", "type": "function", "stateMutability": "view", "inputs": [], "outputs": [{"type": "uint256"}]},
    {"name": "totalChecks", "type": "function", "stateMutability": "view", "inputs": [], "outputs": [{"type": "uint256"}]},
]
STATUS = {0: "none", 1: "open", 2: "confirmed", 3: "rejected"}


@app.get("/api/register")
def register():
    if not WIFWHEEL:
        return {"configured": False, "reports": [], "stats": {}}
    from web3 import Web3
    w3 = Web3(Web3.HTTPProvider(PAY_RPC))
    c = w3.eth.contract(address=Web3.to_checksum_address(WIFWHEEL), abi=REGISTER_ABI)
    reports, ids = c.functions.recentReports(50).call()
    rows = [{"id": i, "reporter": r[0], "token": r[1], "stake": str(r[2]), "status": STATUS.get(r[3], "?"),
             "created_at": r[4], "evidence": r[5]} for r, i in zip(reports, ids)]
    stats = {"reward_pool": str(c.functions.rewardPool().call()), "total_burned": str(c.functions.totalBurned().call()),
             "total_checks": c.functions.totalChecks().call()}
    return {"configured": True, "reports": rows, "stats": stats}
