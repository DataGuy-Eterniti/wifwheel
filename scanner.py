"""WifWheel scanner: reads a Robinhood Chain token straight from the chain and reports rug-pull risk, with evidence.

Free data only:
  * Robinhood Chain JSON-RPC: contract code, owner, proxy slots, and the token's full Transfer history
    (eth_getLogs in 10M-block chunks, the public RPC's limit)
  * DexScreener: liquidity (no key)
  * Optional: ALCHEMY_KEY in .env (free tier) adds "who first funded each top holder" via alchemy_getAssetTransfers

Usage:
    python scanner.py 0xTokenAddress            # deep check
    python scanner.py 0xTokenAddress --quick    # contract + market only (free tier in the app)
    python scanner.py 0xTokenAddress --json

The verdict never says "safe". The best it can say is that no major red flags were found in what it could check,
and it lists what it could not check.
"""
import argparse
import json
import os
import sys
import time
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field

import requests

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

NETWORKS = {
    "mainnet": {"chain_id": 4663, "rpc": "https://rpc.mainnet.chain.robinhood.com",
                "explorer": "https://robinhoodchain.blockscout.com", "alchemy": "robinhood-mainnet"},
    "testnet": {"chain_id": 46630, "rpc": "https://rpc.testnet.chain.robinhood.com",
                "explorer": "https://explorer.testnet.chain.robinhood.com", "alchemy": "robinhood-testnet"},
}
NET = NETWORKS[os.getenv("SCAN_NETWORK", "mainnet")]
RPC_URL = os.getenv("SCAN_RPC_URL") or NET["rpc"]
EXPLORER = os.getenv("EXPLORER_URL") or NET["explorer"]
ALCHEMY_KEY = os.getenv("ALCHEMY_KEY", "").strip()
DEXSCREENER = "https://api.dexscreener.com/latest/dex/tokens/"
TIMEOUT = 40
LOG_SPAN = int(os.getenv("LOG_SPAN", "10000000"))   # public RPC limit per eth_getLogs
EARLY_BLOCKS = 50
RETRIES = int(os.getenv("RPC_RETRIES", "8"))                                    # ~5 seconds after the first transfer at 0.1 s blocks

TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
ZERO = "0x" + "0" * 40
DEAD = {ZERO, "0x000000000000000000000000000000000000dead"}
IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
ADMIN_SLOT = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
POWERS = {
    "40c10f19": "mint(address,uint256)", "a0712d68": "mint(uint256)", "8456cb59": "pause()",
    "f9f92be4": "blacklist(address)", "44337ea1": "addToBlacklist(address)", "69fe0e2d": "setFee(uint256)",
    "c0246668": "excludeFromFees(address,bool)", "8da5cb5b": "owner()",
}
DANGEROUS = {"40c10f19", "a0712d68", "8456cb59", "f9f92be4", "44337ea1", "69fe0e2d", "c0246668"}


@dataclass
class Finding:
    key: str
    severity: str          # high | medium | low | info
    title: str
    detail: str
    evidence: str = ""


@dataclass
class Report:
    address: str
    name: str = ""
    symbol: str = ""
    verdict: str = ""
    score: int = 0
    findings: list = field(default_factory=list)
    not_checked: list = field(default_factory=list)
    facts: dict = field(default_factory=dict)
    explorer: str = ""
    seconds: float = 0.0


def _link(kind, value):
    return f"{EXPLORER}/{kind}/{value}"


def _addr(word):
    if not word or len(word) < 42:
        return None
    a = "0x" + word[-40:].lower()
    return None if a == ZERO else a


def _decode_string(hexdata):
    if not hexdata or hexdata == "0x":
        return ""
    b = bytes.fromhex(hexdata[2:])
    try:
        if len(b) >= 64:
            off = int.from_bytes(b[:32], "big")
            ln = int.from_bytes(b[off:off + 32], "big")
            return b[off + 32:off + 32 + ln].decode("utf-8", "replace")
        return b.rstrip(b"\0").decode("utf-8", "replace")
    except Exception:
        return ""


# ------------------------------------------------------------------ chain access
class Chain:
    """RPC + DexScreener (+ optional Alchemy). Every method fails soft and returns None."""

    def __init__(self, session=None):
        self.s = session or requests.Session()
        self.s.headers.update({"User-Agent": "wifwheel-scanner/0.2"})

    def rpc(self, method, params, url=None):
        try:
            r = self.s.post(url or RPC_URL, json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
                            timeout=TIMEOUT).json()
            return r.get("result") if "error" not in r else {"__error__": r["error"]}
        except Exception as e:
            return {"__error__": str(e)}

    def ok(self, method, params):
        r = self.rpc(method, params)
        return None if isinstance(r, dict) and "__error__" in r else r

    def call(self, to, data):
        return self.ok("eth_call", [{"to": to, "data": data}, "latest"])

    def code(self, addr):
        return self.ok("eth_getCode", [addr, "latest"])

    def code_many(self, addrs):
        """eth_getCode for many addresses in one JSON-RPC batch; falls back to one-by-one (capped)."""
        if not addrs:
            return {}
        try:
            body = [{"jsonrpc": "2.0", "id": i, "method": "eth_getCode", "params": [a, "latest"]} for i, a in enumerate(addrs)]
            r = self.s.post(RPC_URL, json=body, timeout=TIMEOUT).json()
            if isinstance(r, list):
                by_id = {x.get("id"): x.get("result") for x in r}
                return {a: by_id.get(i) for i, a in enumerate(addrs)}
        except Exception:
            pass
        return {a: self.code(a) for a in addrs[:30]}

    def block_number(self):
        r = self.ok("eth_blockNumber", [])
        return int(r, 16) if r else None

    def tx(self, h):
        return self.ok("eth_getTransactionByHash", [h])

    def logs(self, token, frm, to):
        """All Transfer logs of `token` in [frm, to].
        Range/size errors -> split the range. Rate limits or network errors -> wait and retry.
        Returns (logs, None) or (None, error_message)."""
        out, stack = [], [(frm, to)]
        while stack:
            a, b = stack.pop()
            q = [{"address": token, "topics": [TRANSFER], "fromBlock": hex(a), "toBlock": hex(b)}]
            for attempt in range(RETRIES):
                r = self.rpc("eth_getLogs", q)
                if isinstance(r, list):
                    out.extend(r)
                    break
                msg = str((r or {}).get("__error__", r)).lower()
                too_big = any(k in msg for k in ("range", "spans", "too many results", "more than", "exceed", "limit", "narrow"))
                rate = any(k in msg for k in ("rate", "429", "too many requests", "timeout", "timed out", "connection", "busy"))
                if too_big and not rate and b > a:
                    mid = (a + b) // 2
                    stack += [(mid + 1, b), (a, mid)]
                    break
                time.sleep(min(20, 1.5 * 2 ** attempt) if rate else 1.5 * (attempt + 1))
            else:
                return None, msg[:200]
            time.sleep(0.25)   # be gentle with the free public RPC
        return out, None

    def dex(self, token):
        try:
            return self.s.get(DEXSCREENER + token, timeout=TIMEOUT).json().get("pairs") or []
        except Exception:
            return None

    def first_funder(self, wallet):
        """Who sent this wallet its first ETH (Alchemy free tier). None if unavailable."""
        if not ALCHEMY_KEY:
            return None
        url = f"https://{NET['alchemy']}.g.alchemy.com/v2/{ALCHEMY_KEY}"
        r = self.rpc("alchemy_getAssetTransfers", [{"toAddress": wallet, "category": ["external"], "order": "asc",
                                                    "maxCount": "0x1", "fromBlock": "0x0"}], url=url)
        try:
            return (r["transfers"][0]["from"] or "").lower()
        except Exception:
            return None


# ------------------------------------------------------------------ checks
def check_contract(c: Chain, addr, rep: Report):
    code = c.code(addr)
    if code is None:
        rep.not_checked.append("Contract code (RPC unavailable)")
        return False
    if code == "0x":
        rep.findings.append(Finding("no_code", "high", "No contract at this address",
                                    "There is no token contract here. It may be a wallet or the wrong network.",
                                    _link("address", addr)))
        return False
    rep.name = _decode_string(c.call(addr, "0x06fdde03"))
    rep.symbol = _decode_string(c.call(addr, "0x95d89b41"))
    dec = c.call(addr, "0x313ce567")
    sup = c.call(addr, "0x18160ddd")
    rep.facts["decimals"] = int(dec, 16) if dec and dec != "0x" else 18
    rep.facts["total_supply"] = int(sup, 16) if sup and sup != "0x" else None

    owner = _addr(c.call(addr, "0x8da5cb5b"))
    impl = _addr(c.ok("eth_getStorageAt", [addr, IMPL_SLOT, "latest"]))
    admin = _addr(c.ok("eth_getStorageAt", [addr, ADMIN_SLOT, "latest"]))
    rep.facts.update(owner=owner, proxy_implementation=impl, proxy_admin=admin)

    body = code[2:].lower()
    found = sorted({sel for sel in POWERS if ("63" + sel) in body})
    rep.facts["powers"] = [POWERS[s] for s in found]
    danger = [POWERS[s] for s in found if s in DANGEROUS]

    if impl:
        rep.findings.append(Finding("proxy", "high" if admin else "medium", "Upgradeable contract",
                                    "The code behind this token can be swapped later, so today's checks may not hold tomorrow.",
                                    _link("address", impl)))
    if danger and owner:
        rep.findings.append(Finding("owner_powers", "high", "Owner keeps special powers",
                                    f"A live owner can call: {', '.join(danger)}. These can mint new supply, freeze trading or block sellers.",
                                    _link("address", owner)))
    elif danger:
        rep.findings.append(Finding("powers_no_owner", "low", "Special functions exist",
                                    f"The code contains {', '.join(danger)}, but no standard owner was found, so who can call them is unclear.",
                                    _link("address", addr)))
    elif owner:
        rep.findings.append(Finding("owner_live", "low", "Ownership not renounced",
                                    "An owner address still controls the contract, though no high-risk functions were detected.",
                                    _link("address", owner)))
    rep.not_checked.append("Source-code verification (the explorer blocks automated access)")
    return True


def load_transfers(c: Chain, addr, rep: Report):
    latest = c.block_number()
    if latest is None:
        rep.not_checked.append("Transfer history (RPC unavailable)")
        return None
    logs = []
    start = 0
    while start <= latest:
        end = min(latest, start + LOG_SPAN - 1)
        chunk, err = c.logs(addr, start, end)
        if chunk is None:
            rep.not_checked.append(f"Transfer history (RPC error at blocks {start}-{end}: {err})")
            rep.facts["incomplete"] = True
            return None
        logs.extend(chunk)
        start = end + 1
    rows = []
    for lg in logs:
        t = lg.get("topics") or []
        if len(t) < 3:
            continue
        rows.append({"from": "0x" + t[1][-40:].lower(), "to": "0x" + t[2][-40:].lower(),
                     "value": int(lg.get("data") or "0x0", 16), "block": int(lg["blockNumber"], 16),
                     "tx": lg.get("transactionHash"), "i": int(lg.get("logIndex") or "0x0", 16)})
    rows.sort(key=lambda r: (r["block"], r["i"]))
    rep.facts["transfers"] = len(rows)
    return rows


def _contract_set(c: Chain, addrs):
    return {a for a, code in c.code_many(list(addrs)).items() if code and code != "0x"}


def analyse_holders(c: Chain, addr, rows, rep: Report):
    bal = defaultdict(int)
    for r in rows:
        if r["from"] != ZERO:
            bal[r["from"]] -= r["value"]
        bal[r["to"]] += r["value"]
    holders = {a: v for a, v in bal.items() if v > 0 and a not in DEAD}
    supply = rep.facts.get("total_supply") or sum(holders.values())
    rep.facts["holders"] = len(holders)
    if not supply:
        return [], set()
    top = sorted(holders.items(), key=lambda kv: -kv[1])[:40]
    contracts = _contract_set(c, [a for a, _ in top] + [addr])
    wallets = [{"address": a, "share": v / supply} for a, v in top if a not in contracts]
    rep.facts["top_holders"] = [{"address": a, "share": round(v / supply, 4), "contract": a in contracts} for a, v in top[:10]]
    top10 = sum(w["share"] for w in wallets[:10])
    rep.facts["top10_wallet_share"] = round(top10, 4)
    if top10 >= 0.5:
        rep.findings.append(Finding("concentration", "high", "A few wallets hold most of the supply",
                                    f"The top 10 wallets (excluding pools and contracts) hold {top10:.0%}. They can crash the price by selling.",
                                    _link("token", addr)))
    elif top10 >= 0.25:
        rep.findings.append(Finding("concentration", "medium", "Supply is concentrated",
                                    f"The top 10 wallets hold {top10:.0%} of the supply.", _link("token", addr)))
    return wallets, contracts


def analyse_launch(c: Chain, addr, rows, contracts, rep: Report):
    if not rows:
        return None
    launch = rows[0]["block"]
    rep.facts["launch_block"] = launch
    # who launched it: the sender of the first mint transaction (works through launchpads too)
    first_mint = next((r for r in rows if r["from"] == ZERO), rows[0])
    t = c.tx(first_mint["tx"]) if first_mint.get("tx") else None
    launcher = (t or {}).get("from", "").lower() or None
    rep.facts["launcher"] = launcher
    early = [r for r in rows if r["block"] <= launch + EARLY_BLOCKS and r["to"] not in DEAD
             and r["to"] not in contracts and r["to"] != launcher]
    buyers = {r["to"] for r in early}
    rep.facts["early_buyers"] = len(buyers)
    if len(buyers) >= 10:
        rep.findings.append(Finding("snipers", "medium", "Many wallets bought in the first seconds",
                                    f"{len(buyers)} wallets received tokens within about 5 seconds of launch, a common sign of insiders or bots.",
                                    _link("block", launch)))
    return launcher


def analyse_clusters(c: Chain, rows, wallets, contracts, launcher, rep: Report):
    """Link 'independent' top holders through shared token flows: batch funding, a common distributor,
    or a common collector. This is the pattern behind serial rug groups."""
    if not wallets:
        return
    share = {w["address"]: w["share"] for w in wallets}
    first_in, tx_recipients, out_to = {}, defaultdict(set), defaultdict(Counter)
    for r in rows:
        tx_recipients[r["tx"]].add(r["to"])
        if r["to"] in share and r["to"] not in first_in:
            first_in[r["to"]] = r
        if r["from"] in share and r["to"] not in contracts and r["to"] not in DEAD:
            out_to[r["from"]][r["to"]] += r["value"]

    groups = []
    # 1) bundled: first received in a transaction that sent tokens to 5+ wallets at once
    bundled = [h for h, r in first_in.items() if len(tx_recipients[r["tx"]]) >= 5]
    if len(bundled) >= 3:
        groups.append(("bundled", bundled, None))
    # 2) common distributor: first received from the same non-contract wallet
    by_src = defaultdict(list)
    for h, r in first_in.items():
        if r["from"] not in contracts and r["from"] != ZERO:
            by_src[r["from"]].append(h)
    for src, hs in by_src.items():
        if len(hs) >= 3:
            groups.append(("distributor", hs, src))
    # 3) common collector: their biggest outgoing transfers go to the same wallet
    by_dst = defaultdict(list)
    for h, cnt in out_to.items():
        if cnt:
            by_dst[cnt.most_common(1)[0][0]].append(h)
    for dst, hs in by_dst.items():
        if len(hs) >= 3:
            groups.append(("collector", hs, dst))
    # 4) optional: same first ETH funder (Alchemy free tier)
    if ALCHEMY_KEY:
        by_funder = defaultdict(list)
        for w in wallets[:25]:
            f = c.first_funder(w["address"])
            if f:
                by_funder[f].append(w["address"])
        for f, hs in by_funder.items():
            if len(hs) >= 3:
                groups.append(("funder", hs, f))
    else:
        rep.not_checked.append("Who first funded each top holder with ETH (add a free ALCHEMY_KEY to enable)")

    if not groups:
        return
    groups.sort(key=lambda g: -sum(share[h] for h in g[1]))
    rep.facts["clusters"] = [{"type": k, "wallets": len(hs), "share": round(sum(share[h] for h in hs), 4), "via": v}
                             for k, hs, v in groups[:5]]
    kind, hs, via = groups[0]
    s = sum(share[h] for h in hs)
    words = {"bundled": "received their first tokens in the same batch transaction",
             "distributor": "were first supplied by the same wallet",
             "collector": "send their tokens on to the same wallet",
             "funder": "were first funded with ETH by the same wallet"}[kind]
    sev = "high" if s >= 0.2 or len(hs) >= 5 else "medium"
    tag = " (the launcher)" if via and via == launcher else ""
    rep.findings.append(Finding("cluster", sev, "Top holders look linked",
                                f"{len(hs)} of the top holders {words}{tag}, together holding {s:.0%}. "
                                "Rug groups use linked wallets to fake demand and dump together.",
                                _link("address", via) if via else ""))


def analyse_launcher(c: Chain, launcher, rep: Report):
    if not launcher:
        rep.not_checked.append("Launcher history (launcher unknown)")
        return
    n = c.ok("eth_getTransactionCount", [launcher, "latest"])
    n = int(n, 16) if n else 0
    rep.facts["launcher_tx_count"] = n
    created = count_created_contracts(c, launcher, min(n, 120))
    rep.facts["launcher_contracts_created"] = created
    if created is not None and created >= 3:
        rep.findings.append(Finding("serial_deployer", "high", "Launcher has deployed many contracts",
                                    f"The wallet that launched this token has directly deployed {created} contracts. "
                                    "Serial launchers are behind most rug pulls on new chains.",
                                    _link("address", launcher)))
    rep.not_checked.append("Tokens the launcher created through launchpads (only direct deployments are counted)")


def _rlp_create_address(sender, nonce):
    from eth_utils import keccak
    s = bytes.fromhex(sender[2:])
    if nonce == 0:
        n = b"\x80"
    elif nonce < 0x80:
        n = bytes([nonce])
    else:
        nb = nonce.to_bytes((nonce.bit_length() + 7) // 8, "big")
        n = bytes([0x80 + len(nb)]) + nb
    payload = b"\x94" + s + n
    return "0x" + keccak(bytes([0xc0 + len(payload)]) + payload)[-20:].hex()


def count_created_contracts(c: Chain, sender, max_nonce):
    """Contracts deployed directly by `sender`: their addresses are fixed by (sender, nonce)."""
    try:
        addrs = [_rlp_create_address(sender, i) for i in range(max_nonce)]
    except Exception:
        return None
    codes = c.code_many(addrs)
    return sum(1 for a in addrs if (codes.get(a) or "0x") != "0x")


def check_market(c: Chain, addr, rep: Report):
    pairs = c.dex(addr)
    if pairs is None:
        rep.not_checked.append("Liquidity (DexScreener unavailable)")
        return
    pairs = [p for p in pairs if "robinhood" in (p.get("chainId") or "").lower()]
    liq = sum(float((p.get("liquidity") or {}).get("usd") or 0) for p in pairs)
    rep.facts.update(liquidity_usd=round(liq, 2), pairs=len(pairs))
    if pairs:
        rep.facts["price_usd"] = pairs[0].get("priceUsd")
        rep.facts["pair_url"] = pairs[0].get("url")
    if not pairs:
        rep.findings.append(Finding("no_pool", "medium", "No trading pool found",
                                    "There is no visible market for this token, so you may not be able to sell it.", ""))
    elif liq < 5_000:
        rep.findings.append(Finding("thin_liquidity", "medium", "Very little liquidity",
                                    f"Only about ${liq:,.0f} is in its pools. A small sell can move the price a lot.",
                                    pairs[0].get("url", "")))


# ------------------------------------------------------------------ scoring
WEIGHTS = {"high": 30, "medium": 12, "low": 4, "info": 0}


def score(rep: Report):
    rep.score = min(100, sum(WEIGHTS[f.severity] for f in rep.findings))
    highs = sum(1 for f in rep.findings if f.severity == "high")
    if highs >= 2 or rep.score >= 60:
        rep.verdict = "HIGH RISK"
    elif highs == 1 or rep.score >= 20:
        rep.verdict = "CAUTION"
    elif rep.facts.get("incomplete"):
        rep.verdict = "INCOMPLETE CHECK"
    else:
        rep.verdict = "NO MAJOR RED FLAGS FOUND"
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    rep.findings.sort(key=lambda f: order[f.severity])


def scan(address: str, chain: Chain = None, deep: bool = True) -> Report:
    started = time.time()
    c = chain or Chain()
    addr = address.strip().lower()
    rep = Report(address=addr, explorer=_link("token", addr))
    if not (addr.startswith("0x") and len(addr) == 42):
        rep.findings.append(Finding("bad_address", "high", "Not a valid address", "Paste a 0x… token address.", ""))
        score(rep)
        return rep
    if check_contract(c, addr, rep):
        check_market(c, addr, rep)
        if deep:
            rows = load_transfers(c, addr, rep)
            if rows is not None:
                wallets, contracts = analyse_holders(c, addr, rows, rep)
                launcher = analyse_launch(c, addr, rows, contracts, rep)
                analyse_clusters(c, rows, wallets, contracts, launcher, rep)
                analyse_launcher(c, launcher, rep)
        else:
            rep.not_checked.append("Holders, linked wallets, launch snipers and launcher history: run a deep check")
    score(rep)
    rep.seconds = round(time.time() - started, 2)
    return rep


def to_dict(rep: Report) -> dict:
    return asdict(rep)


def main():
    ap = argparse.ArgumentParser(description="WifWheel rug-risk scanner for Robinhood Chain")
    ap.add_argument("address")
    ap.add_argument("--quick", action="store_true", help="contract + market only")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    rep = scan(a.address, deep=not a.quick)
    if a.json:
        print(json.dumps(to_dict(rep), indent=2, default=str))
        return
    f = rep.facts
    print(f"\n{rep.name or 'Unknown token'} ({rep.symbol or '?'})  {rep.address}")
    print(f"VERDICT: {rep.verdict}   risk score {rep.score}/100   ({rep.seconds}s)")
    print(f"holders {f.get('holders', '?')} · transfers {f.get('transfers', '?')} · liquidity ${f.get('liquidity_usd', '?')} · "
          f"top-10 wallets {f.get('top10_wallet_share', '?')} · launcher {f.get('launcher', '?')}\n")
    for x in rep.findings:
        print(f"[{x.severity.upper():6}] {x.title}\n         {x.detail}\n         {x.evidence}")
    if rep.not_checked:
        print("\nNot checked: " + "; ".join(rep.not_checked))
    print(f"\n{rep.explorer}")


if __name__ == "__main__":
    sys.exit(main())
