"""WifWheel scanner: reads a Robinhood Chain token and reports rug-pull risk, with evidence.

Free data sources only:
  * Robinhood Chain JSON-RPC (contract code, ownership, proxy slots)
  * Blockscout (token info, holders, verification, creator, earliest transfers, first funders)
  * DexScreener (liquidity), no key needed

Usage:
    python scanner.py 0xTokenAddress
    python scanner.py 0xTokenAddress --json

The verdict is computed by rules from chain data. It never says "safe": the best it can say is that no
major red flags were found in what it could check, and it lists what it could not check.
"""
import argparse
import json
import os
import sys
import time
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field

import requests

NETWORKS = {
    "mainnet": {"chain_id": 4663, "rpc": "https://rpc.mainnet.chain.robinhood.com",
                "explorer": "https://robinhoodchain.blockscout.com"},
    "testnet": {"chain_id": 46630, "rpc": "https://rpc.testnet.chain.robinhood.com",
                "explorer": "https://explorer.testnet.chain.robinhood.com"},
}
NET = NETWORKS[os.getenv("SCAN_NETWORK", "mainnet")]
RPC_URL = os.getenv("RPC_URL") or NET["rpc"]
EXPLORER = os.getenv("EXPLORER_URL") or NET["explorer"]
DEXSCREENER = "https://api.dexscreener.com/latest/dex/tokens/"
TIMEOUT = 20

DEAD = {"0x0000000000000000000000000000000000000000", "0x000000000000000000000000000000000000dead"}
# EIP-1967 storage slots
IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
ADMIN_SLOT = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
# 4-byte selectors of privileged functions; finding them in bytecode means the power exists
POWERS = {
    "40c10f19": "mint(address,uint256)",
    "a0712d68": "mint(uint256)",
    "8456cb59": "pause()",
    "3f4ba83a": "unpause()",
    "f9f92be4": "blacklist(address)",
    "44337ea1": "addToBlacklist(address)",
    "e47d6060": "isBlacklisted(address)",
    "8da5cb5b": "owner()",
    "69fe0e2d": "setFee(uint256)",
    "c0246668": "excludeFromFees(address,bool)",
    "dd62ed3e": "allowance(address,address)",
}
DANGEROUS = {"40c10f19", "a0712d68", "8456cb59", "f9f92be4", "44337ea1", "69fe0e2d", "c0246668"}


@dataclass
class Finding:
    key: str
    severity: str          # "high" | "medium" | "low" | "info"
    title: str
    detail: str
    evidence: str = ""     # explorer link


@dataclass
class Report:
    address: str
    name: str = ""
    symbol: str = ""
    verdict: str = ""      # HIGH RISK | CAUTION | NO MAJOR RED FLAGS FOUND
    score: int = 0         # 0-100, higher = riskier
    findings: list = field(default_factory=list)
    not_checked: list = field(default_factory=list)
    facts: dict = field(default_factory=dict)
    explorer: str = ""
    seconds: float = 0.0


# ------------------------------------------------------------------ data access
class Chain:
    """Thin wrappers over RPC, Blockscout and DexScreener. Every call fails soft (returns None)."""

    def __init__(self, session=None):
        self.s = session or requests.Session()
        self.s.headers.update({"User-Agent": "wifwheel-scanner/0.1"})

    def rpc(self, method, params):
        try:
            r = self.s.post(RPC_URL, json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params}, timeout=TIMEOUT)
            return r.json().get("result")
        except Exception:
            return None

    def call(self, to, data):
        return self.rpc("eth_call", [{"to": to, "data": data}, "latest"])

    def bs(self, path, **params):
        """Blockscout REST v2."""
        try:
            r = self.s.get(f"{EXPLORER}/api/v2/{path}", params=params or None, timeout=TIMEOUT)
            return r.json() if r.status_code == 200 else None
        except Exception:
            return None

    def bs_legacy(self, **params):
        """Blockscout Etherscan-compatible API (sorted, paginated history)."""
        try:
            r = self.s.get(f"{EXPLORER}/api", params=params, timeout=TIMEOUT)
            j = r.json()
            return j.get("result") if isinstance(j.get("result"), list) else None
        except Exception:
            return None

    def dex(self, token):
        try:
            r = self.s.get(DEXSCREENER + token, timeout=TIMEOUT)
            return r.json().get("pairs") or []
        except Exception:
            return None


def _addr_from_word(word):
    if not word or len(word) < 42:
        return None
    a = "0x" + word[-40:]
    return None if int(a, 16) == 0 else a.lower()


def _link(kind, value):
    return f"{EXPLORER}/{kind}/{value}"


# ------------------------------------------------------------------ checks
def check_contract(c: Chain, addr, rep: Report):
    code = c.rpc("eth_getCode", [addr, "latest"])
    if not code or code == "0x":
        rep.findings.append(Finding("no_code", "high", "No contract at this address",
                                    "There is no token contract here. It may be a wallet or the wrong network.",
                                    _link("address", addr)))
        return False
    rep.facts["bytecode_bytes"] = (len(code) - 2) // 2

    owner = _addr_from_word(c.call(addr, "0x8da5cb5b"))
    impl = _addr_from_word(c.rpc("eth_getStorageAt", [addr, IMPL_SLOT, "latest"]))
    admin = _addr_from_word(c.rpc("eth_getStorageAt", [addr, ADMIN_SLOT, "latest"]))
    rep.facts.update(owner=owner, proxy_implementation=impl, proxy_admin=admin)

    body = code[2:].lower()
    powers = sorted({sel for sel in POWERS if ("63" + sel) in body})  # PUSH4 <selector>
    rep.facts["powers"] = [POWERS[p] for p in powers]
    danger = [POWERS[p] for p in powers if p in DANGEROUS]

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
                                    f"The code contains {', '.join(danger)}, but no standard owner was found. Who can call them is unclear.",
                                    _link("address", addr)))
    elif owner:
        rep.findings.append(Finding("owner_live", "low", "Ownership not renounced",
                                    "An owner address still controls the contract, though no high-risk functions were detected.",
                                    _link("address", owner)))

    info = c.bs(f"smart-contracts/{addr}")
    verified = bool(info and (info.get("is_verified") or info.get("source_code")))
    rep.facts["verified_source"] = verified
    if not verified:
        rep.findings.append(Finding("unverified", "medium", "Source code not verified",
                                    "Nobody can read what this contract really does.", _link("address", addr)))
    return True


def check_token(c: Chain, addr, rep: Report):
    t = c.bs(f"tokens/{addr}") or {}
    rep.name, rep.symbol = t.get("name") or "", t.get("symbol") or ""
    supply, dec = t.get("total_supply"), int(t.get("decimals") or 18)
    rep.facts.update(holders=t.get("holders") or t.get("holders_count"), total_supply=supply, decimals=dec)
    if not supply:
        rep.not_checked.append("Holder concentration (token supply unavailable)")
        return None

    holders = (c.bs(f"tokens/{addr}/holders") or {}).get("items") or []
    supply = int(supply)
    rows = []
    for h in holders[:50]:
        a = ((h.get("address") or {}).get("hash") or "").lower()
        is_contract = bool((h.get("address") or {}).get("is_contract"))
        rows.append({"address": a, "share": int(h.get("value") or 0) / supply, "is_contract": is_contract})
    rep.facts["top_holders"] = rows[:10]

    wallets = [r for r in rows if r["address"] not in DEAD and not r["is_contract"]]
    top10 = sum(r["share"] for r in wallets[:10])
    rep.facts["top10_wallet_share"] = round(top10, 4)
    if top10 >= 0.5:
        rep.findings.append(Finding("concentration", "high", "A few wallets hold most of the supply",
                                    f"The top 10 wallets (excluding pools and burn addresses) hold {top10:.0%}. They can crash the price by selling.",
                                    _link("token", addr) + "?tab=holders"))
    elif top10 >= 0.25:
        rep.findings.append(Finding("concentration", "medium", "Supply is concentrated",
                                    f"The top 10 wallets hold {top10:.0%} of the supply.", _link("token", addr) + "?tab=holders"))
    return wallets


def check_funders(c: Chain, addr, wallets, rep: Report, limit=25):
    """The serial-rug pattern: many 'independent' holders were funded by the same wallet."""
    if not wallets:
        return
    funders = {}
    for w in wallets[:limit]:
        txs = c.bs_legacy(module="account", action="txlist", address=w["address"], sort="asc", page=1, offset=1)
        if txs:
            first = txs[0]
            if (first.get("to") or "").lower() == w["address"] and int(first.get("value") or 0) > 0:
                funders[w["address"]] = (first.get("from") or "").lower()
        time.sleep(0.15)  # stay polite with the free API
    if not funders:
        rep.not_checked.append("Who funded the top holders (no history returned)")
        return
    groups = defaultdict(list)
    for holder, funder in funders.items():
        groups[funder].append(holder)
    share = {w["address"]: w["share"] for w in wallets}
    clusters = sorted(((f, hs) for f, hs in groups.items() if len(hs) >= 2),
                      key=lambda x: -sum(share[h] for h in x[1]))
    rep.facts["funder_clusters"] = [{"funder": f, "holders": len(hs), "share": round(sum(share[h] for h in hs), 4)}
                                    for f, hs in clusters[:5]]
    if clusters:
        f, hs = clusters[0]
        s = sum(share[h] for h in hs)
        sev = "high" if s >= 0.2 or len(hs) >= 5 else "medium"
        rep.findings.append(Finding("funder_cluster", sev, "Holders funded from the same wallet",
                                    f"{len(hs)} of the top holders were first funded by one address and together hold {s:.0%}. "
                                    "Rug groups use clusters like this to fake demand and dump together.",
                                    _link("address", f)))


def check_launch(c: Chain, addr, rep: Report):
    """Who bought in the first blocks after launch."""
    txs = c.bs_legacy(module="account", action="tokentx", contractaddress=addr, sort="asc", page=1, offset=150)
    if not txs:
        rep.not_checked.append("Launch-block buyers (no transfer history returned)")
        return
    blocks = sorted({int(t["blockNumber"]) for t in txs})
    launch = blocks[0]
    early = [t for t in txs if int(t["blockNumber"]) <= launch + 2 and (t.get("to") or "").lower() not in DEAD]
    buyers = Counter((t.get("to") or "").lower() for t in early)
    rep.facts.update(launch_block=launch, early_buyers=len(buyers))
    if len(buyers) >= 10:
        rep.findings.append(Finding("snipers", "medium", "Many wallets bought in the first blocks",
                                    f"{len(buyers)} wallets received tokens within 3 blocks of launch, a common sign of insiders or bots.",
                                    _link("block", launch)))


def check_deployer(c: Chain, addr, rep: Report):
    """Has the creator launched other tokens before?"""
    a = c.bs(f"addresses/{addr}") or {}
    creator = (a.get("creator_address_hash") or "").lower()
    rep.facts["creator"] = creator or None
    if not creator:
        rep.not_checked.append("Deployer history (creator unknown)")
        return
    txs = c.bs_legacy(module="account", action="txlist", address=creator, sort="desc", page=1, offset=200) or []
    created = {(t.get("contractAddress") or "").lower() for t in txs if t.get("contractAddress")}
    created.discard(addr.lower())
    rep.facts["creator_other_contracts"] = len(created)
    if len(created) >= 3:
        rep.findings.append(Finding("serial_deployer", "high", "Creator has launched many contracts",
                                    f"The wallet that created this token has deployed {len(created)} other contracts. "
                                    "Serial launchers are behind most rug pulls on new chains.",
                                    _link("address", creator)))
    elif created:
        rep.findings.append(Finding("repeat_deployer", "low", "Creator has deployed before",
                                    f"The creator has {len(created)} other contract(s). Check how those ended.", _link("address", creator)))


def check_market(c: Chain, addr, rep: Report):
    pairs = c.dex(addr)
    if pairs is None:
        rep.not_checked.append("Liquidity (DexScreener unavailable)")
        return
    pairs = [p for p in pairs if "robinhood" in (p.get("chainId") or "").lower()] or pairs
    liq = sum(float((p.get("liquidity") or {}).get("usd") or 0) for p in pairs)
    rep.facts["liquidity_usd"] = round(liq, 2)
    rep.facts["pairs"] = len(pairs)
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
    s = sum(WEIGHTS[f.severity] for f in rep.findings)
    rep.score = min(100, s)
    highs = sum(1 for f in rep.findings if f.severity == "high")
    if highs >= 2 or rep.score >= 60:
        rep.verdict = "HIGH RISK"
    elif highs == 1 or rep.score >= 20:
        rep.verdict = "CAUTION"
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
        wallets = check_token(c, addr, rep)
        check_market(c, addr, rep)
        if deep:  # the paid deep check: forensics that take more API calls
            check_funders(c, addr, wallets, rep)
            check_launch(c, addr, rep)
            check_deployer(c, addr, rep)
        else:
            rep.not_checked.append("Launch forensics (holder funders, first-block buyers, deployer history): run a deep check")
    score(rep)
    rep.seconds = round(time.time() - started, 2)
    return rep


def to_dict(rep: Report) -> dict:
    d = asdict(rep)
    return d


def main():
    ap = argparse.ArgumentParser(description="WifWheel rug-risk scanner for Robinhood Chain")
    ap.add_argument("address")
    ap.add_argument("--quick", action="store_true", help="skip launch forensics")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    rep = scan(a.address, deep=not a.quick)
    if a.json:
        print(json.dumps(to_dict(rep), indent=2))
        return
    print(f"\n{rep.name or 'Unknown token'} ({rep.symbol or '?'})  {rep.address}")
    print(f"VERDICT: {rep.verdict}   risk score {rep.score}/100   ({rep.seconds}s)\n")
    for f in rep.findings:
        print(f"[{f.severity.upper():6}] {f.title}\n         {f.detail}\n         {f.evidence}")
    if rep.not_checked:
        print("\nNot checked: " + "; ".join(rep.not_checked))
    print(f"\n{rep.explorer}")


if __name__ == "__main__":
    sys.exit(main())
