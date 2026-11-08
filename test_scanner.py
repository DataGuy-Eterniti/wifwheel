"""Offline tests for scanner.py: a fake chain stands in for RPC, Blockscout and DexScreener."""
import scanner

TOKEN = "0x" + "ab" * 20
OWNER = "0x" + "11" * 20
FUNDER = "0x" + "22" * 20
CREATOR = "0x" + "33" * 20
POOL = "0x" + "44" * 20


def word(addr):
    return "0x" + "0" * 24 + addr[2:]


class FakeChain(scanner.Chain):
    def __init__(self, rug: bool):
        self.rug = rug
        super().__init__()

    def rpc(self, method, params):
        if method == "eth_getCode":
            body = "6080" + "63" + "40c10f19" + "63" + "8da5cb5b" + ("63f9f92be4" if self.rug else "") + "00"
            return "0x" + body
        if method == "eth_getStorageAt":
            return word("0x" + "00" * 20)
        return None

    def call(self, to, data):
        return word(OWNER) if (self.rug and data == "0x8da5cb5b") else "0x" + "0" * 64

    def bs(self, path, **params):
        if path.startswith("smart-contracts/"):
            return {"is_verified": not self.rug}
        if path.endswith("/holders"):
            items = [{"address": {"hash": POOL, "is_contract": True}, "value": str(300)}]
            n, each = (8, 80) if self.rug else (8, 10)
            for i in range(n):
                items.append({"address": {"hash": "0x" + f"{i + 1:02x}" * 20, "is_contract": False}, "value": str(each)})
            return {"items": items}
        if path.startswith("tokens/"):
            return {"name": "Rugcoin" if self.rug else "Goodcoin", "symbol": "RUG" if self.rug else "GOOD",
                    "total_supply": "1000", "decimals": "18", "holders": 120}
        if path.startswith("addresses/"):
            return {"creator_address_hash": CREATOR}
        return None

    def bs_legacy(self, **p):
        if p["action"] == "txlist" and p["address"] == CREATOR:
            n = 6 if self.rug else 0
            return [{"contractAddress": "0x" + f"{i + 0x50:02x}" * 20} for i in range(n)]
        if p["action"] == "txlist":
            src = FUNDER if self.rug else "0x" + p["address"][2:4] * 20
            return [{"from": src, "to": p["address"], "value": "1000"}]
        if p["action"] == "tokentx":
            n = 14 if self.rug else 3
            return [{"blockNumber": "100", "to": "0x" + f"{i + 0x60:02x}" * 20} for i in range(n)]
        return None

    def dex(self, token):
        return [{"chainId": "robinhood", "liquidity": {"usd": 1200 if self.rug else 90000}, "url": "https://dex/x"}]


def test_rug_token_is_high_risk():
    scanner.time.sleep = lambda *_: None
    rep = scanner.scan(TOKEN, chain=FakeChain(rug=True))
    keys = {f.key for f in rep.findings}
    assert rep.verdict == "HIGH RISK"
    assert {"owner_powers", "unverified", "concentration", "funder_cluster", "snipers", "serial_deployer", "thin_liquidity"} <= keys
    assert rep.facts["funder_clusters"][0]["funder"] == FUNDER
    assert rep.findings[0].severity == "high"


def test_clean_token_has_no_major_flags():
    scanner.time.sleep = lambda *_: None
    rep = scanner.scan(TOKEN, chain=FakeChain(rug=False))
    assert rep.verdict == "NO MAJOR RED FLAGS FOUND", [(f.key, f.severity) for f in rep.findings]
    assert "funder_cluster" not in {f.key for f in rep.findings}


def test_quick_scan_skips_forensics():
    rep = scanner.scan(TOKEN, chain=FakeChain(rug=True), deep=False)
    assert "funder_cluster" not in {f.key for f in rep.findings}
    assert any("deep check" in n for n in rep.not_checked)


def test_bad_address():
    rep = scanner.scan("hello", chain=FakeChain(rug=False))
    assert rep.verdict == "HIGH RISK" or rep.findings[0].key == "bad_address"
