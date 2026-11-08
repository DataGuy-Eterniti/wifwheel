"""Offline tests for scanner.py. A fake chain serves contract code and Transfer logs like the real RPC."""
import scanner

TOKEN = "0x" + "ab" * 20
OWNER = "0x" + "11" * 20
LAUNCHER = "0x" + "33" * 20
DISTRIB = "0x" + "22" * 20
COLLECTOR = "0x" + "77" * 20
POOL = "0x" + "44" * 20
ZERO = "0x" + "0" * 40


def w(i):
    return "0x" + f"{i:040x}"


def topic(a):
    return "0x" + "0" * 24 + a[2:]


def word(a):
    return "0x" + "0" * 24 + a[2:]


class FakeChain(scanner.Chain):
    """`rug=True`: owner powers, one wallet seeds 8 holders who later forward to one collector,
    14 wallets buy in the launch block, the launcher has deployed 6 contracts, thin liquidity."""

    def __init__(self, rug: bool):
        super().__init__()
        self.rug = rug
        self.created = set()
        if rug:
            self.created = {scanner._rlp_create_address(LAUNCHER, n) for n in range(6)}
        self.transfers = self._build()
        self.log_calls = 0

    def _build(self):
        t = [(ZERO, LAUNCHER, 1000, 100, "0xmint")]
        if self.rug:
            t.append((LAUNCHER, DISTRIB, 640, 101, "0xseed"))
            for i in range(1, 9):
                t.append((DISTRIB, w(i), 80, 102, f"0xd{i}"))           # common distributor
            for i in range(20, 34):
                t.append((LAUNCHER, w(i), 1, 101, "0xbatch"))           # 14 early buyers in one tx
            for i in range(1, 9):
                t.append((w(i), COLLECTOR, 5, 500, f"0xc{i}"))          # common collector
            t.append((LAUNCHER, POOL, 300, 103, "0xpool"))
        else:
            t.append((LAUNCHER, POOL, 1000, 5000, "0xpool"))
            for i in range(1, 30):
                t.append((POOL, w(100 + i), 15, 5000 + i * 900, f"0xb{i}"))
        return t

    def rpc(self, method, params, url=None):
        if method == "eth_getStorageAt":
            return word(ZERO)
        if method == "eth_getLogs":
            self.log_calls += 1
            q = params[0]
            a, b = int(q["fromBlock"], 16), int(q["toBlock"], 16)
            out = []
            for k, (f, to, v, blk, tx) in enumerate(self.transfers):
                if a <= blk <= b:
                    out.append({"topics": [scanner.TRANSFER, topic(f), topic(to)], "data": hex(v),
                                "blockNumber": hex(blk), "transactionHash": tx, "logIndex": hex(k)})
            return out
        if method == "eth_blockNumber":
            return hex(40000)
        if method == "eth_getTransactionByHash":
            return {"from": LAUNCHER}
        if method == "eth_getTransactionCount":
            return hex(10)
        if method == "eth_getCode":
            return self._code(params[0])
        return None

    def _code(self, a):
        if a == TOKEN:
            body = "6080" + "6340c10f19" + "638da5cb5b" + ("63f9f92be4" if self.rug else "") + "00"
            return "0x" + body
        if a == POOL or a in self.created:
            return "0x6080"
        return "0x"

    def code_many(self, addrs):
        return {a: self._code(a) for a in addrs}

    def call(self, to, data):
        if data == "0x8da5cb5b":
            return word(OWNER) if self.rug else "0x" + "0" * 64
        if data == "0x313ce567":
            return hex(18)
        if data == "0x18160ddd":
            return hex(1000)
        if data == "0x95d89b41":
            return "0x" + "20".rjust(64, "0") + "3".rjust(64, "0") + ("RUG" if self.rug else "OK!").encode().hex().ljust(64, "0")
        return "0x"

    def dex(self, token):
        return [{"chainId": "robinhood", "liquidity": {"usd": 1200 if self.rug else 90000}, "url": "https://dex/x"}]


def kinds(rep):
    return {f.key for f in rep.findings}


def test_rug_token_is_high_risk():
    rep = scanner.scan(TOKEN, chain=FakeChain(rug=True))
    assert rep.verdict == "HIGH RISK"
    assert {"owner_powers", "concentration", "cluster", "snipers", "serial_deployer", "thin_liquidity"} <= kinds(rep)
    assert rep.symbol == "RUG"
    assert rep.facts["launcher"] == LAUNCHER
    assert rep.facts["launcher_contracts_created"] == 6
    assert any(c["type"] in ("distributor", "collector") for c in rep.facts["clusters"])
    assert rep.findings[0].severity == "high"


def test_clean_token_has_no_major_flags():
    rep = scanner.scan(TOKEN, chain=FakeChain(rug=False))
    assert rep.verdict == "NO MAJOR RED FLAGS FOUND", [(f.key, f.severity) for f in rep.findings]
    assert "cluster" not in kinds(rep)
    assert rep.facts["holders"] >= 29


def test_quick_scan_skips_forensics():
    fc = FakeChain(rug=True)
    rep = scanner.scan(TOKEN, chain=fc, deep=False)
    assert fc.log_calls == 0
    assert "cluster" not in kinds(rep)
    assert any("deep check" in n for n in rep.not_checked)


def test_log_range_is_chunked_to_rpc_limit(monkeypatch):
    monkeypatch.setattr(scanner, "LOG_SPAN", 7000)
    fc = FakeChain(rug=False)
    scanner.scan(TOKEN, chain=fc)
    assert fc.log_calls == 6          # blocks 0..40000 in 7000-block chunks


def test_create_address_matches_known_vector():
    # well-known example: sender 0x6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0, nonce 0
    assert scanner._rlp_create_address("0x6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0", 0) == \
        "0xcd234a471b72ba2f1ccf0a70fcaba648a5eecd8d"


def test_bad_address():
    rep = scanner.scan("hello", chain=FakeChain(rug=False))
    assert rep.findings[0].key == "bad_address"
