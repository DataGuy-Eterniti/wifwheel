# WifWheel

**A $WIF-powered rug-pull checker and scam register for Robinhood Chain.**

Paste a token address and WifWheel reads the chain to tell you whether it looks like a rug, with evidence you can click. Pay a little $WIF for a deep check, report scams by staking $WIF, and earn $WIF when your report is confirmed. Every check feeds a public scam register.

> **Demo status:** payments run on **Robinhood Chain testnet with a mock $WIF token**, so anyone can try the full flow for free. Token checks read **real mainnet data**. Moving payments to mainnet $WIF is a one-line config change (`WIF_ADDRESS`, `NETWORK=mainnet`).

Built for the [World is Flat hackathon](https://worldisflat.fun/build). Not affiliated with Robinhood Markets, Inc.

---

## Why

Rug pulls are hitting this chain hard. In September 2026 an onchain analyst linked **53 tokens on Robinhood Chain to one group that extracted at least $18.4M**. The pattern was the same each time: clusters of 70 to 200 wallets funded from shared sources bought most of the supply, insiders were exempted from launch taxes, then everything was dumped. ([ForkLog](https://forklog.com/en/news/researcher-uncovers-18-million-rug-pull-scheme-in-robinhood-chain))

That pattern is visible onchain. WifWheel looks for it before you buy.

## What it checks

| Check | What it catches |
|---|---|
| **Contract powers** | A live owner who can mint, pause, blacklist or change fees; upgradeable proxies; unverified source |
| **Holder concentration** | The top 10 wallets (excluding pools and burn addresses) holding most of the supply |
| **Funder clusters** | Many "independent" top holders first funded by the **same wallet**, the serial-rug signature |
| **Launch snipers** | Lots of wallets buying in the first blocks after launch |
| **Deployer history** | A creator who has launched many contracts before |
| **Liquidity** | Thin or missing trading pools |

Every finding links to the block explorer. The verdict is **HIGH RISK**, **CAUTION** or **NO MAJOR RED FLAGS FOUND**. WifWheel never says "safe", and it lists what it could not check.

## The $WIF flywheel

```
  pay $WIF for a deep check ──► 50% burned, 50% to the reward pool
              ▲                                   │
              │                                   ▼
  better register brings more checks ◄── confirmed scam reports are paid from the pool
              ▲                                   │
              └──────── reporters stake $WIF to report scams ◄──┘
```

- **Quick checks are free.** Deep checks (funder clusters, launch snipers, deployer history) cost a small $WIF fee.
- **Report a scam** by staking $WIF with a link to evidence.
  - **Confirmed:** you get your stake back plus a reward from the pool, and the token is flagged in the public register.
  - **Rejected:** your stake is split between a burn and the pool, so spam costs money.
- **v1 has a single curator** who confirms reports. That is stated plainly here; a community or objective resolution is on the roadmap.

## Contract

`contracts/WifWheel.sol` · MIT · no external dependencies.

| Function | What it does |
|---|---|
| `payForCheck(token)` | Pay the check fee in $WIF; part burned, part to the pool |
| `submitReport(token, evidence)` | Stake $WIF to report a scam |
| `resolveReport(id, confirmed)` | Curator confirms (stake + reward, token flagged) or rejects (stake slashed) |
| `fundPool(amount)` | Anyone can top up rewards |
| `flagged(token)`, `recentReports(n)` | Public scam register |

Rewards only ever come from the pool, never from other users' open stakes. Reentrancy guarded. 9 tests.

## Run it

```bash
npm install && npm run compile            # build the contract
pip install -r requirements.txt
python scanner.py 0xTokenAddress          # check any Robinhood Chain token
python scanner.py 0xTokenAddress --quick  # free checks only
```

Deploy to testnet with a mock $WIF (free):

```bash
cp .env.example .env    # add a NEW wallet's key with testnet ETH
python contracts/deploy.py
```

Tests (Linux/macOS, or CI): `npm test` and `python -m pytest test_scanner.py`.

## Network

| | Testnet (payments in this demo) | Mainnet (token data) |
|---|---|---|
| Chain ID | 46630 | 4663 |
| RPC | `https://rpc.testnet.chain.robinhood.com` | `https://rpc.mainnet.chain.robinhood.com` |
| Explorer | explorer.testnet.chain.robinhood.com | robinhoodchain.blockscout.com |

## Roadmap

- Web app: check page, wallet connect, pay and report in $WIF, public register *(in progress)*
- Mainnet $WIF payments
- Community resolution of reports instead of a single curator
- Watchlists and alerts for new launches that match the rug pattern

## License

[MIT](LICENSE)
