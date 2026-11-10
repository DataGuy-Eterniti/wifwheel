# WifWheel

**A $WIF-powered rug-pull checker and scam register for Robinhood Chain.**

Paste a token address and WifWheel reads the chain to tell you whether it looks like a rug, with evidence you can click. Pay a little $WIF for a deep check, report scams by staking $WIF, and earn $WIF when your report is confirmed.

**Try it live:** https://wifwheel.onrender.com
**Demo video (under 3 min):** https://youtu.be/k2dGYIfJN60

> **Demo status:** payments run on **Robinhood Chain testnet with a mock $WIF token**, so anyone can try the full flow for free (the site has a "Get test $WIF" button). Token checks read **real mainnet data**. The contract takes the $WIF address at deploy, so going live means deploying it on mainnet pointed at real $WIF.
>
> The free hosting sleeps when idle: if the site is slow to open, give it about a minute to wake up.

Built for the [World is Flat hackathon](https://worldisflat.fun/build). Not affiliated with Robinhood Markets, Inc.

---

## Why

Rug pulls are hitting this chain hard. In September 2026 an onchain analyst linked **53 token launches on Robinhood Chain to one group that extracted about $18.4M** (Deed Estate, CRUMBS, LEGS, PINK and others). The pattern repeated: insider wallets held most of the supply when trading opened, then dumped it and left the market dead. ([Coinpaper](https://coinpaper.com/36441/analyst-links-53-robinhood-chain-tokens-to-one-184m-rug-pull-ring), [CoinCentral](https://coincentral.com/inside-the-18-million-rug-pull-rocking-robinhood-chain))

After a rug, today's holder list looks harmless. The evidence is in the token's history, and WifWheel replays it.

## Results on real tokens

| Token | Verdict | Why |
|---|---|---|
| **Deed Estate (DEED)**, from the rug ring | **HIGH RISK, 100/100** | 41 wallets held 89% of the supply a minute after trading opened, then sold 91% of it; liquidity under $6K; no trades in 24h; 114 wallets bought in the first seconds |
| **World is Flat ($WIF)** | **No major red flags, 16/100** | Its launch was concentrated too, but supply has spread to 1,600+ holders and about $137K of liquidity remains, so it is marked low, not a rug |

## What it checks

**Quick check (free, seconds):**

| Check | What it catches |
|---|---|
| Contract powers | A live owner who can mint, pause, blacklist or change fees; upgradeable proxies |
| Liquidity and trading | Thin or missing pools; trading that has died |
| Spam names | Names stuffed with other brands to impersonate them in searches |

**Deep check (paid in $WIF): replays every Transfer of the token from the chain:**

| Check | What it catches |
|---|---|
| Insiders at launch | How much of the supply wallets held about a minute after trading opened (pools and launchpad curves included) |
| Sell-off | Whether those wallets sold out **and** the market collapsed: the rug pattern |
| Linked holders | Top holders funded by, or cashing out to, the same wallet, or seeded in one transaction |
| Launch snipers | Many wallets buying in the first seconds |
| Holder concentration | The top 10 wallets (excluding pools and contracts) holding most of the supply |
| Launcher history | A creator who has deployed many contracts before |

Every finding links to the block explorer. The verdict is **HIGH RISK**, **CAUTION**, **NO MAJOR RED FLAGS FOUND** or **INCOMPLETE CHECK** (when the RPC could not return the full history). WifWheel never says "safe", and it lists what it could not check.

## The $WIF flywheel

```
  pay $WIF for a deep check ──► 50% burned, 50% to the reward pool
              ▲                                   │
              │                                   ▼
  public register brings more checks ◄── confirmed scam reports are paid from the pool
              ▲                                   │
              └──────── reporters stake $WIF to report scams ◄──┘
```

- **Quick checks are free.** Deep checks cost a small $WIF fee (10 in the demo), split onchain: 50% burned, 50% to the reward pool.
- **Report a scam** by staking $WIF (100 in the demo) with a link to evidence.
  - **Confirmed:** you get your stake back plus a reward from the pool, and the token is flagged in the public onchain register.
  - **Rejected:** half the stake is burned and half goes to the pool, so spam costs money.
- The server only runs a paid deep check after it reads the `CheckPaid` event for that exact token in the transaction receipt, and each payment works once.
- **v1 has a single curator** who confirms reports. That is stated plainly here; community resolution is on the roadmap.

## Contracts (Robinhood Chain testnet, chain 46630)

| Contract | Address |
|---|---|
| WifWheel | `__WIFWHEEL__` ([explorer](https://explorer.testnet.chain.robinhood.com/address/__WIFWHEEL__)) |
| Mock $WIF (demo only) | `__WIF__` ([explorer](https://explorer.testnet.chain.robinhood.com/address/__WIF__)) |

`contracts/WifWheel.sol` · MIT · no external dependencies.

| Function | What it does |
|---|---|
| `payForCheck(token)` | Pay the check fee in $WIF; part burned, part to the pool |
| `submitReport(token, evidence)` | Stake $WIF to report a scam |
| `resolveReport(id, confirmed)` | Curator confirms (stake + reward, token flagged) or rejects (stake slashed) |
| `fundPool(amount)` | Anyone can top up rewards |
| `flagged(token)`, `recentReports(n)` | Public scam register |

Rewards only ever come from the pool, never from other users' open stakes. Reentrancy guarded.

## How it's built

- **Contract:** Solidity 0.8.24, compiled with solc-js.
- **Scanner (`scanner.py`):** reads the public RPC and DexScreener only, with no indexer and no explorer API (the explorer blocks scripts). Transfer logs are fetched in 10-million-block chunks with backoff on rate limits; finished chunks are saved to disk so an interrupted scan resumes.
- **Server (`app.py`):** FastAPI. Quick checks are rate-limited; deep checks run as background jobs; results are cached for 6 hours.
- **Frontend (`static/index.html`):** one page with ethers v6 and MetaMask.
- **Hosting:** Docker on Render.
- **Tests:** 31 tests (contract, scanner, server) run in GitHub Actions on every push.

## Run it yourself

```bash
pip install -r requirements.txt
python scanner.py 0xTokenAddress           # full check of any Robinhood Chain token
python scanner.py 0xTokenAddress --quick   # free checks only
uvicorn app:app --port 8000                # the web app at http://localhost:8000
```

Deploy your own contract to testnet with a mock $WIF (free):

```bash
npm install && npm run compile
cp .env.example .env    # add a NEW wallet's key with testnet ETH from the faucet
python contracts/deploy.py
```

Tests: `npm test` and `python -m pytest test_scanner.py test_app.py` (the contract tests need `web3[tester]`, which installs easily on Linux and macOS).

## Network

| | Testnet (payments in this demo) | Mainnet (token data) |
|---|---|---|
| Chain ID | 46630 | 4663 |
| RPC | `https://rpc.testnet.chain.robinhood.com` | `https://rpc.mainnet.chain.robinhood.com` |
| Explorer | explorer.testnet.chain.robinhood.com | robinhoodchain.blockscout.com |

## Roadmap

- Mainnet $WIF payments
- Community resolution of reports instead of a single curator
- Show register flags inside check results; a free API and Telegram bot
- Count tokens launched through launchpads, and link wallets by who funded them with ETH
- Auto-scan new launches and alert holders

## License

[MIT](LICENSE)
