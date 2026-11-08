"""Deploy WifWheel to Robinhood Chain testnet or mainnet.

.env (never commit it):
    DEPLOYER_KEY=0x...            # a NEW wallet used only for this project
    NETWORK=testnet               # or mainnet
    WIF_ADDRESS=                  # mainnet: the real $WIF contract; testnet: leave empty to deploy a mock
    CHECK_FEE=10                  # whole $WIF per deep check
    REPORT_STAKE=100              # whole $WIF staked per report
    REPORT_REWARD=50              # whole $WIF reward for a confirmed report
    BURN_BPS=5000                 # 5000 = burn 50% of fees and slashed stakes

Run:
    node contracts/compile.js
    python contracts/deploy.py
"""
import json
import os
import sys

from dotenv import load_dotenv
from eth_account import Account
from web3 import Web3

NETWORKS = {
    "testnet": {"rpc": "https://rpc.testnet.chain.robinhood.com", "chain_id": 46630,
                "explorer": "https://explorer.testnet.chain.robinhood.com"},
    "mainnet": {"rpc": "https://rpc.mainnet.chain.robinhood.com", "chain_id": 4663,
                "explorer": "https://robinhoodchain.blockscout.com"},
}
HERE = os.path.dirname(os.path.abspath(__file__))
ERC20_DECIMALS = [{"name": "decimals", "inputs": [], "outputs": [{"type": "uint8"}], "stateMutability": "view", "type": "function"}]


def load(name):
    with open(os.path.join(HERE, "build", f"{name}.json")) as f:
        return json.load(f)


def send(w3, acct, tx):
    tx.setdefault("from", acct.address)
    tx.setdefault("nonce", w3.eth.get_transaction_count(acct.address))
    tx.setdefault("chainId", w3.eth.chain_id)
    tx.setdefault("gas", int(w3.eth.estimate_gas(tx) * 1.2))
    if "maxFeePerGas" not in tx and "gasPrice" not in tx:
        tx["gasPrice"] = w3.eth.gas_price
    signed = acct.sign_transaction(tx)
    h = w3.eth.send_raw_transaction(signed.raw_transaction)
    rcpt = w3.eth.wait_for_transaction_receipt(h, timeout=180)
    if rcpt.status != 1:
        sys.exit(f"Transaction failed: {h.hex()}")
    return rcpt


def deploy(w3, acct, name, *args):
    art = load(name)
    tx = w3.eth.contract(abi=art["abi"], bytecode=art["bytecode"]).constructor(*args).build_transaction(
        {"from": acct.address, "nonce": w3.eth.get_transaction_count(acct.address)})
    tx.pop("gas", None)
    rcpt = send(w3, acct, tx)
    return rcpt.contractAddress, rcpt.transactionHash.hex()


def main():
    load_dotenv()
    net = NETWORKS[os.getenv("NETWORK", "testnet")]
    w3 = Web3(Web3.HTTPProvider(os.getenv("RPC_URL") or net["rpc"]))
    if w3.eth.chain_id != net["chain_id"]:
        sys.exit(f"Connected to chain {w3.eth.chain_id}, expected {net['chain_id']}")
    acct = Account.from_key(os.environ["DEPLOYER_KEY"])
    print(f"Deployer {acct.address} · balance {w3.from_wei(w3.eth.get_balance(acct.address), 'ether')} ETH")

    wif = os.getenv("WIF_ADDRESS", "").strip()
    if not wif:
        if net["chain_id"] == 4663:
            sys.exit("On mainnet, set WIF_ADDRESS to the real $WIF contract.")
        wif, h = deploy(w3, acct, "MockWIF")
        print(f"MockWIF deployed at {wif}  ({net['explorer']}/tx/0x{h.removeprefix('0x')})")
        mock = w3.eth.contract(address=wif, abi=load("MockWIF")["abi"])
        send(w3, acct, mock.functions.mint(acct.address, 1_000_000 * 10 ** 18).build_transaction(
            {"from": acct.address, "nonce": w3.eth.get_transaction_count(acct.address)}))
        print("Minted 1,000,000 mock WIF to the deployer for testing")
    wif = Web3.to_checksum_address(wif)
    dec = w3.eth.contract(address=wif, abi=ERC20_DECIMALS).functions.decimals().call()
    unit = 10 ** dec

    args = (wif, int(float(os.getenv("CHECK_FEE", "10")) * unit), int(float(os.getenv("REPORT_STAKE", "100")) * unit),
            int(float(os.getenv("REPORT_REWARD", "50")) * unit), int(os.getenv("BURN_BPS", "5000")))
    addr, h = deploy(w3, acct, "WifWheel", *args)
    print(f"WifWheel deployed at {addr}")
    print(f"  {net['explorer']}/address/{addr}")
    print(f"  tx {net['explorer']}/tx/0x{h.removeprefix('0x')}")
    print(f"\nAdd to .env:\nWIFWHEEL_ADDRESS={addr}\nWIF_ADDRESS={wif}")


if __name__ == "__main__":
    main()
