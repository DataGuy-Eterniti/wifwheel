"""Tests for WifWheel on a local in-memory EVM (no network, no real funds).

Run:  node contracts/compile.js  &&  python -m pytest contracts/test_wifwheel.py -q
"""
import json
import os

import pytest
from web3 import EthereumTesterProvider, Web3
from eth_tester.exceptions import TransactionFailed
from web3.exceptions import ContractLogicError

REVERT = (ContractLogicError, TransactionFailed)

BUILD = os.path.join(os.path.dirname(__file__), "build")
E = 10 ** 18
FEE, STAKE, REWARD, BURN_BPS = 10 * E, 100 * E, 50 * E, 5000
DEAD = Web3.to_checksum_address("0x000000000000000000000000000000000000dEaD")
SCAM = Web3.to_checksum_address("0x1111111111111111111111111111111111111111")


def load(name):
    with open(os.path.join(BUILD, f"{name}.json")) as f:
        return json.load(f)


@pytest.fixture
def env():
    w3 = Web3(EthereumTesterProvider())
    owner, alice, bob, mallory = w3.eth.accounts[:4]

    def deploy(name, *args):
        art = load(name)
        tx = w3.eth.contract(abi=art["abi"], bytecode=art["bytecode"]).constructor(*args).transact({"from": owner})
        addr = w3.eth.get_transaction_receipt(tx).contractAddress
        return w3.eth.contract(address=addr, abi=art["abi"])

    wif = deploy("MockWIF")
    wheel = deploy("WifWheel", wif.address, FEE, STAKE, REWARD, BURN_BPS)
    for who in (alice, bob, mallory):
        wif.functions.mint(who, 1_000 * E).transact({"from": owner})
        wif.functions.approve(wheel.address, 2 ** 256 - 1).transact({"from": who})
    return w3, wif, wheel, owner, alice, bob, mallory


def test_pay_for_check_burns_half_and_funds_pool(env):
    w3, wif, wheel, owner, alice, *_ = env
    wheel.functions.payForCheck(SCAM).transact({"from": alice})
    assert wif.functions.balanceOf(DEAD).call() == FEE // 2
    assert wheel.functions.rewardPool().call() == FEE // 2
    assert wheel.functions.totalBurned().call() == FEE // 2
    assert wheel.functions.totalChecks().call() == 1
    assert wif.functions.balanceOf(alice).call() == 1_000 * E - FEE


def test_confirmed_report_returns_stake_pays_reward_and_flags(env):
    w3, wif, wheel, owner, alice, bob, _ = env
    for _ in range(12):  # 12 checks -> pool of 60 WIF
        wheel.functions.payForCheck(SCAM).transact({"from": alice})
    wheel.functions.submitReport(SCAM, "https://example.org/evidence").transact({"from": bob})
    before = wif.functions.balanceOf(bob).call()
    wheel.functions.resolveReport(0, True).transact({"from": owner})
    assert wif.functions.balanceOf(bob).call() == before + STAKE + REWARD
    assert wheel.functions.flagged(SCAM).call() is True
    assert wheel.functions.confirmedReports(SCAM).call() == 1
    assert wheel.functions.reporterScore(bob).call() == 1
    assert wheel.functions.rewardPool().call() == 60 * E - REWARD


def test_reward_is_capped_by_pool(env):
    w3, wif, wheel, owner, alice, bob, _ = env
    wheel.functions.payForCheck(SCAM).transact({"from": alice})  # pool = 5 WIF
    wheel.functions.submitReport(SCAM, "ev").transact({"from": bob})
    before = wif.functions.balanceOf(bob).call()
    wheel.functions.resolveReport(0, True).transact({"from": owner})
    assert wif.functions.balanceOf(bob).call() == before + STAKE + 5 * E
    assert wheel.functions.rewardPool().call() == 0


def test_rejected_report_slashes_stake(env):
    w3, wif, wheel, owner, _, _, mallory = env
    wheel.functions.submitReport(SCAM, "spam").transact({"from": mallory})
    wheel.functions.resolveReport(0, False).transact({"from": owner})
    assert wif.functions.balanceOf(mallory).call() == 1_000 * E - STAKE
    assert wif.functions.balanceOf(DEAD).call() == STAKE // 2
    assert wheel.functions.rewardPool().call() == STAKE // 2
    assert wheel.functions.flagged(SCAM).call() is False


def test_open_stakes_are_not_paid_out_as_rewards(env):
    """Rewards come only from the pool, never from other people's open stakes."""
    w3, wif, wheel, owner, _, bob, mallory = env
    wheel.functions.submitReport(SCAM, "a").transact({"from": mallory})  # open, 100 WIF staked
    wheel.functions.submitReport(SCAM, "b").transact({"from": bob})
    wheel.functions.resolveReport(1, True).transact({"from": owner})      # pool is empty
    assert wheel.functions.rewardPool().call() == 0
    assert wif.functions.balanceOf(wheel.address).call() == STAKE           # mallory's stake still held


def test_only_curator_resolves_and_only_once(env):
    w3, wif, wheel, owner, alice, bob, _ = env
    wheel.functions.submitReport(SCAM, "ev").transact({"from": bob})
    with pytest.raises(REVERT):
        wheel.functions.resolveReport(0, True).transact({"from": alice})
    wheel.functions.resolveReport(0, True).transact({"from": owner})
    with pytest.raises(REVERT):
        wheel.functions.resolveReport(0, False).transact({"from": owner})


def test_admin_controls(env):
    w3, wif, wheel, owner, alice, *_ = env
    with pytest.raises(REVERT):
        wheel.functions.setParams(1, 1, 1, 100).transact({"from": alice})
    with pytest.raises(REVERT):
        wheel.functions.setParams(1, 1, 1, 10_001).transact({"from": owner})
    wheel.functions.setParams(2 * E, 20 * E, 5 * E, 2500).transact({"from": owner})
    assert wheel.functions.checkFee().call() == 2 * E
    wheel.functions.setCurator(alice).transact({"from": owner})
    assert wheel.functions.curator().call() == alice


def test_fund_pool_and_recent_reports(env):
    w3, wif, wheel, owner, alice, bob, _ = env
    wheel.functions.fundPool(30 * E).transact({"from": alice})
    assert wheel.functions.rewardPool().call() == 30 * E
    wheel.functions.submitReport(SCAM, "first").transact({"from": bob})
    wheel.functions.submitReport(SCAM, "second").transact({"from": alice})
    reports, ids = wheel.functions.recentReports(5).call()
    assert ids == [1, 0]
    assert reports[0][5] == "second"


def test_zero_address_token_rejected(env):
    w3, wif, wheel, owner, alice, *_ = env
    zero = "0x0000000000000000000000000000000000000000"
    with pytest.raises(REVERT):
        wheel.functions.payForCheck(zero).transact({"from": alice})
    with pytest.raises(REVERT):
        wheel.functions.submitReport(zero, "x").transact({"from": alice})
