// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Minimal ERC-20 interface used by WifWheel.
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

/// @title WifWheel
/// @notice $WIF-powered scam register for Robinhood Chain.
///   - Anyone can pay a small $WIF fee for a deep token check: part is burned, the rest funds the reward pool.
///   - Anyone can report a scam token by staking $WIF. The curator resolves reports:
///       confirmed -> stake returned + a reward from the pool, and the token is flagged in the public register;
///       rejected  -> the stake is split between a burn and the pool.
///   The flywheel: checks fund rewards, rewards attract reporters, reports improve the register, a better register
///   attracts more checks.
/// @dev v1 uses a single curator to confirm reports; this is stated openly in the README.
contract WifWheel {
    address public constant BURN = 0x000000000000000000000000000000000000dEaD;
    uint16 public constant BPS = 10_000;

    IERC20 public immutable wif;
    address public owner;
    address public curator;

    uint256 public checkFee;      // $WIF (token units) per deep check
    uint256 public reportStake;   // $WIF a reporter must stake
    uint256 public reportReward;  // $WIF paid from the pool for a confirmed report
    uint16 public burnBps;        // share of fees and slashed stakes that is burned

    uint256 public rewardPool;    // $WIF held for rewards (excludes open stakes)
    uint256 public totalBurned;
    uint256 public totalChecks;

    enum Status { None, Open, Confirmed, Rejected }

    struct Report {
        address reporter;
        address token;
        uint96 stake;
        Status status;
        uint64 createdAt;
        string evidence;  // URL or IPFS link to the evidence
    }

    Report[] public reports;
    mapping(address => bool) public flagged;            // token -> confirmed scam
    mapping(address => uint256) public confirmedReports; // token -> number of confirmed reports
    mapping(address => uint256) public reporterScore;    // reporter -> confirmed reports

    uint256 private _locked = 1;

    event CheckPaid(address indexed user, address indexed token, uint256 fee, uint256 burned, uint256 indexed checkId);
    event ReportSubmitted(uint256 indexed id, address indexed reporter, address indexed token, uint256 stake, string evidence);
    event ReportResolved(uint256 indexed id, address indexed token, bool confirmed, uint256 payout, uint256 burned);
    event TokenFlagged(address indexed token, uint256 confirmedReports);
    event PoolFunded(address indexed from, uint256 amount);
    event ParamsUpdated(uint256 checkFee, uint256 reportStake, uint256 reportReward, uint16 burnBps);
    event CuratorChanged(address indexed curator);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    error NotOwner();
    error NotCurator();
    error BadParams();
    error BadToken();
    error NotOpen();
    error TransferFailed();
    error Reentrancy();

    modifier onlyOwner() { if (msg.sender != owner) revert NotOwner(); _; }
    modifier onlyCurator() { if (msg.sender != curator) revert NotCurator(); _; }
    modifier nonReentrant() { if (_locked != 1) revert Reentrancy(); _locked = 2; _; _locked = 1; }

    constructor(address wif_, uint256 checkFee_, uint256 reportStake_, uint256 reportReward_, uint16 burnBps_) {
        if (wif_ == address(0) || burnBps_ > BPS || reportStake_ > type(uint96).max) revert BadParams();
        wif = IERC20(wif_);
        owner = msg.sender;
        curator = msg.sender;
        checkFee = checkFee_;
        reportStake = reportStake_;
        reportReward = reportReward_;
        burnBps = burnBps_;
        emit OwnershipTransferred(address(0), msg.sender);
        emit CuratorChanged(msg.sender);
        emit ParamsUpdated(checkFee_, reportStake_, reportReward_, burnBps_);
    }

    // ------------------------------------------------------------------ checks
    /// @notice Pay the $WIF fee for a deep check of `token`. Requires prior approve(checkFee).
    function payForCheck(address token) external nonReentrant returns (uint256 checkId) {
        if (token == address(0)) revert BadToken();
        uint256 fee = checkFee;
        _pull(msg.sender, fee);
        uint256 burned = (fee * burnBps) / BPS;
        _burn(burned);
        rewardPool += fee - burned;
        checkId = ++totalChecks;
        emit CheckPaid(msg.sender, token, fee, burned, checkId);
    }

    // ------------------------------------------------------------------ reports
    /// @notice Report `token` as a scam by staking `reportStake` $WIF. Requires prior approve(reportStake).
    function submitReport(address token, string calldata evidence) external nonReentrant returns (uint256 id) {
        if (token == address(0)) revert BadToken();
        uint256 stake = reportStake;
        _pull(msg.sender, stake);
        id = reports.length;
        reports.push(Report({
            reporter: msg.sender, token: token, stake: uint96(stake), status: Status.Open,
            createdAt: uint64(block.timestamp), evidence: evidence
        }));
        emit ReportSubmitted(id, msg.sender, token, stake, evidence);
    }

    /// @notice Curator confirms or rejects an open report.
    function resolveReport(uint256 id, bool confirmed) external onlyCurator nonReentrant {
        Report storage r = reports[id];
        if (r.status != Status.Open) revert NotOpen();
        uint256 stake = r.stake;
        uint256 payout;
        uint256 burned;
        if (confirmed) {
            r.status = Status.Confirmed;
            uint256 reward = reportReward <= rewardPool ? reportReward : rewardPool;
            rewardPool -= reward;
            payout = stake + reward;
            reporterScore[r.reporter] += 1;
            uint256 n = ++confirmedReports[r.token];
            if (!flagged[r.token]) {
                flagged[r.token] = true;
            }
            emit TokenFlagged(r.token, n);
            _push(r.reporter, payout);
        } else {
            r.status = Status.Rejected;
            burned = (stake * burnBps) / BPS;
            _burn(burned);
            rewardPool += stake - burned;
        }
        emit ReportResolved(id, r.token, confirmed, payout, burned);
    }

    // ------------------------------------------------------------------ pool
    /// @notice Anyone can top up the reward pool. Requires prior approve(amount).
    function fundPool(uint256 amount) external nonReentrant {
        _pull(msg.sender, amount);
        rewardPool += amount;
        emit PoolFunded(msg.sender, amount);
    }

    // ------------------------------------------------------------------ views
    function reportCount() external view returns (uint256) { return reports.length; }

    function getReport(uint256 id) external view returns (Report memory) { return reports[id]; }

    /// @notice Most recent reports, newest first (for the public register page).
    function recentReports(uint256 limit) external view returns (Report[] memory out, uint256[] memory ids) {
        uint256 n = reports.length < limit ? reports.length : limit;
        out = new Report[](n);
        ids = new uint256[](n);
        for (uint256 i = 0; i < n; i++) {
            uint256 id = reports.length - 1 - i;
            out[i] = reports[id];
            ids[i] = id;
        }
    }

    // ------------------------------------------------------------------ admin
    function setParams(uint256 checkFee_, uint256 reportStake_, uint256 reportReward_, uint16 burnBps_) external onlyOwner {
        if (burnBps_ > BPS || reportStake_ > type(uint96).max) revert BadParams();
        checkFee = checkFee_;
        reportStake = reportStake_;
        reportReward = reportReward_;
        burnBps = burnBps_;
        emit ParamsUpdated(checkFee_, reportStake_, reportReward_, burnBps_);
    }

    function setCurator(address curator_) external onlyOwner {
        if (curator_ == address(0)) revert BadParams();
        curator = curator_;
        emit CuratorChanged(curator_);
    }

    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert BadParams();
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    // ------------------------------------------------------------------ internal
    function _pull(address from, uint256 amount) private {
        if (amount == 0) return;
        if (!wif.transferFrom(from, address(this), amount)) revert TransferFailed();
    }

    function _push(address to, uint256 amount) private {
        if (amount == 0) return;
        if (!wif.transfer(to, amount)) revert TransferFailed();
    }

    function _burn(uint256 amount) private {
        if (amount == 0) return;
        totalBurned += amount;
        if (!wif.transfer(BURN, amount)) revert TransferFailed();
    }
}
