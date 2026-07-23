// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.0;

interface IERC20Grants {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

/// @title VybssGrants — Quadratic Funding (Gitcoin-style) for Quantos
/// @notice Rounds, projects, donations in QTEST. QF matching calculated off-chain,
///         matching pool distributed on-chain by admin after round ends.
contract VybssGrants {

    // ── Solang 0.3.3 workaround: force full 256-bit arithmetic ──
    function _mul(uint256 a, uint256 b) internal pure returns (uint256) { return a * b; }
    function _div(uint256 a, uint256 b) internal pure returns (uint256) { return a / b; }

    // ── Constants ───────────────────────────────────────────────
    uint256 public constant BPS = 10000;
    uint256 public constant PROTOCOL_FEE_BPS = 250; // 2.5% fee on donations
    uint256 public constant MAX_PROJECTS_PER_ROUND = 200;

    // ── Enums (as uint8 constants for Solang) ───────────────────
    uint8 public constant ROUND_UPCOMING   = 0;
    uint8 public constant ROUND_ACTIVE     = 1;
    uint8 public constant ROUND_FINALIZING = 2;
    uint8 public constant ROUND_COMPLETED  = 3;
    uint8 public constant ROUND_CANCELLED  = 4;

    uint8 public constant PROJECT_PENDING  = 0;
    uint8 public constant PROJECT_APPROVED = 1;
    uint8 public constant PROJECT_REJECTED = 2;

    // ── State ───────────────────────────────────────────────────
    address public owner;
    address public immutable donationToken; // QTEST address

    uint256 public nextRoundId;
    uint256 public nextProjectId;
    uint256 public protocolFees;

    // ── Round struct ────────────────────────────────────────────
    struct Round {
        uint256 startTime;
        uint256 endTime;
        uint256 matchingPool;         // QTEST deposited by admin
        uint256 matchingDistributed;  // amount actually sent to projects
        uint256 totalDonations;
        uint256 uniqueDonors;
        uint256 projectCount;
        uint8   status;
    }

    // ── Project struct ──────────────────────────────────────────
    struct Project {
        uint256 roundId;
        address owner;               // project creator/recipient
        uint256 raised;              // total donations received
        uint256 donorCount;
        uint256 matchingReceived;    // matching amount distributed
        uint8   status;              // pending / approved / rejected
    }

    // ── Storage ─────────────────────────────────────────────────
    mapping(uint256 => Round) public rounds;
    mapping(uint256 => Project) public projects;

    // roundId → projectId[]
    mapping(uint256 => uint256[]) public roundProjects;

    // projectId → donor → total donated
    mapping(uint256 => mapping(address => uint256)) public donations;

    // roundId → donor → has donated (for unique count)
    mapping(uint256 => mapping(address => bool)) public roundDonors;

    // projectId → donor → has donated
    mapping(uint256 => mapping(address => bool)) public projectDonors;

    // ── Events ──────────────────────────────────────────────────
    event RoundCreated(uint256 indexed roundId, uint256 startTime, uint256 endTime, uint256 matchingPool);
    event RoundStatusChanged(uint256 indexed roundId, uint8 status);
    event MatchingPoolAdded(uint256 indexed roundId, uint256 amount);
    event ProjectSubmitted(uint256 indexed projectId, uint256 indexed roundId, address indexed owner);
    event ProjectStatusChanged(uint256 indexed projectId, uint8 status);
    event Donated(uint256 indexed projectId, address indexed donor, uint256 amount, uint256 fee);
    event MatchingDistributed(uint256 indexed roundId, uint256 indexed projectId, uint256 amount);
    event ProtocolFeesWithdrawn(address indexed to, uint256 amount);

    // ── Constructor ─────────────────────────────────────────────
    constructor(address _donationToken) {
        require(_donationToken != address(0), "Invalid token");
        owner = msg.sender;
        donationToken = _donationToken;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    // ═══════════════════════════════════════════════════════════
    //  ROUND MANAGEMENT (admin)
    // ═══════════════════════════════════════════════════════════

    /// @notice Create a new funding round
    function createRound(
        uint256 _startTime,
        uint256 _endTime,
        uint256 _matchingPool
    ) external onlyOwner returns (uint256 roundId) {
        require(_endTime > _startTime, "Invalid dates");

        roundId = nextRoundId;
        nextRoundId += 1;

        rounds[roundId] = Round({
            startTime: _startTime,
            endTime: _endTime,
            matchingPool: 0,
            matchingDistributed: 0,
            totalDonations: 0,
            uniqueDonors: 0,
            projectCount: 0,
            status: ROUND_UPCOMING
        });

        // Transfer matching pool from admin
        if (_matchingPool > 0) {
            require(
                IERC20Grants(donationToken).transferFrom(msg.sender, address(this), _matchingPool),
                "Pool transfer failed"
            );
            rounds[roundId].matchingPool = _matchingPool;
        }

        emit RoundCreated(roundId, _startTime, _endTime, _matchingPool);
    }

    /// @notice Add more QTEST to a round's matching pool
    function addToMatchingPool(uint256 _roundId, uint256 _amount) external {
        require(_amount > 0, "Zero amount");
        Round storage r = rounds[_roundId];
        require(r.status == ROUND_UPCOMING || r.status == ROUND_ACTIVE, "Round not open");

        require(
            IERC20Grants(donationToken).transferFrom(msg.sender, address(this), _amount),
            "Transfer failed"
        );
        r.matchingPool += _amount;

        emit MatchingPoolAdded(_roundId, _amount);
    }

    /// @notice Activate a round (must be upcoming)
    function activateRound(uint256 _roundId) external onlyOwner {
        Round storage r = rounds[_roundId];
        require(r.status == ROUND_UPCOMING, "Not upcoming");
        r.status = ROUND_ACTIVE;
        emit RoundStatusChanged(_roundId, ROUND_ACTIVE);
    }

    /// @notice Move round to finalizing (stops donations, before matching distribution)
    function finalizeRound(uint256 _roundId) external onlyOwner {
        Round storage r = rounds[_roundId];
        require(r.status == ROUND_ACTIVE, "Not active");
        r.status = ROUND_FINALIZING;
        emit RoundStatusChanged(_roundId, ROUND_FINALIZING);
    }

    /// @notice Complete round (after all matching is distributed)
    function completeRound(uint256 _roundId) external onlyOwner {
        Round storage r = rounds[_roundId];
        require(r.status == ROUND_FINALIZING, "Not finalizing");
        r.status = ROUND_COMPLETED;
        emit RoundStatusChanged(_roundId, ROUND_COMPLETED);
    }

    /// @notice Cancel round — refund matching pool to owner
    function cancelRound(uint256 _roundId) external onlyOwner {
        Round storage r = rounds[_roundId];
        require(r.status == ROUND_UPCOMING || r.status == ROUND_ACTIVE, "Cannot cancel");

        uint256 refund = r.matchingPool - r.matchingDistributed;
        r.status = ROUND_CANCELLED;

        if (refund > 0) {
            require(
                IERC20Grants(donationToken).transfer(owner, refund),
                "Refund failed"
            );
        }

        emit RoundStatusChanged(_roundId, ROUND_CANCELLED);
    }

    // ═══════════════════════════════════════════════════════════
    //  PROJECT MANAGEMENT
    // ═══════════════════════════════════════════════════════════

    /// @notice Submit a project to a round
    function submitProject(uint256 _roundId) external returns (uint256 projectId) {
        Round storage r = rounds[_roundId];
        require(r.status == ROUND_UPCOMING || r.status == ROUND_ACTIVE, "Round not open");
        require(r.projectCount < MAX_PROJECTS_PER_ROUND, "Max projects reached");

        projectId = nextProjectId;
        nextProjectId += 1;

        projects[projectId] = Project({
            roundId: _roundId,
            owner: msg.sender,
            raised: 0,
            donorCount: 0,
            matchingReceived: 0,
            status: PROJECT_PENDING
        });

        roundProjects[_roundId].push(projectId);
        r.projectCount += 1;

        emit ProjectSubmitted(projectId, _roundId, msg.sender);
    }

    /// @notice Admin approves or rejects a project
    function setProjectStatus(uint256 _projectId, uint8 _status) external onlyOwner {
        require(_status == PROJECT_APPROVED || _status == PROJECT_REJECTED, "Invalid status");
        projects[_projectId].status = _status;
        emit ProjectStatusChanged(_projectId, _status);
    }

    // ═══════════════════════════════════════════════════════════
    //  DONATIONS (core of QF)
    // ═══════════════════════════════════════════════════════════

    /// @notice Donate QTEST to an approved project in an active round
    function donate(uint256 _projectId, uint256 _amount) external {
        require(_amount > 0, "Zero amount");

        Project storage p = projects[_projectId];
        require(p.status == PROJECT_APPROVED, "Project not approved");

        Round storage r = rounds[p.roundId];
        require(r.status == ROUND_ACTIVE, "Round not active");

        // Transfer QTEST from donor
        require(
            IERC20Grants(donationToken).transferFrom(msg.sender, address(this), _amount),
            "Transfer failed"
        );

        // Protocol fee
        uint256 fee = _div(_mul(_amount, PROTOCOL_FEE_BPS), BPS);
        uint256 netAmount = _amount - fee;
        protocolFees += fee;

        // Credit project
        p.raised += netAmount;
        donations[_projectId][msg.sender] += netAmount;

        // Track unique donors
        if (!projectDonors[_projectId][msg.sender]) {
            projectDonors[_projectId][msg.sender] = true;
            p.donorCount += 1;
        }
        if (!roundDonors[p.roundId][msg.sender]) {
            roundDonors[p.roundId][msg.sender] = true;
            r.uniqueDonors += 1;
        }

        r.totalDonations += netAmount;

        emit Donated(_projectId, msg.sender, netAmount, fee);
    }

    // ═══════════════════════════════════════════════════════════
    //  MATCHING DISTRIBUTION (admin, after off-chain QF calc)
    // ═══════════════════════════════════════════════════════════

    /// @notice Distribute matching funds to a project. Called by admin after QF calculation.
    ///         The matching amounts are calculated off-chain (Supabase RPC) using the
    ///         CLR formula: matching_i = (sum_j sqrt(c_ij))^2 normalized to the pool.
    function distributeMatching(
        uint256 _roundId,
        uint256 _projectId,
        uint256 _amount
    ) external onlyOwner {
        Round storage r = rounds[_roundId];
        require(r.status == ROUND_FINALIZING, "Round not finalizing");
        require(_amount > 0, "Zero amount");

        Project storage p = projects[_projectId];
        require(p.roundId == _roundId, "Project not in round");
        require(p.status == PROJECT_APPROVED, "Not approved");

        uint256 remaining = r.matchingPool - r.matchingDistributed;
        require(_amount <= remaining, "Exceeds pool");

        r.matchingDistributed += _amount;
        p.matchingReceived += _amount;

        // Transfer matching to project owner
        require(
            IERC20Grants(donationToken).transfer(p.owner, _amount),
            "Transfer failed"
        );

        emit MatchingDistributed(_roundId, _projectId, _amount);
    }

    /// @notice Batch distribute matching to multiple projects
    function distributeMatchingBatch(
        uint256 _roundId,
        uint256[] calldata _projectIds,
        uint256[] calldata _amounts
    ) external onlyOwner {
        require(_projectIds.length == _amounts.length, "Length mismatch");
        Round storage r = rounds[_roundId];
        require(r.status == ROUND_FINALIZING, "Round not finalizing");

        for (uint256 i = 0; i < _projectIds.length; i++) {
            uint256 pid = _projectIds[i];
            uint256 amt = _amounts[i];
            if (amt == 0) continue;

            Project storage p = projects[pid];
            require(p.roundId == _roundId, "Project not in round");
            require(p.status == PROJECT_APPROVED, "Not approved");

            uint256 remaining = r.matchingPool - r.matchingDistributed;
            require(amt <= remaining, "Exceeds pool");

            r.matchingDistributed += amt;
            p.matchingReceived += amt;

            require(
                IERC20Grants(donationToken).transfer(p.owner, amt),
                "Transfer failed"
            );

            emit MatchingDistributed(_roundId, pid, amt);
        }
    }

    // ═══════════════════════════════════════════════════════════
    //  WITHDRAWALS
    // ═══════════════════════════════════════════════════════════

    /// @notice Project owner withdraws accumulated donations
    function withdrawDonations(uint256 _projectId) external {
        Project storage p = projects[_projectId];
        require(msg.sender == p.owner, "Not project owner");
        require(p.raised > 0, "Nothing to withdraw");

        Round storage r = rounds[p.roundId];
        require(r.status == ROUND_FINALIZING || r.status == ROUND_COMPLETED, "Round still active");

        uint256 amount = p.raised;
        p.raised = 0;

        require(
            IERC20Grants(donationToken).transfer(msg.sender, amount),
            "Transfer failed"
        );
    }

    /// @notice Admin withdraws accumulated protocol fees
    function withdrawProtocolFees() external onlyOwner {
        uint256 amount = protocolFees;
        require(amount > 0, "No fees");
        protocolFees = 0;

        require(
            IERC20Grants(donationToken).transfer(owner, amount),
            "Transfer failed"
        );

        emit ProtocolFeesWithdrawn(owner, amount);
    }

    // ═══════════════════════════════════════════════════════════
    //  VIEW FUNCTIONS
    // ═══════════════════════════════════════════════════════════

    function getRound(uint256 _roundId) external view returns (
        uint256 startTime, uint256 endTime, uint256 matchingPool,
        uint256 matchingDistributed, uint256 totalDonations,
        uint256 uniqueDonors, uint256 projectCount, uint8 status
    ) {
        Round storage r = rounds[_roundId];
        return (r.startTime, r.endTime, r.matchingPool, r.matchingDistributed,
                r.totalDonations, r.uniqueDonors, r.projectCount, r.status);
    }

    function getProject(uint256 _projectId) external view returns (
        uint256 roundId, address projectOwner, uint256 raised,
        uint256 donorCount, uint256 matchingReceived, uint8 status
    ) {
        Project storage p = projects[_projectId];
        return (p.roundId, p.owner, p.raised, p.donorCount, p.matchingReceived, p.status);
    }

    function getDonation(uint256 _projectId, address _donor) external view returns (uint256) {
        return donations[_projectId][_donor];
    }

    function getRoundProjectIds(uint256 _roundId) external view returns (uint256[] memory) {
        return roundProjects[_roundId];
    }

    function getRoundProjectCount(uint256 _roundId) external view returns (uint256) {
        return rounds[_roundId].projectCount;
    }

    // ── Admin ───────────────────────────────────────────────────
    function transferOwnership(address _newOwner) external onlyOwner {
        require(_newOwner != address(0), "Invalid");
        owner = _newOwner;
    }
}
