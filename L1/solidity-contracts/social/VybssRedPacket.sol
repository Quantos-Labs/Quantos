// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.0;

/// @title VybssRedPacket — On-chain lucky money with QTEST on Quantos testnet
/// @notice Users lock QTEST into a red packet. Others can claim equal or lucky amounts.
///         Creator can reclaim unclaimed tokens after expiry.

interface IERC20RP {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract VybssRedPacket {

    // ── Solang 0.3.3 workaround ──────────────────────────────
    function _mul(uint256 a, uint256 b) internal pure returns (uint256) { return a * b; }
    function _div(uint256 a, uint256 b) internal pure returns (uint256) { return a / b; }

    // ── Packet type constants ────────────────────────────────
    uint8 public constant TYPE_EQUAL = 0;
    uint8 public constant TYPE_LUCKY = 1;

    // ── Packet status constants ──────────────────────────────
    uint8 public constant STATUS_ACTIVE  = 0;
    uint8 public constant STATUS_EXPIRED = 1;

    // ── Packet struct ────────────────────────────────────────
    struct RedPacket {
        address creator;
        address token;
        uint128 totalAmount;     // total QTEST locked (in wei)
        uint128 claimedAmount;   // total QTEST claimed so far
        uint32  totalCount;      // number of sub-packets
        uint32  claimedCount;    // number of claims so far
        uint8   packetType;      // 0 = equal, 1 = lucky
        uint8   status;          // 0 = active, 1 = expired
        uint64  expiresAt;       // unix timestamp (seconds)
    }

    // ── Storage ──────────────────────────────────────────────
    uint256 public nextPacketId;

    mapping(uint256 => RedPacket) public packets;
    mapping(uint256 => mapping(address => bool))    public hasClaimed;
    mapping(uint256 => mapping(address => uint128)) public claimAmounts;

    // Pseudo-random nonce — incremented each lucky claim
    uint256 private _nonce;

    // ── Events ───────────────────────────────────────────────
    event PacketCreated(
        uint256 indexed packetId,
        address indexed creator,
        uint128 amount,
        uint32  count,
        uint8   packetType
    );
    event PacketClaimed(
        uint256 indexed packetId,
        address indexed claimer,
        uint128 amount
    );
    event PacketExpired(uint256 indexed packetId, uint128 refunded);

    // ── Create ───────────────────────────────────────────────
    /// @notice Lock QTEST into a new red packet.
    /// @param token   ERC-20 token address (use QTEST address)
    /// @param amount  Total amount in wei (must be approved first)
    /// @param count   Number of sub-packets (1-500)
    /// @param packetType 0 = equal split, 1 = lucky random
    /// @param expiresAt Unix timestamp when unclaimed tokens can be refunded
    function createRedPacket(
        address token,
        uint128 amount,
        uint32  count,
        uint8   packetType,
        uint64  expiresAt
    ) external returns (uint256) {
        require(amount > 0, "amount=0");
        require(count > 0 && count <= 500, "count out of range");
        require(expiresAt > uint64(block.timestamp), "already expired");

        require(
            IERC20RP(token).transferFrom(msg.sender, address(this), uint256(amount)),
            "transferFrom failed"
        );

        uint256 packetId = nextPacketId;
        nextPacketId = packetId + 1;

        packets[packetId] = RedPacket({
            creator:       msg.sender,
            token:         token,
            totalAmount:   amount,
            claimedAmount: 0,
            totalCount:    count,
            claimedCount:  0,
            packetType:    packetType,
            status:        STATUS_ACTIVE,
            expiresAt:     expiresAt
        });

        emit PacketCreated(packetId, msg.sender, amount, count, packetType);
        return packetId;
    }

    // ── Claim ────────────────────────────────────────────────
    /// @notice Claim your share of a red packet.
    /// @param packetId The ID of the red packet to claim
    function claimRedPacket(uint256 packetId) external returns (uint128) {
        RedPacket storage p = packets[packetId];
        require(p.creator != address(0), "not found");
        require(p.status == STATUS_ACTIVE, "not active");
        require(uint64(block.timestamp) < p.expiresAt, "expired");
        require(p.claimedCount < p.totalCount, "all claimed");
        require(!hasClaimed[packetId][msg.sender], "already claimed");
        require(msg.sender != p.creator, "creator cannot claim own packet");

        uint128 remaining = p.totalAmount - p.claimedAmount;
        uint32  remCount  = p.totalCount - p.claimedCount;
        uint128 claimAmt;

        if (p.packetType == TYPE_EQUAL || remCount == 1) {
            // Equal split (also last packet always gets remainder)
            claimAmt = remaining / uint128(remCount);
        } else {
            // Lucky: pseudo-random between 1 wei and (remaining * 2 / remCount)
            // Simple arithmetic — avoids abi.encode / keccak for Solang compat
            _nonce = _nonce + 1;
            uint256 seed = block.timestamp + uint256(uint160(msg.sender)) + _nonce;
            uint128 maxPerPacket = _div(
                _mul(uint256(remaining), 2),
                uint256(remCount)
            ) > 0
                ? uint128(_div(_mul(uint256(remaining), 2), uint256(remCount)))
                : 1;
            claimAmt = uint128(seed % uint256(maxPerPacket)) + 1;
            // Cap: ensure every remaining claimer can get at least 1 unit
            uint128 maxAllowed = remaining - uint128(remCount - 1);
            if (claimAmt > maxAllowed) {
                claimAmt = maxAllowed;
            }
        }

        hasClaimed[packetId][msg.sender]  = true;
        claimAmounts[packetId][msg.sender] = claimAmt;
        p.claimedAmount += claimAmt;
        p.claimedCount  += 1;

        require(
            IERC20RP(p.token).transfer(msg.sender, uint256(claimAmt)),
            "transfer failed"
        );

        emit PacketClaimed(packetId, msg.sender, claimAmt);
        return claimAmt;
    }

    // ── Expire / refund ──────────────────────────────────────
    /// @notice Refund unclaimed tokens back to the creator.
    ///         Can be called by anyone after expiry (or once all packets claimed).
    function expireRedPacket(uint256 packetId) external returns (uint128) {
        RedPacket storage p = packets[packetId];
        require(p.creator != address(0), "not found");
        require(p.status == STATUS_ACTIVE, "not active");
        require(
            uint64(block.timestamp) >= p.expiresAt || p.claimedCount == p.totalCount,
            "not expired yet"
        );

        p.status = STATUS_EXPIRED;
        uint128 refund = p.totalAmount - p.claimedAmount;

        if (refund > 0) {
            require(
                IERC20RP(p.token).transfer(p.creator, uint256(refund)),
                "refund failed"
            );
        }

        emit PacketExpired(packetId, refund);
        return refund;
    }

    // ── Read packet info ─────────────────────────────────────
    function getRedPacket(uint256 packetId) external view returns (
        address creator,
        address token,
        uint128 totalAmount,
        uint128 claimedAmount,
        uint32  totalCount,
        uint32  claimedCount,
        uint8   packetType,
        uint8   status,
        uint64  expiresAt
    ) {
        RedPacket storage p = packets[packetId];
        return (
            p.creator,
            p.token,
            p.totalAmount,
            p.claimedAmount,
            p.totalCount,
            p.claimedCount,
            p.packetType,
            p.status,
            p.expiresAt
        );
    }

    /// @notice How many QTEST wei did a user receive from a specific packet?
    function getClaimAmount(uint256 packetId, address user) external view returns (uint128) {
        return claimAmounts[packetId][user];
    }

    /// @notice Has a user already claimed from a specific packet?
    function getUserHasClaimed(uint256 packetId, address user) external view returns (bool) {
        return hasClaimed[packetId][user];
    }
}
