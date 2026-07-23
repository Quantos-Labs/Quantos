// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.0;

/// @title QNS — Quantos Name Service
/// @notice Decentralized domain name service for the Quantos blockchain.
///         Each .qts domain is an NFT. Registration lasts 1 year.
///         Payment (300 QTEST) is enforced by the transaction layer.
contract QNS {
    // ── Constants ──
    string public constant name = "Quantos Name Service";
    string public constant symbol = "QNS";
    uint256 public constant REGISTRATION_DURATION = 365 days;

    // ── Domain Data ──
    struct Domain {
        address owner;
        address resolver;
        uint256 expiry;
        uint256 tokenId;
    }

    uint256 public totalSupply;
    uint256 private nextTokenId;

    // nameHash => Domain
    mapping(bytes32 => Domain) public domains;

    // tokenId => nameHash
    mapping(uint256 => bytes32) public tokenToName;

    // tokenId => full name string (e.g. "alice.qts")
    mapping(uint256 => string) public tokenNames;

    // address => nameHash (primary reverse record)
    mapping(address => bytes32) public reverseRecords;

    // ── ERC-721 Core ──
    mapping(uint256 => address) public ownerOf;
    mapping(address => uint256) public balanceOf;
    mapping(uint256 => address) public getApproved;
    mapping(address => mapping(address => bool)) public isApprovedForAll;

    // ── Events ──
    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);
    event Approval(address indexed owner, address indexed approved, uint256 indexed tokenId);
    event ApprovalForAll(address indexed owner, address indexed operator, bool approved);
    event NameRegistered(string domainName, bytes32 indexed nameHash, address indexed owner, uint256 expiry, uint256 tokenId);
    event NameRenewed(bytes32 indexed nameHash, uint256 newExpiry);
    event ResolverSet(bytes32 indexed nameHash, address indexed resolver);
    event ReverseRecordSet(address indexed addr, bytes32 indexed nameHash);

    // ══════════════════════════════════════════════════════════
    // ── Registration ──
    // ══════════════════════════════════════════════════════════

    /// @notice Register a new .qts domain name
    /// @param domainName The full domain name (e.g. "alice.qts")
    function register(string memory domainName) public {
        bytes32 nameHash = keccak256(bytes(domainName));

        // Check name is available or expired
        Domain storage d = domains[nameHash];
        if (d.owner != address(0)) {
            require(block.timestamp >= d.expiry, "Name is taken and not expired");
            // Clean up expired domain
            _cleanupExpired(nameHash);
        }

        // Mint NFT
        uint256 tokenId = nextTokenId;
        nextTokenId += 1;
        totalSupply += 1;

        uint256 expiry = block.timestamp + REGISTRATION_DURATION;

        domains[nameHash] = Domain({
            owner: msg.sender,
            resolver: msg.sender,
            expiry: expiry,
            tokenId: tokenId
        });

        tokenToName[tokenId] = nameHash;
        tokenNames[tokenId] = domainName;
        ownerOf[tokenId] = msg.sender;
        balanceOf[msg.sender] += 1;

        // Auto-set reverse record if user has none
        if (reverseRecords[msg.sender] == bytes32(0)) {
            reverseRecords[msg.sender] = nameHash;
            emit ReverseRecordSet(msg.sender, nameHash);
        }

        emit Transfer(address(0), msg.sender, tokenId);
        emit NameRegistered(domainName, nameHash, msg.sender, expiry, tokenId);
    }

    /// @notice Renew a domain for another year (owner only)
    /// @param domainName The full domain name
    function renew(string memory domainName) public {
        bytes32 nameHash = keccak256(bytes(domainName));
        Domain storage d = domains[nameHash];
        require(d.owner == msg.sender, "Not the owner");
        require(block.timestamp < d.expiry, "Domain expired, re-register instead");

        d.expiry += REGISTRATION_DURATION;
        emit NameRenewed(nameHash, d.expiry);
    }

    // ══════════════════════════════════════════════════════════
    // ── Resolution ──
    // ══════════════════════════════════════════════════════════

    /// @notice Resolve a domain name to an address
    /// @param domainName The full domain name
    /// @return The resolved address (address(0) if not found or expired)
    function resolve(string memory domainName) public view returns (address) {
        bytes32 nameHash = keccak256(bytes(domainName));
        Domain storage d = domains[nameHash];
        if (d.owner == address(0) || block.timestamp >= d.expiry) {
            return address(0);
        }
        return d.resolver;
    }

    /// @notice Resolve a nameHash to an address
    function resolveByHash(bytes32 nameHash) public view returns (address) {
        Domain storage d = domains[nameHash];
        if (d.owner == address(0) || block.timestamp >= d.expiry) {
            return address(0);
        }
        return d.resolver;
    }

    /// @notice Reverse resolve: get the primary name hash for an address
    function reverseResolve(address addr) public view returns (bytes32) {
        bytes32 nameHash = reverseRecords[addr];
        if (nameHash == bytes32(0)) return bytes32(0);
        Domain storage d = domains[nameHash];
        if (d.owner != addr || block.timestamp >= d.expiry) {
            return bytes32(0);
        }
        return nameHash;
    }

    /// @notice Set the resolver address for a domain (owner only)
    function setResolver(string memory domainName, address resolver) public {
        bytes32 nameHash = keccak256(bytes(domainName));
        Domain storage d = domains[nameHash];
        require(d.owner == msg.sender, "Not the owner");
        require(block.timestamp < d.expiry, "Domain expired");
        d.resolver = resolver;
        emit ResolverSet(nameHash, resolver);
    }

    /// @notice Set your primary reverse record
    function setReverseRecord(string memory domainName) public {
        bytes32 nameHash = keccak256(bytes(domainName));
        Domain storage d = domains[nameHash];
        require(d.owner == msg.sender, "Not the owner");
        require(block.timestamp < d.expiry, "Domain expired");
        reverseRecords[msg.sender] = nameHash;
        emit ReverseRecordSet(msg.sender, nameHash);
    }

    // ══════════════════════════════════════════════════════════
    // ── Read Helpers ──
    // ══════════════════════════════════════════════════════════

    /// @notice Get full domain info by name
    function getDomain(string memory domainName) public view returns (
        address owner,
        address resolver,
        uint256 expiry,
        uint256 tokenId,
        bool isExpired
    ) {
        bytes32 nameHash = keccak256(bytes(domainName));
        Domain storage d = domains[nameHash];
        return (d.owner, d.resolver, d.expiry, d.tokenId, block.timestamp >= d.expiry);
    }

    /// @notice Check if a domain name is available
    function isAvailable(string memory domainName) public view returns (bool) {
        bytes32 nameHash = keccak256(bytes(domainName));
        Domain storage d = domains[nameHash];
        return d.owner == address(0) || block.timestamp >= d.expiry;
    }

    /// @notice Get the name string for a token ID
    function nameOf(uint256 tokenId) public view returns (string memory) {
        return tokenNames[tokenId];
    }

    // ══════════════════════════════════════════════════════════
    // ── ERC-721 Transfers ──
    // ══════════════════════════════════════════════════════════

    function transferFrom(address from, address to, uint256 tokenId) public {
        require(ownerOf[tokenId] == from, "Not the token owner");
        require(
            msg.sender == from ||
            msg.sender == getApproved[tokenId] ||
            isApprovedForAll[from][msg.sender],
            "Not authorized"
        );
        require(to != address(0), "Transfer to zero address");

        // Update NFT ownership
        ownerOf[tokenId] = to;
        balanceOf[from] -= 1;
        balanceOf[to] += 1;
        getApproved[tokenId] = address(0);

        // Update domain ownership
        bytes32 nameHash = tokenToName[tokenId];
        Domain storage d = domains[nameHash];
        d.owner = to;
        d.resolver = to;

        // Clear reverse record if transferring away
        if (reverseRecords[from] == nameHash) {
            reverseRecords[from] = bytes32(0);
        }

        // Set reverse record for new owner if they have none
        if (reverseRecords[to] == bytes32(0)) {
            reverseRecords[to] = nameHash;
            emit ReverseRecordSet(to, nameHash);
        }

        emit Transfer(from, to, tokenId);
    }

    function approve(address to, uint256 tokenId) public {
        address tokenOwner = ownerOf[tokenId];
        require(msg.sender == tokenOwner || isApprovedForAll[tokenOwner][msg.sender], "Not authorized");
        getApproved[tokenId] = to;
        emit Approval(tokenOwner, to, tokenId);
    }

    function setApprovalForAll(address operator, bool approved) public {
        isApprovedForAll[msg.sender][operator] = approved;
        emit ApprovalForAll(msg.sender, operator, approved);
    }

    // ══════════════════════════════════════════════════════════
    // ── Internal ──
    // ══════════════════════════════════════════════════════════

    function _cleanupExpired(bytes32 nameHash) internal {
        Domain storage d = domains[nameHash];
        if (d.owner == address(0)) return;

        address prevOwner = d.owner;
        uint256 prevTokenId = d.tokenId;

        // Burn the expired NFT
        ownerOf[prevTokenId] = address(0);
        if (balanceOf[prevOwner] > 0) {
            balanceOf[prevOwner] -= 1;
        }
        totalSupply -= 1;

        // Clear reverse record if it was this name
        if (reverseRecords[prevOwner] == nameHash) {
            reverseRecords[prevOwner] = bytes32(0);
        }

        emit Transfer(prevOwner, address(0), prevTokenId);
    }
}
