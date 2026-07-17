// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title LynxNFT - 10,000 unique Lynx on Quantos
/// @notice ERC721-style NFT with minter-only mint, max supply 10k
contract LynxNFT {
    string public constant name = "Lynx NFT";
    string public constant symbol = "LYNX";
    uint256 public constant MAX_SUPPLY = 10000;

    address public minter;
    uint256 private _totalMinted;

    // tokenId → owner
    mapping(uint256 => address) private _owners;
    // owner → balance
    mapping(address => uint256) private _balances;
    // tokenId → approved address
    mapping(uint256 => address) private _tokenApprovals;
    // owner → operator → approved
    mapping(address => mapping(address => bool)) private _operatorApprovals;

    // Base URI for metadata
    string private _baseURI;

    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);
    event Approval(address indexed owner, address indexed approved, uint256 indexed tokenId);
    event ApprovalForAll(address indexed owner, address indexed operator, bool approved);
    event MinterSet(address indexed minterAddress);
    event BaseURISet(string uri);

    constructor() {}

    // ── Admin ──

    function setMinter(address _minter) external {
        require(minter == address(0), "Minter already set");
        require(_minter != address(0), "Invalid minter");
        minter = _minter;
        emit MinterSet(_minter);
    }

    function setBaseURI(string memory uri) external {
        require(msg.sender == minter, "Only minter");
        _baseURI = uri;
        emit BaseURISet(uri);
    }

    modifier onlyMinter() {
        require(msg.sender == minter, "Only minter");
        _;
    }

    // ── ERC721 Views ──

    function totalSupply() external view returns (uint256) {
        return _totalMinted;
    }

    function balanceOf(address owner) external view returns (uint256) {
        require(owner != address(0), "Zero address");
        return _balances[owner];
    }

    function ownerOf(uint256 tokenId) external view returns (address) {
        address owner = _owners[tokenId];
        require(owner != address(0), "Token does not exist");
        return owner;
    }

    function tokenURI(uint256 tokenId) external view returns (string memory) {
        require(_owners[tokenId] != address(0), "Token does not exist");
        // Returns baseURI + tokenId (consumer concatenates)
        return _baseURI;
    }

    function getApproved(uint256 tokenId) external view returns (address) {
        require(_owners[tokenId] != address(0), "Token does not exist");
        return _tokenApprovals[tokenId];
    }

    function isApprovedForAll(address owner, address operator) external view returns (bool) {
        return _operatorApprovals[owner][operator];
    }

    // ── ERC721 Writes ──

    function approve(address to, uint256 tokenId) external {
        address owner = _owners[tokenId];
        require(owner != address(0), "Token does not exist");
        require(msg.sender == owner || _operatorApprovals[owner][msg.sender], "Not authorized");
        _tokenApprovals[tokenId] = to;
        emit Approval(owner, to, tokenId);
    }

    function setApprovalForAll(address operator, bool approved) external {
        require(operator != msg.sender, "Approve to self");
        _operatorApprovals[msg.sender][operator] = approved;
        emit ApprovalForAll(msg.sender, operator, approved);
    }

    function transferFrom(address from, address to, uint256 tokenId) external {
        require(_isApprovedOrOwner(msg.sender, tokenId), "Not authorized");
        _transfer(from, to, tokenId);
    }

    // ── Mint (minter only) ──

    function mint(address to, uint256 tokenId) external onlyMinter {
        require(to != address(0), "Mint to zero");
        require(_owners[tokenId] == address(0), "Already minted");
        require(_totalMinted < MAX_SUPPLY, "Max supply reached");

        _owners[tokenId] = to;
        _balances[to] += 1;
        _totalMinted += 1;

        emit Transfer(address(0), to, tokenId);
    }

    // ── Internal ──

    function _transfer(address from, address to, uint256 tokenId) private {
        require(_owners[tokenId] == from, "Not owner");
        require(to != address(0), "Transfer to zero");

        // Clear approvals
        _tokenApprovals[tokenId] = address(0);

        _balances[from] -= 1;
        _balances[to] += 1;
        _owners[tokenId] = to;

        emit Transfer(from, to, tokenId);
    }

    function _isApprovedOrOwner(address spender, uint256 tokenId) private view returns (bool) {
        address owner = _owners[tokenId];
        require(owner != address(0), "Token does not exist");
        return (spender == owner || _tokenApprovals[tokenId] == spender || _operatorApprovals[owner][spender]);
    }
}
