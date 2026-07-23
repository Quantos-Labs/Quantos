// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.0;

interface IERC20Mkt {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

/// @title VybssNFTMarketplace — Combined ERC721 + Marketplace on Quantos
/// @notice Mint NFTs, list/buy with QTEST, offers with escrow, creator royalties.
///         0% marketplace fee (testnet). 5% default royalties (0-10% configurable).
contract VybssNFTMarketplace {

    // ── Solang 0.3.3 workaround ──
    function _mul(uint256 a, uint256 b) internal pure returns (uint256) { return a * b; }
    function _div(uint256 a, uint256 b) internal pure returns (uint256) { return a / b; }

    // ── Constants ──
    uint256 public constant BPS = 10000;
    uint256 public constant DEFAULT_ROYALTY_BPS = 500;  // 5%
    uint256 public constant MAX_ROYALTY_BPS = 1000;     // 10%

    // ── ERC721 metadata ──
    string public constant name = "Vybss NFT";
    string public constant symbol = "VNFT";

    address public owner;
    address public immutable paymentToken; // QTEST

    uint256 public nextTokenId;

    // ERC721 storage
    mapping(uint256 => address) private _owners;
    mapping(address => uint256) private _balances;
    mapping(uint256 => address) private _tokenApprovals;
    mapping(address => mapping(address => bool)) private _operatorApprovals;
    mapping(uint256 => string)  private _tokenURIs;
    mapping(uint256 => address) public creators;
    mapping(uint256 => uint256) public royaltyBps;

    // ── Marketplace: Listings ──
    struct Listing {
        address seller;
        uint256 price;
        bool    active;
    }
    mapping(uint256 => Listing) public listings;

    // ── Marketplace: Offers (escrowed) ──
    struct Offer {
        uint256 tokenId;
        address offerer;
        uint256 amount;
        bool    active;
    }
    mapping(uint256 => Offer) public offers;
    uint256 public nextOfferId;

    // ── Stats (on-chain) ──
    uint256 public totalVolume;
    uint256 public totalSales;
    uint256 public activeListingCount;

    // ── Events ──
    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);
    event Approval(address indexed owner, address indexed approved, uint256 indexed tokenId);
    event ApprovalForAll(address indexed owner, address indexed operator, bool approved);
    event Minted(uint256 indexed tokenId, address indexed creator, string uri, uint256 royaltyBps);
    event Listed(uint256 indexed tokenId, address indexed seller, uint256 price);
    event Delisted(uint256 indexed tokenId, address indexed seller);
    event Sold(uint256 indexed tokenId, address indexed seller, address indexed buyer, uint256 price, uint256 royalty);
    event OfferMade(uint256 indexed offerId, uint256 indexed tokenId, address indexed offerer, uint256 amount);
    event OfferAccepted(uint256 indexed offerId, uint256 indexed tokenId, address indexed buyer, uint256 amount);
    event OfferCancelled(uint256 indexed offerId);

    // ── Constructor ──
    constructor(address _paymentToken) {
        require(_paymentToken != address(0), "Invalid token");
        owner = msg.sender;
        paymentToken = _paymentToken;
    }

    // ═══════════════════════════════════════════════════════
    //  ERC721 VIEWS
    // ═══════════════════════════════════════════════════════

    function totalSupply() external view returns (uint256) { return nextTokenId; }

    function balanceOf(address _owner) external view returns (uint256) {
        require(_owner != address(0), "Zero address");
        return _balances[_owner];
    }

    function ownerOf(uint256 tokenId) external view returns (address) {
        address o = _owners[tokenId];
        require(o != address(0), "Not exists");
        return o;
    }

    function tokenURI(uint256 tokenId) external view returns (string memory) {
        require(_owners[tokenId] != address(0), "Not exists");
        return _tokenURIs[tokenId];
    }

    function getApproved(uint256 tokenId) external view returns (address) {
        return _tokenApprovals[tokenId];
    }

    function isApprovedForAll(address _owner, address operator) external view returns (bool) {
        return _operatorApprovals[_owner][operator];
    }

    // ═══════════════════════════════════════════════════════
    //  ERC721 WRITES
    // ═══════════════════════════════════════════════════════

    function approve(address to, uint256 tokenId) external {
        address o = _owners[tokenId];
        require(o != address(0), "Not exists");
        require(msg.sender == o || _operatorApprovals[o][msg.sender], "Not authorized");
        _tokenApprovals[tokenId] = to;
        emit Approval(o, to, tokenId);
    }

    function setApprovalForAll(address operator, bool approved) external {
        require(operator != msg.sender, "Self approve");
        _operatorApprovals[msg.sender][operator] = approved;
        emit ApprovalForAll(msg.sender, operator, approved);
    }

    function transferFrom(address from, address to, uint256 tokenId) external {
        require(_isApprovedOrOwner(msg.sender, tokenId), "Not authorized");
        _transfer(from, to, tokenId);
    }

    // ═══════════════════════════════════════════════════════
    //  MINT — anyone can mint
    // ═══════════════════════════════════════════════════════

    /// @notice Mint a new NFT with metadata URI and royalty percentage
    /// @param uri IPFS/HTTP URI pointing to metadata JSON
    /// @param _royaltyBps Royalty in basis points (0-1000 = 0%-10%)
    function mint(string memory uri, uint256 _royaltyBps) external returns (uint256 tokenId) {
        require(_royaltyBps <= MAX_ROYALTY_BPS, "Royalty > 10%");

        tokenId = nextTokenId;
        nextTokenId += 1;

        _owners[tokenId] = msg.sender;
        _balances[msg.sender] += 1;
        _tokenURIs[tokenId] = uri;
        creators[tokenId] = msg.sender;
        royaltyBps[tokenId] = _royaltyBps;

        emit Transfer(address(0), msg.sender, tokenId);
        emit Minted(tokenId, msg.sender, uri, _royaltyBps);
    }

    // ═══════════════════════════════════════════════════════
    //  MARKETPLACE: LIST / DELIST
    // ═══════════════════════════════════════════════════════

    function listItem(uint256 tokenId, uint256 price) external {
        require(_owners[tokenId] == msg.sender, "Not owner");
        require(price > 0, "Zero price");
        require(!listings[tokenId].active, "Already listed");

        // Auto-approve marketplace for transfer
        _tokenApprovals[tokenId] = address(this);

        listings[tokenId] = Listing({
            seller: msg.sender,
            price: price,
            active: true
        });
        activeListingCount += 1;

        emit Listed(tokenId, msg.sender, price);
    }

    function delistItem(uint256 tokenId) external {
        Listing storage l = listings[tokenId];
        require(l.active, "Not listed");
        require(l.seller == msg.sender, "Not seller");

        l.active = false;
        activeListingCount -= 1;
        _tokenApprovals[tokenId] = address(0);

        emit Delisted(tokenId, msg.sender);
    }

    // ═══════════════════════════════════════════════════════
    //  MARKETPLACE: BUY (direct purchase)
    // ═══════════════════════════════════════════════════════

    /// @notice Buy a listed NFT. Buyer must have approved QTEST to this contract.
    ///         0% marketplace fee. Royalties go to creator (if seller ≠ creator).
    function buyItem(uint256 tokenId) external {
        Listing storage l = listings[tokenId];
        require(l.active, "Not listed");
        require(msg.sender != l.seller, "Own item");

        uint256 price = l.price;
        address seller = l.seller;
        address creator = creators[tokenId];

        // Royalty (only if resale: seller != creator)
        uint256 royalty = 0;
        uint256 sellerAmount = price;
        if (seller != creator && royaltyBps[tokenId] > 0) {
            royalty = _div(_mul(price, royaltyBps[tokenId]), BPS);
            sellerAmount = price - royalty;
        }

        // Pay seller
        require(
            IERC20Mkt(paymentToken).transferFrom(msg.sender, seller, sellerAmount),
            "Payment failed"
        );
        // Pay royalty to creator
        if (royalty > 0) {
            require(
                IERC20Mkt(paymentToken).transferFrom(msg.sender, creator, royalty),
                "Royalty failed"
            );
        }

        // Transfer NFT & clear listing
        l.active = false;
        activeListingCount -= 1;
        _transfer(seller, msg.sender, tokenId);

        totalVolume += price;
        totalSales += 1;

        emit Sold(tokenId, seller, msg.sender, price, royalty);
    }

    // ═══════════════════════════════════════════════════════
    //  MARKETPLACE: OFFERS (escrowed in contract)
    // ═══════════════════════════════════════════════════════

    /// @notice Make an offer — QTEST is escrowed in the contract
    function makeOffer(uint256 tokenId, uint256 amount) external returns (uint256 offerId) {
        require(_owners[tokenId] != address(0), "Not exists");
        require(amount > 0, "Zero amount");
        require(msg.sender != _owners[tokenId], "Own item");

        require(
            IERC20Mkt(paymentToken).transferFrom(msg.sender, address(this), amount),
            "Escrow failed"
        );

        offerId = nextOfferId;
        nextOfferId += 1;

        offers[offerId] = Offer({
            tokenId: tokenId,
            offerer: msg.sender,
            amount: amount,
            active: true
        });

        emit OfferMade(offerId, tokenId, msg.sender, amount);
    }

    /// @notice NFT owner accepts an offer
    function acceptOffer(uint256 offerId) external {
        Offer storage o = offers[offerId];
        require(o.active, "Not active");

        uint256 tokenId = o.tokenId;
        require(_owners[tokenId] == msg.sender, "Not owner");

        address buyer = o.offerer;
        uint256 amount = o.amount;
        address creator = creators[tokenId];

        // Royalty calculation
        uint256 royalty = 0;
        uint256 sellerAmount = amount;
        if (msg.sender != creator && royaltyBps[tokenId] > 0) {
            royalty = _div(_mul(amount, royaltyBps[tokenId]), BPS);
            sellerAmount = amount - royalty;
        }

        o.active = false;

        // Pay from escrow
        require(IERC20Mkt(paymentToken).transfer(msg.sender, sellerAmount), "Pay failed");
        if (royalty > 0) {
            require(IERC20Mkt(paymentToken).transfer(creator, royalty), "Royalty failed");
        }

        // Delist if listed
        if (listings[tokenId].active) {
            listings[tokenId].active = false;
            activeListingCount -= 1;
        }

        // Transfer NFT
        _transfer(msg.sender, buyer, tokenId);

        totalVolume += amount;
        totalSales += 1;

        emit OfferAccepted(offerId, tokenId, buyer, amount);
    }

    /// @notice Cancel own offer — refund escrowed QTEST
    function cancelOffer(uint256 offerId) external {
        Offer storage o = offers[offerId];
        require(o.active, "Not active");
        require(o.offerer == msg.sender, "Not offerer");

        uint256 amount = o.amount;
        o.active = false;

        require(IERC20Mkt(paymentToken).transfer(msg.sender, amount), "Refund failed");

        emit OfferCancelled(offerId);
    }

    // ═══════════════════════════════════════════════════════
    //  VIEWS
    // ═══════════════════════════════════════════════════════

    function getListing(uint256 tokenId) external view returns (address seller, uint256 price, bool active) {
        Listing storage l = listings[tokenId];
        return (l.seller, l.price, l.active);
    }

    function getOffer(uint256 offerId) external view returns (uint256 tokenId, address offerer, uint256 amount, bool active) {
        Offer storage o = offers[offerId];
        return (o.tokenId, o.offerer, o.amount, o.active);
    }

    // ═══════════════════════════════════════════════════════
    //  INTERNAL
    // ═══════════════════════════════════════════════════════

    function _transfer(address from, address to, uint256 tokenId) private {
        require(_owners[tokenId] == from, "Not owner");
        require(to != address(0), "Zero address");
        _tokenApprovals[tokenId] = address(0);
        _balances[from] -= 1;
        _balances[to] += 1;
        _owners[tokenId] = to;
        emit Transfer(from, to, tokenId);
    }

    function _isApprovedOrOwner(address spender, uint256 tokenId) private view returns (bool) {
        address o = _owners[tokenId];
        require(o != address(0), "Not exists");
        return (spender == o || _tokenApprovals[tokenId] == spender || _operatorApprovals[o][spender]);
    }
}
