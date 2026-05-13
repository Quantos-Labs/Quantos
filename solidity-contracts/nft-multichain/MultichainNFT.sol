// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/ERC721Royalty.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title MultichainNFT
 * @dev ERC-721 NFT contract with royalties (EIP-2981)
 * Deployable to Base, Arbitrum, BSC, Polygon, HyperEVM
 */
contract MultichainNFT is ERC721, ERC721URIStorage, ERC721Royalty, Ownable {
    uint256 private _nextTokenId;
    
    string public baseTokenURI;
    uint256 public maxSupply;
    uint256 public mintPrice;
    bool public publicMintEnabled;
    address public payoutRecipient;
    uint96 public defaultRoyaltyFeeNumerator;
    
    mapping(address => bool) public minters;
    
    event NFTMinted(address indexed to, uint256 indexed tokenId, string tokenURI);
    event BaseURIUpdated(string newBaseURI);
    event MintPriceUpdated(uint256 newPrice);
    event PublicMintToggled(bool enabled);
    event MinterAdded(address indexed minter);
    event MinterRemoved(address indexed minter);
    event PayoutRecipientUpdated(address indexed newRecipient);
    
    modifier onlyMinter() {
        require(minters[msg.sender] || msg.sender == owner(), "Not authorized to mint");
        _;
    }
    
    constructor(
        string memory name,
        string memory symbol,
        string memory _baseTokenURI,
        uint256 _maxSupply,
        uint256 _mintPrice,
        address _payoutRecipient,
        address royaltyReceiver,
        uint96 royaltyFeeNumerator
    ) ERC721(name, symbol) Ownable(msg.sender) {
        require(_payoutRecipient != address(0), "Invalid payout recipient");
        require(royaltyReceiver != address(0), "Invalid royalty recipient");

        baseTokenURI = _baseTokenURI;
        maxSupply = _maxSupply;
        mintPrice = _mintPrice;
        payoutRecipient = _payoutRecipient;
        defaultRoyaltyFeeNumerator = royaltyFeeNumerator;
        
        // Set default royalty (EIP-2981)
        _setDefaultRoyalty(royaltyReceiver, royaltyFeeNumerator);
    }
    
    function _baseURI() internal view override returns (string memory) {
        return baseTokenURI;
    }
    
    /**
     * @dev Mint NFT with metadata URI
     */
    function mint(address to, string memory uri) public payable onlyMinter returns (uint256) {
        require(_nextTokenId < maxSupply, "Max supply reached");
        
        if (!minters[msg.sender] && msg.sender != owner()) {
            require(publicMintEnabled, "Public mint not enabled");
            require(msg.value >= mintPrice, "Insufficient payment");
        }
        
        uint256 tokenId = _nextTokenId;
        _nextTokenId += 1;
        
        _safeMint(to, tokenId);
        _setTokenURI(tokenId, uri);
        _setTokenRoyalty(tokenId, to, defaultRoyaltyFeeNumerator);

        if (msg.value > 0) {
            payable(payoutRecipient).transfer(msg.value);
        }
        
        emit NFTMinted(to, tokenId, uri);
        
        return tokenId;
    }
    
    /**
     * @dev Batch mint multiple NFTs
     */
    function batchMint(
        address to,
        string[] memory uris
    ) external payable onlyMinter returns (uint256[] memory) {
        require(_nextTokenId + uris.length <= maxSupply, "Exceeds max supply");
        
        if (!minters[msg.sender] && msg.sender != owner()) {
            require(publicMintEnabled, "Public mint not enabled");
            require(msg.value >= mintPrice * uris.length, "Insufficient payment");
        }
        
        uint256[] memory tokenIds = new uint256[](uris.length);
        
        for (uint256 i = 0; i < uris.length; i++) {
            uint256 tokenId = _nextTokenId;
            _nextTokenId += 1;
            
            _safeMint(to, tokenId);
            _setTokenURI(tokenId, uris[i]);
            _setTokenRoyalty(tokenId, to, defaultRoyaltyFeeNumerator);
            
            tokenIds[i] = tokenId;
            emit NFTMinted(to, tokenId, uris[i]);
        }

        if (msg.value > 0) {
            payable(payoutRecipient).transfer(msg.value);
        }
        
        return tokenIds;
    }
    
    /**
     * @dev Set token-specific royalty
     */
    function setTokenRoyalty(
        uint256 tokenId,
        address receiver,
        uint96 feeNumerator
    ) external onlyOwner {
        _setTokenRoyalty(tokenId, receiver, feeNumerator);
    }
    
    /**
     * @dev Update base URI
     */
    function setBaseURI(string memory newBaseURI) external onlyOwner {
        baseTokenURI = newBaseURI;
        emit BaseURIUpdated(newBaseURI);
    }
    
    /**
     * @dev Update mint price
     */
    function setMintPrice(uint256 newPrice) external onlyOwner {
        mintPrice = newPrice;
        emit MintPriceUpdated(newPrice);
    }
    
    /**
     * @dev Toggle public minting
     */
    function togglePublicMint() external onlyOwner {
        publicMintEnabled = !publicMintEnabled;
        emit PublicMintToggled(publicMintEnabled);
    }
    
    /**
     * @dev Add authorized minter
     */
    function addMinter(address minter) external onlyOwner {
        minters[minter] = true;
        emit MinterAdded(minter);
    }
    
    /**
     * @dev Remove authorized minter
     */
    function removeMinter(address minter) external onlyOwner {
        minters[minter] = false;
        emit MinterRemoved(minter);
    }

    /**
     * @dev Update payout recipient for primary mint funds
     */
    function setPayoutRecipient(address newRecipient) external onlyOwner {
        require(newRecipient != address(0), "Invalid payout recipient");
        payoutRecipient = newRecipient;
        emit PayoutRecipientUpdated(newRecipient);
    }
    
    /**
     * @dev Withdraw contract balance
     */
    function withdraw() external onlyOwner {
        uint256 balance = address(this).balance;
        require(balance > 0, "No balance to withdraw");
        payable(payoutRecipient).transfer(balance);
    }
    
    /**
     * @dev Get total minted
     */
    function totalMinted() public view returns (uint256) {
        return _nextTokenId;
    }
    
    // Required overrides
    function tokenURI(uint256 tokenId)
        public
        view
        override(ERC721, ERC721URIStorage)
        returns (string memory)
    {
        return super.tokenURI(tokenId);
    }
    
    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(ERC721, ERC721URIStorage, ERC721Royalty)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }
    
}
