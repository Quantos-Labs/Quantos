// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import "@openzeppelin/contracts/token/ERC1155/IERC1155.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC721/utils/ERC721Holder.sol";
import "@openzeppelin/contracts/token/ERC1155/utils/ERC1155Holder.sol";
import "@openzeppelin/contracts/interfaces/IERC2981.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title MultichainNFTMarketplace
 * @dev NFT marketplace supporting ERC-721 and ERC-1155 with royalties
 * Deployable to Base, Arbitrum, BSC, Polygon, HyperEVM
 */
contract MultichainNFTMarketplace is Ownable, ReentrancyGuard, ERC721Holder, ERC1155Holder {
    
    enum TokenStandard { ERC721, ERC1155 }
    enum ListingStatus { Active, Sold, Cancelled }
    
    struct Listing {
        uint256 listingId;
        address seller;
        address nftContract;
        uint256 tokenId;
        uint256 amount; // For ERC1155, 1 for ERC721
        TokenStandard standard;
        address paymentToken; // address(0) for native token
        uint256 price;
        ListingStatus status;
        uint256 expiresAt; // 0 for no expiration
    }
    
    struct Offer {
        uint256 offerId;
        address offerer;
        address nftContract;
        uint256 tokenId;
        address paymentToken;
        uint256 offerPrice;
        uint256 expiresAt;
        bool isActive;
    }
    
    // Marketplace fee (basis points, e.g., 100 = 1%)
    uint256 public marketplaceFee = 100;
    uint256 public constant MAX_FEE = 1000; // Max 10%
    address public feeRecipient;
    
    // Listing tracking
    uint256 private _listingIdCounter;
    uint256 private _offerIdCounter;
    mapping(uint256 => Listing) public listings;
    mapping(uint256 => Offer) public offers;
    
    // NFT contract => token ID => listing IDs
    mapping(address => mapping(uint256 => uint256[])) public nftListings;
    
    // NFT contract => token ID => offer IDs
    mapping(address => mapping(uint256 => uint256[])) public nftOffers;
    
    // Events
    event Listed(
        uint256 indexed listingId,
        address indexed seller,
        address indexed nftContract,
        uint256 tokenId,
        uint256 amount,
        TokenStandard standard,
        address paymentToken,
        uint256 price,
        uint256 expiresAt
    );
    
    event Sale(
        uint256 indexed listingId,
        address indexed buyer,
        address indexed seller,
        address nftContract,
        uint256 tokenId,
        uint256 amount,
        uint256 price,
        uint256 marketplaceFeeAmount,
        uint256 royaltyAmount
    );
    
    event ListingCancelled(uint256 indexed listingId);
    
    event OfferMade(
        uint256 indexed offerId,
        address indexed offerer,
        address indexed nftContract,
        uint256 tokenId,
        address paymentToken,
        uint256 offerPrice,
        uint256 expiresAt
    );
    
    event OfferAccepted(
        uint256 indexed offerId,
        address indexed seller,
        uint256 price
    );
    
    event OfferCancelled(uint256 indexed offerId);
    
    event MarketplaceFeeUpdated(uint256 newFee);
    event FeeRecipientUpdated(address newRecipient);
    
    constructor(address _feeRecipient) Ownable(msg.sender) {
        require(_feeRecipient != address(0), "Invalid fee recipient");
        feeRecipient = _feeRecipient;
    }
    
    /**
     * @dev List NFT for sale
     */
    function listNFT(
        address nftContract,
        uint256 tokenId,
        uint256 amount,
        TokenStandard standard,
        address paymentToken,
        uint256 price,
        uint256 expiresAt
    ) external nonReentrant returns (uint256) {
        require(price > 0, "Price must be greater than 0");
        require(amount > 0, "Amount must be greater than 0");
        
        if (standard == TokenStandard.ERC721) {
            require(amount == 1, "ERC721 amount must be 1");
            IERC721 nft = IERC721(nftContract);
            require(nft.ownerOf(tokenId) == msg.sender, "Not token owner");
            require(
                nft.isApprovedForAll(msg.sender, address(this)) || 
                nft.getApproved(tokenId) == address(this),
                "Marketplace not approved"
            );
        } else {
            IERC1155 nft = IERC1155(nftContract);
            require(
                nft.balanceOf(msg.sender, tokenId) >= amount,
                "Insufficient balance"
            );
            require(
                nft.isApprovedForAll(msg.sender, address(this)),
                "Marketplace not approved"
            );
        }
        
        uint256 listingId = _listingIdCounter++;
        
        listings[listingId] = Listing({
            listingId: listingId,
            seller: msg.sender,
            nftContract: nftContract,
            tokenId: tokenId,
            amount: amount,
            standard: standard,
            paymentToken: paymentToken,
            price: price,
            status: ListingStatus.Active,
            expiresAt: expiresAt
        });
        
        nftListings[nftContract][tokenId].push(listingId);
        
        emit Listed(
            listingId,
            msg.sender,
            nftContract,
            tokenId,
            amount,
            standard,
            paymentToken,
            price,
            expiresAt
        );
        
        return listingId;
    }
    
    /**
     * @dev Buy listed NFT
     */
    function buyNFT(uint256 listingId) external payable nonReentrant {
        Listing storage listing = listings[listingId];
        
        require(listing.status == ListingStatus.Active, "Listing not active");
        require(
            listing.expiresAt == 0 || block.timestamp < listing.expiresAt,
            "Listing expired"
        );
        require(msg.sender != listing.seller, "Cannot buy own listing");
        
        uint256 totalPrice = listing.price;
        
        // Handle payment
        if (listing.paymentToken == address(0)) {
            require(msg.value == totalPrice, "Incorrect payment amount");
        } else {
            require(msg.value == 0, "Should not send ETH for token payment");
            IERC20 token = IERC20(listing.paymentToken);
            require(
                token.transferFrom(msg.sender, address(this), totalPrice),
                "Payment transfer failed"
            );
        }
        
        // Calculate fees
        uint256 marketplaceFeeAmount = (totalPrice * marketplaceFee) / 10000;
        uint256 royaltyAmount = 0;
        address royaltyReceiver = address(0);
        
        // Check for royalties (EIP-2981)
        try IERC2981(listing.nftContract).royaltyInfo(listing.tokenId, totalPrice) 
            returns (address receiver, uint256 royalty) {
            royaltyReceiver = receiver;
            royaltyAmount = royalty;
        } catch {
            // No royalty support
        }
        
        uint256 sellerProceeds = totalPrice - marketplaceFeeAmount - royaltyAmount;
        
        // Transfer NFT
        if (listing.standard == TokenStandard.ERC721) {
            IERC721(listing.nftContract).safeTransferFrom(
                listing.seller,
                msg.sender,
                listing.tokenId
            );
        } else {
            IERC1155(listing.nftContract).safeTransferFrom(
                listing.seller,
                msg.sender,
                listing.tokenId,
                listing.amount,
                ""
            );
        }
        
        // Distribute payments
        if (listing.paymentToken == address(0)) {
            // Native token payments
            payable(feeRecipient).transfer(marketplaceFeeAmount);
            if (royaltyAmount > 0 && royaltyReceiver != address(0)) {
                payable(royaltyReceiver).transfer(royaltyAmount);
            }
            payable(listing.seller).transfer(sellerProceeds);
        } else {
            // ERC20 payments
            IERC20 token = IERC20(listing.paymentToken);
            require(token.transfer(feeRecipient, marketplaceFeeAmount), "Fee transfer failed");
            if (royaltyAmount > 0 && royaltyReceiver != address(0)) {
                require(token.transfer(royaltyReceiver, royaltyAmount), "Royalty transfer failed");
            }
            require(token.transfer(listing.seller, sellerProceeds), "Seller payment failed");
        }
        
        // Update listing status
        listing.status = ListingStatus.Sold;
        
        emit Sale(
            listingId,
            msg.sender,
            listing.seller,
            listing.nftContract,
            listing.tokenId,
            listing.amount,
            totalPrice,
            marketplaceFeeAmount,
            royaltyAmount
        );
    }
    
    /**
     * @dev Cancel listing
     */
    function cancelListing(uint256 listingId) external nonReentrant {
        Listing storage listing = listings[listingId];
        
        require(listing.seller == msg.sender, "Not listing owner");
        require(listing.status == ListingStatus.Active, "Listing not active");
        
        listing.status = ListingStatus.Cancelled;
        
        emit ListingCancelled(listingId);
    }
    
    /**
     * @dev Make offer on NFT
     */
    function makeOffer(
        address nftContract,
        uint256 tokenId,
        address paymentToken,
        uint256 offerPrice,
        uint256 expiresAt
    ) external nonReentrant returns (uint256) {
        require(offerPrice > 0, "Offer price must be greater than 0");
        require(paymentToken != address(0), "Must use ERC20 for offers");
        
        // Verify offerer has approved tokens
        IERC20 token = IERC20(paymentToken);
        require(
            token.allowance(msg.sender, address(this)) >= offerPrice,
            "Insufficient token allowance"
        );
        
        uint256 offerId = _offerIdCounter++;
        
        offers[offerId] = Offer({
            offerId: offerId,
            offerer: msg.sender,
            nftContract: nftContract,
            tokenId: tokenId,
            paymentToken: paymentToken,
            offerPrice: offerPrice,
            expiresAt: expiresAt,
            isActive: true
        });
        
        nftOffers[nftContract][tokenId].push(offerId);
        
        emit OfferMade(
            offerId,
            msg.sender,
            nftContract,
            tokenId,
            paymentToken,
            offerPrice,
            expiresAt
        );
        
        return offerId;
    }
    
    /**
     * @dev Accept offer (seller accepts)
     */
    function acceptOffer(uint256 offerId, TokenStandard standard) external nonReentrant {
        Offer storage offer = offers[offerId];
        
        require(offer.isActive, "Offer not active");
        require(
            offer.expiresAt == 0 || block.timestamp < offer.expiresAt,
            "Offer expired"
        );
        
        // Verify seller owns the NFT
        if (standard == TokenStandard.ERC721) {
            IERC721 nft = IERC721(offer.nftContract);
            require(nft.ownerOf(offer.tokenId) == msg.sender, "Not token owner");
            require(
                nft.isApprovedForAll(msg.sender, address(this)) || 
                nft.getApproved(offer.tokenId) == address(this),
                "Marketplace not approved"
            );
        } else {
            IERC1155 nft = IERC1155(offer.nftContract);
            require(
                nft.balanceOf(msg.sender, offer.tokenId) >= 1,
                "Insufficient balance"
            );
            require(
                nft.isApprovedForAll(msg.sender, address(this)),
                "Marketplace not approved"
            );
        }
        
        uint256 totalPrice = offer.offerPrice;
        
        // Transfer payment from offerer
        IERC20 token = IERC20(offer.paymentToken);
        require(
            token.transferFrom(offer.offerer, address(this), totalPrice),
            "Payment transfer failed"
        );
        
        // Calculate fees
        uint256 marketplaceFeeAmount = (totalPrice * marketplaceFee) / 10000;
        uint256 royaltyAmount = 0;
        address royaltyReceiver = address(0);
        
        // Check for royalties
        try IERC2981(offer.nftContract).royaltyInfo(offer.tokenId, totalPrice) 
            returns (address receiver, uint256 royalty) {
            royaltyReceiver = receiver;
            royaltyAmount = royalty;
        } catch {}
        
        uint256 sellerProceeds = totalPrice - marketplaceFeeAmount - royaltyAmount;
        
        // Transfer NFT
        if (standard == TokenStandard.ERC721) {
            IERC721(offer.nftContract).safeTransferFrom(
                msg.sender,
                offer.offerer,
                offer.tokenId
            );
        } else {
            IERC1155(offer.nftContract).safeTransferFrom(
                msg.sender,
                offer.offerer,
                offer.tokenId,
                1,
                ""
            );
        }
        
        // Distribute payments
        require(token.transfer(feeRecipient, marketplaceFeeAmount), "Fee transfer failed");
        if (royaltyAmount > 0 && royaltyReceiver != address(0)) {
            require(token.transfer(royaltyReceiver, royaltyAmount), "Royalty transfer failed");
        }
        require(token.transfer(msg.sender, sellerProceeds), "Seller payment failed");
        
        // Mark offer as inactive
        offer.isActive = false;
        
        emit OfferAccepted(offerId, msg.sender, totalPrice);
    }
    
    /**
     * @dev Cancel offer
     */
    function cancelOffer(uint256 offerId) external nonReentrant {
        Offer storage offer = offers[offerId];
        
        require(offer.offerer == msg.sender, "Not offer creator");
        require(offer.isActive, "Offer not active");
        
        offer.isActive = false;
        
        emit OfferCancelled(offerId);
    }
    
    /**
     * @dev Update marketplace fee
     */
    function setMarketplaceFee(uint256 newFee) external onlyOwner {
        require(newFee <= MAX_FEE, "Fee too high");
        marketplaceFee = newFee;
        emit MarketplaceFeeUpdated(newFee);
    }
    
    /**
     * @dev Update fee recipient
     */
    function setFeeRecipient(address newRecipient) external onlyOwner {
        require(newRecipient != address(0), "Invalid recipient");
        feeRecipient = newRecipient;
        emit FeeRecipientUpdated(newRecipient);
    }
    
    /**
     * @dev Get all active listings for an NFT
     */
    function getActiveListings(address nftContract, uint256 tokenId)
        external
        view
        returns (Listing[] memory)
    {
        uint256[] memory listingIds = nftListings[nftContract][tokenId];
        uint256 activeCount = 0;
        
        // Count active listings
        for (uint256 i = 0; i < listingIds.length; i++) {
            if (listings[listingIds[i]].status == ListingStatus.Active) {
                activeCount++;
            }
        }
        
        // Populate array
        Listing[] memory activeListings = new Listing[](activeCount);
        uint256 index = 0;
        
        for (uint256 i = 0; i < listingIds.length; i++) {
            if (listings[listingIds[i]].status == ListingStatus.Active) {
                activeListings[index] = listings[listingIds[i]];
                index++;
            }
        }
        
        return activeListings;
    }
    
    /**
     * @dev Get all active offers for an NFT
     */
    function getActiveOffers(address nftContract, uint256 tokenId)
        external
        view
        returns (Offer[] memory)
    {
        uint256[] memory offerIds = nftOffers[nftContract][tokenId];
        uint256 activeCount = 0;
        
        // Count active offers
        for (uint256 i = 0; i < offerIds.length; i++) {
            if (offers[offerIds[i]].isActive) {
                activeCount++;
            }
        }
        
        // Populate array
        Offer[] memory activeOffers = new Offer[](activeCount);
        uint256 index = 0;
        
        for (uint256 i = 0; i < offerIds.length; i++) {
            if (offers[offerIds[i]].isActive) {
                activeOffers[index] = offers[offerIds[i]];
                index++;
            }
        }
        
        return activeOffers;
    }
}
