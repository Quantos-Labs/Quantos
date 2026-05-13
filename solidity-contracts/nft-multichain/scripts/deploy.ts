import { ethers } from "hardhat";

/**
 * Deployment script for multichain NFT marketplace
 * 
 * Usage:
 * npx hardhat run scripts/deploy.ts --network <network>
 * 
 * Networks: baseTestnet, arbitrumTestnet, bscTestnet, polygonTestnet, hyperevmTestnet
 */

async function main() {
  const [deployer] = await ethers.getSigners();

  const EVM_TREASURY = "0x44A9Eb810ffAFb611b4a00E6217A87ff3e762ba7";
  
  console.log("Deploying contracts with account:", deployer.address);
  console.log("Account balance:", (await ethers.provider.getBalance(deployer.address)).toString());
  
  // Configuration
  const NFT_NAME = "Quantos NFT";
  const NFT_SYMBOL = "QNFT";
  const BASE_URI = "ipfs://"; // Will be updated after IPFS setup
  const MAX_SUPPLY = 10000;
  const MINT_PRICE = ethers.parseEther("0.01"); // 0.01 ETH/native token
  const PRIMARY_SALE_RECIPIENT = EVM_TREASURY;
  const DEFAULT_ROYALTY_RECEIVER = deployer.address;
  const ROYALTY_FEE_NUMERATOR = 250; // 2.5% royalty (250 basis points)
  const MARKETPLACE_FEE_RECIPIENT = EVM_TREASURY;
  const MARKETPLACE_FEE_BPS = 100; // 1% marketplace fee
  
  // Deploy NFT Contract
  console.log("\n📦 Deploying MultichainNFT...");
  const MultichainNFT = await ethers.getContractFactory("MultichainNFT");
  const nft = await MultichainNFT.deploy(
    NFT_NAME,
    NFT_SYMBOL,
    BASE_URI,
    MAX_SUPPLY,
    MINT_PRICE,
    PRIMARY_SALE_RECIPIENT,
    DEFAULT_ROYALTY_RECEIVER,
    ROYALTY_FEE_NUMERATOR
  );
  
  await nft.waitForDeployment();
  const nftAddress = await nft.getAddress();
  console.log("✅ MultichainNFT deployed to:", nftAddress);
  
  // Deploy Marketplace Contract
  console.log("\n📦 Deploying MultichainNFTMarketplace...");
  const Marketplace = await ethers.getContractFactory("MultichainNFTMarketplace");
  const marketplace = await Marketplace.deploy(MARKETPLACE_FEE_RECIPIENT);
  
  await marketplace.waitForDeployment();
  await (await marketplace.setMarketplaceFee(MARKETPLACE_FEE_BPS)).wait();
  const marketplaceAddress = await marketplace.getAddress();
  console.log("✅ MultichainNFTMarketplace deployed to:", marketplaceAddress);
  
  // Configuration summary
  console.log("\n📋 Deployment Summary:");
  console.log("═══════════════════════════════════════");
  console.log("Network:", (await ethers.provider.getNetwork()).name);
  console.log("Chain ID:", (await ethers.provider.getNetwork()).chainId);
  console.log("Deployer:", deployer.address);
  console.log("\n🎨 NFT Contract:");
  console.log("  Address:", nftAddress);
  console.log("  Name:", NFT_NAME);
  console.log("  Symbol:", NFT_SYMBOL);
  console.log("  Max Supply:", MAX_SUPPLY);
  console.log("  Mint Price:", ethers.formatEther(MINT_PRICE), "ETH");
  console.log("  Primary Sale Recipient:", PRIMARY_SALE_RECIPIENT);
  console.log("  Royalty:", ROYALTY_FEE_NUMERATOR / 100, "%");
  console.log("  Default Royalty Fallback:", DEFAULT_ROYALTY_RECEIVER);
  console.log("  Token Royalties:", "creator wallet per minted NFT");
  console.log("\n🏪 Marketplace Contract:");
  console.log("  Address:", marketplaceAddress);
  console.log("  Fee:", Number(await marketplace.marketplaceFee()) / 100, "%");
  console.log("  Fee Recipient:", MARKETPLACE_FEE_RECIPIENT);
  console.log("═══════════════════════════════════════");
  
  // Save deployment info
  const deploymentInfo = {
    network: (await ethers.provider.getNetwork()).name,
    chainId: Number((await ethers.provider.getNetwork()).chainId),
    deployer: deployer.address,
    nft: {
      address: nftAddress,
      name: NFT_NAME,
      symbol: NFT_SYMBOL,
      maxSupply: MAX_SUPPLY,
      mintPrice: ethers.formatEther(MINT_PRICE),
      primarySaleRecipient: PRIMARY_SALE_RECIPIENT,
      defaultRoyaltyReceiver: DEFAULT_ROYALTY_RECEIVER,
      royaltyFee: ROYALTY_FEE_NUMERATOR / 100
    },
    marketplace: {
      address: marketplaceAddress,
      fee: Number(await marketplace.marketplaceFee()) / 100,
      feeRecipient: MARKETPLACE_FEE_RECIPIENT
    },
    timestamp: new Date().toISOString()
  };
  
  console.log("\n💾 Deployment info:");
  console.log(JSON.stringify(deploymentInfo, null, 2));
  
  // Verification instructions
  console.log("\n✅ Deployment complete!");
  console.log("\n📝 To verify contracts, run:");
  console.log(`npx hardhat verify --network ${(await ethers.provider.getNetwork()).name} ${nftAddress} "${NFT_NAME}" "${NFT_SYMBOL}" "${BASE_URI}" ${MAX_SUPPLY} ${MINT_PRICE} ${PRIMARY_SALE_RECIPIENT} ${DEFAULT_ROYALTY_RECEIVER} ${ROYALTY_FEE_NUMERATOR}`);
  console.log(`npx hardhat verify --network ${(await ethers.provider.getNetwork()).name} ${marketplaceAddress} ${MARKETPLACE_FEE_RECIPIENT}`);
  
  // Post-deployment setup instructions
  console.log("\n🔧 Post-deployment setup:");
  console.log("1. Enable public minting: await nft.togglePublicMint()");
  console.log("2. Add marketplace as minter: await nft.addMinter(marketplaceAddress)");
  console.log("3. Update base URI after IPFS setup: await nft.setBaseURI('ipfs://...')");
  console.log("4. Update Supabase with contract addresses");
  console.log("5. Update frontend config with contract addresses");
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
