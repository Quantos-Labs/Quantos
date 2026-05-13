import { ethers, network } from "hardhat";

async function main() {
  const [deployer] = await ethers.getSigners();
  const protocolFeeRecipient = process.env.PROTOCOL_FEE_RECIPIENT;

  if (!protocolFeeRecipient) {
    throw new Error("Missing PROTOCOL_FEE_RECIPIENT env var");
  }

  console.log("Deploying MultichainPredictionMarket");
  console.log("Network:", network.name);
  console.log("Deployer:", deployer.address);
  console.log("Balance:", (await ethers.provider.getBalance(deployer.address)).toString());
  console.log("Protocol fee recipient:", protocolFeeRecipient);

  const factory = await ethers.getContractFactory("MultichainPredictionMarket");
  const contract = await factory.deploy(deployer.address, protocolFeeRecipient);
  await contract.waitForDeployment();

  const address = await contract.getAddress();
  const chain = await ethers.provider.getNetwork();

  console.log("Contract deployed:", address);
  console.log(JSON.stringify({
    contract: address,
    network: network.name,
    chainId: Number(chain.chainId),
    deployer: deployer.address,
    protocolFeeRecipient,
    fees: {
      totalBps: 200,
      protocolBps: 50,
      lpBps: 150
    },
    supportedChains: ["base", "polygon", "bsc", "hyperliquid", "arbitrum"],
    timestamp: new Date().toISOString()
  }, null, 2));
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
