require("dotenv").config();
const hre = require("hardhat");

async function main() {
  const [deployer] = await hre.ethers.getSigners();
  const owner = process.env.OWNER_ADDRESS || deployer.address;

  console.log("Deploying QuantosL0Verifier...");
  console.log("Network:", hre.network.name);
  console.log("Deployer:", deployer.address);
  console.log("Owner:", owner);

  const QuantosL0Verifier = await hre.ethers.getContractFactory("QuantosL0Verifier");
  const verifier = await QuantosL0Verifier.deploy(owner);
  await verifier.waitForDeployment();
  const verifierAddress = await verifier.getAddress();

  console.log("");
  console.log("========================================");
  console.log("QuantosL0Verifier deployed!");
  console.log("Network:", hre.network.name);
  console.log("Address:", verifierAddress);
  console.log("Owner:", owner);
  console.log("========================================");

  console.log("");
  console.log("Next steps:");
  console.log("1. Register a validator set root:");
  console.log(`   npx hardhat run scripts/register-validator-set.js --network ${hre.network.name}`);
  console.log("");
  console.log("2. Verify contract on explorer:");
  console.log(`   npx hardhat verify --network ${hre.network.name} ${verifierAddress} ${owner}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
