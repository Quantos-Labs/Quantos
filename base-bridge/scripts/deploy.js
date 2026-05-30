require("dotenv").config();
const hre = require("hardhat");

async function main() {
  const quantosChainIdRaw = process.env.QUANTOS_CHAIN_ID;
  if (!quantosChainIdRaw) {
    throw new Error("QUANTOS_CHAIN_ID is required");
  }

  const [deployer] = await hre.ethers.getSigners();
  const owner = process.env.OWNER_ADDRESS || deployer.address;
  const relayer = process.env.RELAYER_ADDRESS || owner;
  const quantosChainId = BigInt(quantosChainIdRaw);

  console.log("Deployer:", deployer.address);
  console.log("Owner:", owner);
  console.log("Relayer:", relayer);
  console.log("Quantos chain id:", quantosChainId.toString());

  const WrappedQTEST = await hre.ethers.getContractFactory("WrappedQTEST");
  const wrapped = await WrappedQTEST.deploy(deployer.address);
  await wrapped.waitForDeployment();
  const wrappedAddress = await wrapped.getAddress();

  const BaseBridgeGateway = await hre.ethers.getContractFactory("BaseBridgeGateway");
  const gateway = await BaseBridgeGateway.deploy(wrappedAddress, deployer.address, quantosChainId);
  await gateway.waitForDeployment();
  const gatewayAddress = await gateway.getAddress();

  await (await wrapped.setBridgeGateway(gatewayAddress)).wait();
  await (await gateway.setRelayer(relayer, true)).wait();

  if (owner.toLowerCase() !== deployer.address.toLowerCase()) {
    await (await wrapped.transferOwnership(owner)).wait();
    await (await gateway.transferOwnership(owner)).wait();
  }

  console.log(JSON.stringify({
    wrappedQTEST: wrappedAddress,
    baseBridgeGateway: gatewayAddress,
    owner,
    relayer,
    quantosChainId: quantosChainId.toString()
  }, null, 2));
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
