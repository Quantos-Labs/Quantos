// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

require("dotenv").config();
const hre = require("hardhat");

async function main() {
  const verifierAddress = process.env.L0_VERIFIER_ADDRESS;
  if (!verifierAddress) {
    throw new Error("L0_VERIFIER_ADDRESS env var is required");
  }

  const root = process.env.VALIDATOR_SET_ROOT;
  const totalStake = process.env.VALIDATOR_TOTAL_STAKE;
  const threshold = process.env.VALIDATOR_THRESHOLD;

  if (!root || !totalStake || !threshold) {
    throw new Error("VALIDATOR_SET_ROOT, VALIDATOR_TOTAL_STAKE, and VALIDATOR_THRESHOLD are required");
  }

  const [signer] = await hre.ethers.getSigners();
  const verifier = await hre.ethers.getContractAt("QuantosL0Verifier", verifierAddress, signer);

  console.log("Registering validator set...");
  console.log("Verifier:", verifierAddress);
  console.log("Root:", root);
  console.log("Total Stake:", totalStake);
  console.log("Threshold:", threshold);

  const tx = await verifier.registerValidatorSet(root, totalStake, threshold);
  await tx.wait();

  console.log("Validator set registered successfully!");
  console.log("Tx hash:", tx.hash);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
