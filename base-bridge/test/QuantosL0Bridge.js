// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("QuantosL0Bridge", function () {
    let bridge, verifier, starkVerifier, qtsToken, owner, relayer, challenger, depositor;

    const DAILY_CAP_USD = ethers.parseUnits("100000", 6); // $100K
    const CHALLENGE_WINDOW = 15 * 60; // 15 minutes
    const CHALLENGER_BOND = ethers.parseEther("0.1");
    const ESCROW_MULTIPLIER = 15000; // 150% in bps
    const BPS_DENOMINATOR = 10000;

    beforeEach(async function () {
        [owner, relayer, challenger, depositor] = await ethers.getSigners();

        // Deploy mock QTS token
        const MockERC20 = await ethers.getContractFactory("MockERC20");
        qtsToken = await MockERC20.deploy("Quantos", "QTS", 18);
        await qtsToken.waitForDeployment();

        // Deploy base verifier
        const Verifier = await ethers.getContractFactory("QuantosL0Verifier");
        verifier = await Verifier.deploy(owner.address);
        await verifier.waitForDeployment();

        // Deploy STARK verifier (already compiled as BatchAggVerifier)
        const Stark = await ethers.getContractFactory("BatchAggVerifier");
        starkVerifier = await Stark.deploy();
        await starkVerifier.waitForDeployment();

        // Deploy bridge
        const Bridge = await ethers.getContractFactory("QuantosL0Bridge");
        bridge = await Bridge.deploy(
            owner.address,
            await verifier.getAddress(),
            await starkVerifier.getAddress(),
            await qtsToken.getAddress(),
            ethers.ZeroAddress, // no oracle in test
            DAILY_CAP_USD
        );
        await bridge.waitForDeployment();

        // Register validator set in verifier
        const validatorSetRoot = ethers.randomBytes(32);
        await verifier.registerValidatorSet(validatorSetRoot, 10000, 5000);
    });

    describe("lockDeposit + acceptProofOptimistic", function () {
        it("locks ETH and accepts proof with sufficient escrow", async function () {
            const depositId = ethers.randomBytes(32);
            const proofHash = ethers.randomBytes(32);
            const amount = ethers.parseEther("1");
            const requiredEscrow = (amount * BigInt(ESCROW_MULTIPLIER)) / BigInt(BPS_DENOMINATOR);

            // User locks ETH
            await bridge.connect(depositor).lockDeposit(depositId, ethers.ZeroAddress, amount, { value: amount });

            // Relayer accepts proof with 150% escrow
            const validatorSetRoot = ethers.randomBytes(32);
            await verifier.registerValidatorSet(validatorSetRoot, 10000, 5000);

            await expect(
                bridge.connect(relayer).acceptProofOptimistic(
                    proofHash,
                    depositId,
                    validatorSetRoot,
                    6000, // signedStake
                    1,    // epoch
                    1,    // slot
                    ethers.randomBytes(32),
                    { value: requiredEscrow }
                )
            ).to.emit(bridge, "ProofAcceptedOptimistic");

            const ps = await bridge.proofs(proofHash);
            expect(ps.relayer).to.equal(relayer.address);
            expect(ps.escrow).to.equal(requiredEscrow);
            expect(ps.mevMax).to.equal(amount);
        });

        it("reverts with insufficient escrow", async function () {
            const depositId = ethers.randomBytes(32);
            const proofHash = ethers.randomBytes(32);
            const amount = ethers.parseEther("1");

            await bridge.connect(depositor).lockDeposit(depositId, ethers.ZeroAddress, amount, { value: amount });

            const validatorSetRoot = ethers.randomBytes(32);
            await verifier.registerValidatorSet(validatorSetRoot, 10000, 5000);

            await expect(
                bridge.connect(relayer).acceptProofOptimistic(
                    proofHash,
                    depositId,
                    validatorSetRoot,
                    6000,
                    1, 1,
                    ethers.randomBytes(32),
                    { value: ethers.parseEther("0.5") } // only 50%, not 150%
                )
            ).to.be.revertedWithCustomError(bridge, "InsufficientEscrow");
        });
    });

    describe("challenge + resolve", function () {
        let proofHash, depositId, amount, requiredEscrow;

        beforeEach(async function () {
            depositId = ethers.randomBytes(32);
            proofHash = ethers.randomBytes(32);
            amount = ethers.parseEther("1");
            requiredEscrow = (amount * BigInt(ESCROW_MULTIPLIER)) / BigInt(BPS_DENOMINATOR);

            await bridge.connect(depositor).lockDeposit(depositId, ethers.ZeroAddress, amount, { value: amount });

            const validatorSetRoot = ethers.randomBytes(32);
            await verifier.registerValidatorSet(validatorSetRoot, 10000, 5000);

            await bridge.connect(relayer).acceptProofOptimistic(
                proofHash,
                depositId,
                validatorSetRoot,
                6000,
                1, 1,
                ethers.randomBytes(32),
                { value: requiredEscrow }
            );
        });

        it("allows permissionless challenge with fixed bond", async function () {
            await expect(
                bridge.connect(challenger).challengeProof(proofHash, { value: CHALLENGER_BOND })
            ).to.emit(bridge, "ProofChallenged");

            const ps = await bridge.proofs(proofHash);
            expect(ps.challenged).to.be.true;
            expect(ps.challenger).to.equal(challenger.address);
            expect(ps.challengerBond).to.equal(CHALLENGER_BOND);
        });

        it("slashes relayer on invalid STARK proof (fraud confirmed)", async function () {
            await bridge.connect(challenger).challengeProof(proofHash, { value: CHALLENGER_BOND });

            // Build an invalid StarkProof that will fail verification
            const invalidProof = {
                traceRoot: ethers.zeroPadValue("0x00", 32),
                constraintRoot: ethers.zeroPadValue("0x00", 32),
                signedStake: 0,
                stakeThreshold: 0,
                signerCount: 0,
                queries: [],
                fri: { layerRoots: [], finalEvals: [], layerPaths: [] },
                powNonce: 0
            };

            const totalPayout = requiredEscrow + CHALLENGER_BOND;
            const expectedReward = (totalPayout * BigInt(8000)) / BigInt(10000);

            const balanceBefore = await ethers.provider.getBalance(challenger.address);

            await expect(bridge.connect(challenger).resolveChallenge(proofHash, invalidProof))
                .to.emit(bridge, "ChallengeResolved")
                .withArgs(proofHash, true, challenger.address, expectedReward);

            const balanceAfter = await ethers.provider.getBalance(challenger.address);
            expect(balanceAfter).to.be.gt(balanceBefore);
        });
    });

    describe("finalizeAndRelease", function () {
        let proofHash, depositId, amount, requiredEscrow;

        beforeEach(async function () {
            depositId = ethers.randomBytes(32);
            proofHash = ethers.randomBytes(32);
            amount = ethers.parseEther("1");
            requiredEscrow = (amount * BigInt(ESCROW_MULTIPLIER)) / BigInt(BPS_DENOMINATOR);

            await bridge.connect(depositor).lockDeposit(depositId, ethers.ZeroAddress, amount, { value: amount });

            const validatorSetRoot = ethers.randomBytes(32);
            await verifier.registerValidatorSet(validatorSetRoot, 10000, 5000);

            await bridge.connect(relayer).acceptProofOptimistic(
                proofHash,
                depositId,
                validatorSetRoot,
                6000,
                1, 1,
                ethers.randomBytes(32),
                { value: requiredEscrow }
            );
        });

        it("reverts if challenge window still active", async function () {
            await expect(bridge.finalizeAndRelease(proofHash))
                .to.be.revertedWithCustomError(bridge, "ChallengeWindowStillActive");
        });

        it("releases funds after challenge window expires", async function () {
            await ethers.provider.send("evm_increaseTime", [CHALLENGE_WINDOW + 1]);
            await ethers.provider.send("evm_mine");

            const balanceBefore = await ethers.provider.getBalance(relayer.address);

            await expect(bridge.finalizeAndRelease(proofHash))
                .to.emit(bridge, "ProofFinalized")
                .withArgs(proofHash, depositId, amount);

            const balanceAfter = await ethers.provider.getBalance(relayer.address);
            expect(balanceAfter).to.be.gt(balanceBefore);
        });
    });
});
