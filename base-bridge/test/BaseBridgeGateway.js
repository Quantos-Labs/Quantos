// Copyright (c) 2026 Quantos Labs SAS
// SPDX-License-Identifier: BUSL-1.1
// See the LICENSE file in the project root for the full license text.

const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("Base bridge flow", function () {
  async function deployFixture() {
    const [owner, relayer, user] = await ethers.getSigners();

    const WrappedQTEST = await ethers.getContractFactory("WrappedQTEST");
    const wrapped = await WrappedQTEST.deploy(owner.address);
    await wrapped.waitForDeployment();

    const BaseBridgeGateway = await ethers.getContractFactory("BaseBridgeGateway");
    const gateway = await BaseBridgeGateway.deploy(await wrapped.getAddress(), owner.address, 1337);
    await gateway.waitForDeployment();

    await wrapped.connect(owner).setBridgeGateway(await gateway.getAddress());
    await gateway.connect(owner).setRelayer(relayer.address, true);

    return { owner, relayer, user, wrapped, gateway };
  }

  it("allows an authorized relayer to mint once per Quantos deposit id", async function () {
    const { relayer, user, wrapped, gateway } = await deployFixture();
    const depositId = ethers.zeroPadValue("0x1234", 32);
    const quantosSender = ethers.zeroPadValue("0xabcd", 32);
    const amount = ethers.parseEther("25");

    await expect(
      gateway.connect(relayer).mintFromQuantos(depositId, 7, quantosSender, user.address, amount)
    )
      .to.emit(gateway, "QuantosDepositMinted")
      .withArgs(depositId, 7, user.address, amount, quantosSender);

    expect(await wrapped.balanceOf(user.address)).to.equal(amount);

    await expect(
      gateway.connect(relayer).mintFromQuantos(depositId, 7, quantosSender, user.address, amount)
    ).to.be.revertedWithCustomError(gateway, "DepositAlreadyProcessed");
  });

  it("burns wrapped tokens for a Quantos recipient and emits a bridge event", async function () {
    const { relayer, user, wrapped, gateway } = await deployFixture();
    const depositId = ethers.zeroPadValue("0x5678", 32);
    const quantosSender = ethers.zeroPadValue("0xbeef", 32);
    const quantosRecipient = ethers.zeroPadValue("0xcafe", 32);
    const amount = ethers.parseEther("10");

    await gateway.connect(relayer).mintFromQuantos(depositId, 11, quantosSender, user.address, amount);
    await wrapped.connect(user).approve(await gateway.getAddress(), amount);

    await expect(gateway.connect(user).burnToQuantos(quantosRecipient, amount))
      .to.emit(gateway, "BaseBurnInitiated")
      .withArgs(0, user.address, quantosRecipient, amount, 1337);

    expect(await wrapped.balanceOf(user.address)).to.equal(0);
  });
});
