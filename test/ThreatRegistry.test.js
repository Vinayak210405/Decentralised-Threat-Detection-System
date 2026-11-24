const { expect } = require("chai");
const { ethers } = require("hardhat");
const zk = require("../scripts/zk/lib");
const { deployRegistry } = require("../scripts/deploy_lib");

const coder = ethers.AbiCoder.defaultAbiCoder();
const signalHash = (category, severity, cid) =>
  BigInt(ethers.keccak256(coder.encode(["uint8", "uint8", "string"], [category, severity, cid]))) >> 8n;
const voteScope = (id) =>
  BigInt(ethers.keccak256(coder.encode(["string", "uint256"], ["DTDS_VOTE", id]))) >> 8n;

// A keyed IOC hash as the Python node produces it (any value below the field works here).
const IOC_A = 0x1234567890abcdefn;
const IOC_B = 0xfeedfacecafebeefn;

describe("ThreatRegistry", function () {
  let ids, members, registry;

  async function report(id, ioc, { category = 1, severity = 3, cid = "", membersList = members, root } = {}) {
    const p = await zk.prove({ secret: id.secret, members: membersList, scope: ioc,
      signalHash: signalHash(category, severity, cid) });
    return registry.submitReport(ioc, category, severity, cid, root ?? p.root, p.nullifier, p.proof);
  }

  beforeEach(async function () {
    ids = [];
    for (let i = 0; i < 3; i++) ids.push(await zk.newIdentity());
    members = ids.map((i) => i.commitment);
    ({ registry } = await deployRegistry(ethers, { members, threshold: 2, votingPeriod: 3600 }));
  });

  it("builds the same Poseidon Merkle root on-chain as off-chain", async function () {
    const tree = await zk.buildTree(members);
    expect(await registry.root()).to.equal(tree.root);
    expect(await registry.memberCount()).to.equal(3n);
  });

  it("matches the contract's signal hash", async function () {
    expect(await registry.reportSignalHash(2, 4, "bafyabc")).to.equal(signalHash(2, 4, "bafyabc"));
    expect(await registry.voteScope(7)).to.equal(voteScope(7));
  });

  it("accepts an anonymous report and counts it", async function () {
    const tx = await report(ids[0], IOC_A, { cid: "bafytest" });
    const receipt = await tx.wait();
    console.log(`      gas used by submitReport: ${receipt.gasUsed}`);
    const ind = await registry.indicators(IOC_A);
    expect(ind.reports).to.equal(1n);
    expect(ind.common).to.equal(false);
    await expect(tx).to.emit(registry, "ThreatReported");
  });

  it("rejects the same company reporting the same IOC twice (nullifier)", async function () {
    await report(ids[0], IOC_A);
    await expect(report(ids[0], IOC_A, { severity: 1 }))
      .to.be.revertedWithCustomError(registry, "NullifierAlreadyUsed");
  });

  it("lets the same company report a different IOC (unlinkable nullifiers)", async function () {
    await report(ids[0], IOC_A);
    await report(ids[0], IOC_B);
    expect((await registry.indicators(IOC_B)).reports).to.equal(1n);
  });

  it("flags a common threat once enough distinct companies report it", async function () {
    await report(ids[0], IOC_A, { severity: 2 });
    const tx = await report(ids[1], IOC_A, { severity: 4 });
    await expect(tx).to.emit(registry, "CommonThreat").withArgs(IOC_A, 2, 4);
    const tx3 = await report(ids[2], IOC_A);
    await expect(tx3).to.not.emit(registry, "CommonThreat");
    expect(await registry.commonIndicatorCount()).to.equal(1n);
    expect((await registry.indicators(IOC_A)).reports).to.equal(3n);
  });

  it("rejects a proof whose metadata was changed after proving", async function () {
    const p = await zk.prove({ secret: ids[0].secret, members, scope: IOC_A, signalHash: signalHash(1, 3, "") });
    await expect(registry.submitReport(IOC_A, 1, 4, "", p.root, p.nullifier, p.proof))
      .to.be.revertedWithCustomError(registry, "InvalidProof");
  });

  it("rejects a proof replayed for a different IOC", async function () {
    const p = await zk.prove({ secret: ids[0].secret, members, scope: IOC_A, signalHash: signalHash(1, 3, "") });
    await expect(registry.submitReport(IOC_B, 1, 3, "", p.root, p.nullifier, p.proof))
      .to.be.revertedWithCustomError(registry, "InvalidProof");
  });

  it("rejects a forged nullifier", async function () {
    const p = await zk.prove({ secret: ids[0].secret, members, scope: IOC_A, signalHash: signalHash(1, 3, "") });
    await expect(registry.submitReport(IOC_A, 1, 3, "", p.root, 12345n, p.proof))
      .to.be.revertedWithCustomError(registry, "InvalidProof");
  });

  it("rejects proofs against a tree the contract never had", async function () {
    const outsider = await zk.newIdentity();
    const fakeMembers = [...members, outsider.commitment];
    await expect(report(outsider, IOC_A, { membersList: fakeMembers }))
      .to.be.revertedWithCustomError(registry, "UnknownRoot");
  });

  it("rejects garbage proofs", async function () {
    const root = await registry.root();
    await expect(registry.submitReport(IOC_A, 1, 3, "", root, 1n, Array(8).fill(1n)))
      .to.be.reverted;
  });

  describe("governance", function () {
    it("admits a new member by anonymous majority vote", async function () {
      const newcomer = await zk.newIdentity();
      await registry.propose(0, newcomer.commitment);
      const snapshot = [...members];
      for (const id of ids.slice(0, 2)) {
        const p = await zk.prove({ secret: id.secret, members: snapshot, scope: voteScope(0), signalHash: 1n });
        await registry.vote(0, true, p.nullifier, p.proof);
      }
      await registry.execute(0);
      expect(await registry.memberCount()).to.equal(4n);
      expect(await registry.isMember(newcomer.commitment)).to.equal(true);
      // The newcomer can now report, proving against the new root.
      await report(newcomer, IOC_A, { membersList: [...members, newcomer.commitment] });
      expect((await registry.indicators(IOC_A)).reports).to.equal(1n);
    });

    it("allows only one vote per member per proposal", async function () {
      await registry.propose(1, 3);
      const p = await zk.prove({ secret: ids[0].secret, members, scope: voteScope(0), signalHash: 1n });
      await registry.vote(0, true, p.nullifier, p.proof);
      const p2 = await zk.prove({ secret: ids[0].secret, members, scope: voteScope(0), signalHash: 0n });
      await expect(registry.vote(0, false, p2.nullifier, p2.proof))
        .to.be.revertedWithCustomError(registry, "NullifierAlreadyUsed");
    });

    it("does not execute without a majority", async function () {
      await registry.propose(1, 3);
      const p = await zk.prove({ secret: ids[0].secret, members, scope: voteScope(0), signalHash: 1n });
      await registry.vote(0, true, p.nullifier, p.proof);
      await expect(registry.execute(0)).to.be.revertedWithCustomError(registry, "ProposalNotPassed");
    });

    it("rejects a vote whose choice was flipped after proving", async function () {
      await registry.propose(1, 3);
      const p = await zk.prove({ secret: ids[0].secret, members, scope: voteScope(0), signalHash: 1n });
      await expect(registry.vote(0, false, p.nullifier, p.proof))
        .to.be.revertedWithCustomError(registry, "InvalidProof");
    });

    it("changes the threshold when the vote passes", async function () {
      await registry.propose(1, 3);
      for (const id of ids.slice(0, 2)) {
        const p = await zk.prove({ secret: id.secret, members, scope: voteScope(0), signalHash: 1n });
        await registry.vote(0, true, p.nullifier, p.proof);
      }
      await registry.execute(0);
      expect(await registry.threshold()).to.equal(3n);
    });

    it("closes voting after the deadline", async function () {
      await registry.propose(1, 3);
      await ethers.provider.send("evm_increaseTime", [3601]);
      await ethers.provider.send("evm_mine", []);
      const p = await zk.prove({ secret: ids[0].secret, members, scope: voteScope(0), signalHash: 1n });
      await expect(registry.vote(0, true, p.nullifier, p.proof))
        .to.be.revertedWithCustomError(registry, "ProposalClosed");
    });
  });
});
