// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {PoseidonT3} from "poseidon-solidity/PoseidonT3.sol";

interface IGroth16Verifier {
    function verifyProof(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[4] calldata pubSignals
    ) external view returns (bool);
}

/**
 * @title ThreatRegistry
 * @notice Anonymous threat-indicator sharing between member companies.
 *
 * - Members are identity commitments in an on-chain Poseidon Merkle tree.
 * - A member reports an indicator of compromise (IOC) by submitting only its
 *   keyed hash plus a zk-SNARK proving "I am a member" without revealing which
 *   one. The proof's nullifier is unique per (member, IOC), so one company
 *   cannot inflate the count by reporting the same IOC repeatedly.
 * - When `threshold` distinct members have reported the same IOC hash, the
 *   contract emits CommonThreat and every member node blocks/alerts on it.
 * - New members and threshold changes go through anonymous one-member-one-vote
 *   proposals that use the same membership proof.
 *
 * Nothing here stores raw indicators or company names. The IOC hash is an
 * HMAC under a consortium key, so outsiders cannot brute-force it (see README,
 * "Threat model").
 */
contract ThreatRegistry {
    uint256 public constant SNARK_SCALAR_FIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint8 public constant DEPTH = 10;
    uint8 public constant ROOT_HISTORY = 30;
    uint32 public constant MAX_MEMBERS = uint32(1) << DEPTH;

    enum ProposalKind { AddMember, SetThreshold }

    struct Indicator {
        uint32 reports;     // distinct members who reported it
        uint64 firstSeen;
        uint64 lastSeen;
        uint8 maxSeverity;  // 0..4
        bool common;        // reached the threshold
    }

    struct Proposal {
        ProposalKind kind;
        uint256 value;          // commitment for AddMember, new threshold for SetThreshold
        uint256 snapshotRoot;   // members at creation time vote; later joiners cannot
        uint32 snapshotMembers;
        uint32 yes;
        uint32 no;
        uint64 deadline;
        bool executed;
    }

    IGroth16Verifier public immutable verifier;

    // ---- Membership tree (incremental Merkle tree, Poseidon, zero leaf = 0) ----
    uint256[DEPTH] public zeros;
    uint256[DEPTH] private filledSubtrees;
    uint256 public root;
    uint32 public memberCount;
    uint256[ROOT_HISTORY] private rootHistory;
    uint8 private rootIndex;
    mapping(uint256 => bool) public isMember; // commitment => member

    // ---- Threat data ----
    uint32 public threshold;
    mapping(uint256 => Indicator) public indicators;
    mapping(uint256 => bool) public nullifierUsed;
    uint256[] public commonIndicators;
    uint256 public totalReports;

    // ---- Governance ----
    Proposal[] public proposals;
    uint64 public votingPeriod;

    event MemberAdded(uint256 indexed commitment, uint32 index, uint256 newRoot);
    event ThreatReported(uint256 indexed iocHash, uint32 reports, uint8 category, uint8 severity,
                         string evidenceCid, uint256 nullifier);
    event CommonThreat(uint256 indexed iocHash, uint32 reports, uint8 maxSeverity);
    event ProposalCreated(uint256 indexed id, ProposalKind kind, uint256 value, uint64 deadline);
    event Voted(uint256 indexed id, bool support, uint32 yes, uint32 no);
    event ProposalExecuted(uint256 indexed id);

    error UnknownRoot();
    error NullifierAlreadyUsed();
    error InvalidProof();
    error FieldOverflow();
    error AlreadyMember();
    error TreeFull();
    error BadThreshold();
    error ProposalClosed();
    error ProposalNotPassed();

    constructor(IGroth16Verifier _verifier, uint256[] memory foundingMembers, uint32 _threshold,
                uint64 _votingPeriod) {
        verifier = _verifier;
        uint256 z = 0;
        for (uint8 i = 0; i < DEPTH; i++) {
            zeros[i] = z;
            filledSubtrees[i] = z;
            z = PoseidonT3.hash([z, z]);
        }
        root = z;
        rootHistory[0] = z;
        for (uint256 i = 0; i < foundingMembers.length; i++) _insert(foundingMembers[i]);
        if (_threshold == 0) revert BadThreshold();
        threshold = _threshold;
        votingPeriod = _votingPeriod;
    }

    // ------------------------------------------------------------------ //
    // Reporting
    // ------------------------------------------------------------------ //

    /// Hash binding the report's metadata to the proof (must match the off-chain value).
    function reportSignalHash(uint8 category, uint8 severity, string calldata evidenceCid)
        public pure returns (uint256)
    {
        return uint256(keccak256(abi.encode(category, severity, evidenceCid))) >> 8;
    }

    function submitReport(
        uint256 iocHash,
        uint8 category,
        uint8 severity,
        string calldata evidenceCid,
        uint256 merkleRoot,
        uint256 nullifier,
        uint256[8] calldata proof
    ) external {
        if (iocHash >= SNARK_SCALAR_FIELD) revert FieldOverflow();
        if (!isKnownRoot(merkleRoot)) revert UnknownRoot();
        if (nullifierUsed[nullifier]) revert NullifierAlreadyUsed();
        _verify(proof, nullifier, merkleRoot, iocHash, reportSignalHash(category, severity, evidenceCid));
        nullifierUsed[nullifier] = true;

        Indicator storage ind = indicators[iocHash];
        if (ind.reports == 0) ind.firstSeen = uint64(block.timestamp);
        ind.lastSeen = uint64(block.timestamp);
        ind.reports += 1;
        if (severity > ind.maxSeverity) ind.maxSeverity = severity;
        totalReports += 1;
        emit ThreatReported(iocHash, ind.reports, category, severity, evidenceCid, nullifier);

        if (!ind.common && ind.reports >= threshold) {
            ind.common = true;
            commonIndicators.push(iocHash);
            emit CommonThreat(iocHash, ind.reports, ind.maxSeverity);
        }
    }

    function commonIndicatorCount() external view returns (uint256) {
        return commonIndicators.length;
    }

    // ------------------------------------------------------------------ //
    // Governance: anonymous one-member-one-vote
    // ------------------------------------------------------------------ //

    /// Anyone may propose; only members can vote. Spam proposals simply fail.
    function propose(ProposalKind kind, uint256 value) external returns (uint256 id) {
        if (kind == ProposalKind.SetThreshold && value == 0) revert BadThreshold();
        id = proposals.length;
        uint64 deadline = uint64(block.timestamp) + votingPeriod;
        proposals.push(Proposal(kind, value, root, memberCount, 0, 0, deadline, false));
        emit ProposalCreated(id, kind, value, deadline);
    }

    function voteScope(uint256 proposalId) public pure returns (uint256) {
        return uint256(keccak256(abi.encode("DTDS_VOTE", proposalId))) >> 8;
    }

    function vote(uint256 proposalId, bool support, uint256 nullifier, uint256[8] calldata proof)
        external
    {
        Proposal storage p = proposals[proposalId];
        if (p.executed || block.timestamp > p.deadline) revert ProposalClosed();
        if (nullifierUsed[nullifier]) revert NullifierAlreadyUsed();
        _verify(proof, nullifier, p.snapshotRoot, voteScope(proposalId), support ? 1 : 0);
        nullifierUsed[nullifier] = true;
        if (support) p.yes += 1; else p.no += 1;
        emit Voted(proposalId, support, p.yes, p.no);
    }

    /// Passes with a strict majority of the members at proposal time.
    function execute(uint256 proposalId) external {
        Proposal storage p = proposals[proposalId];
        if (p.executed) revert ProposalClosed();
        if (uint256(p.yes) * 2 <= p.snapshotMembers) revert ProposalNotPassed();
        p.executed = true;
        if (p.kind == ProposalKind.AddMember) {
            _insert(p.value);
        } else {
            threshold = uint32(p.value);
        }
        emit ProposalExecuted(proposalId);
    }

    function proposalCount() external view returns (uint256) {
        return proposals.length;
    }

    // ------------------------------------------------------------------ //
    // Internals
    // ------------------------------------------------------------------ //

    function isKnownRoot(uint256 r) public view returns (bool) {
        if (r == 0) return false;
        for (uint8 i = 0; i < ROOT_HISTORY; i++) {
            if (rootHistory[i] == r) return true;
        }
        return false;
    }

    function _verify(uint256[8] calldata p, uint256 nullifier, uint256 merkleRoot, uint256 scope,
                     uint256 signalHash) internal view {
        bool ok = verifier.verifyProof(
            [p[0], p[1]],
            [[p[2], p[3]], [p[4], p[5]]],
            [p[6], p[7]],
            [nullifier, merkleRoot, scope, signalHash]
        );
        if (!ok) revert InvalidProof();
    }

    function _insert(uint256 commitment) internal {
        if (commitment >= SNARK_SCALAR_FIELD || commitment == 0) revert FieldOverflow();
        if (isMember[commitment]) revert AlreadyMember();
        if (memberCount >= MAX_MEMBERS) revert TreeFull();
        uint32 index = memberCount;
        uint256 cur = commitment;
        uint32 idx = index;
        for (uint8 i = 0; i < DEPTH; i++) {
            if (idx & 1 == 0) {
                filledSubtrees[i] = cur;
                cur = PoseidonT3.hash([cur, zeros[i]]);
            } else {
                cur = PoseidonT3.hash([filledSubtrees[i], cur]);
            }
            idx >>= 1;
        }
        root = cur;
        rootIndex = uint8((rootIndex + 1) % ROOT_HISTORY);
        rootHistory[rootIndex] = cur;
        isMember[commitment] = true;
        memberCount = index + 1;
        emit MemberAdded(commitment, index, cur);
    }
}
