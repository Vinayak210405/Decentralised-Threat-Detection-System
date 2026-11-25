# Legacy v1 prototype

The original 2025 code, kept for reference. It is **not used** by v2 and is not maintained.

Removed when it was moved here: committed encryption keys, `node_modules/` (5,460 files), compiled circuit outputs, the 75 MB powers-of-tau file, and generated JSON outputs. They remain in git history before the v2 branch. **The old `encryption_key.key` files were public on GitHub, so treat anything encrypted with them as readable by anyone.**

Why v2 replaced each part:

| v1 | Problem | v2 |
|---|---|---|
| `zk/circuits/threat_proof.circom` proves `threshold < score` with both values private | Anyone can prove it with `score=1, threshold=0`; the proof isn't tied to any report | `circuits/membership.circom`: membership + nullifier + signal binding |
| Nullifier = `sha256(user_id + metadata + "zk_salt")` in Python | Not checked by any circuit; contract accepted any value | Nullifier computed and constrained inside the circuit |
| `verifyZKProof` is `onlyOwner` | One admin decides what is verified | Anyone can submit; the proof is verified on submission |
| `matcher/matchthreat.py` calls `matchThreat()` | Function doesn't exist in the contract | On-chain distinct-reporter count + `CommonThreat` event |
| `SequenceMatcher` similarity on metadata JSON | Compared IOC counts/timestamps, not IOCs | Exact keyed-hash matching of canonical IOCs |
| One Fernet key for all data, committed to git | Anyone could decrypt | Per-company evidence keys, never committed |
| Ingestion, alerts, governance | One-line stubs | Implemented (`dtds/extraction`, `dtds/alerts.py`, contract governance) |
