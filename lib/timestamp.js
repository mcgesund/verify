// OpenTimestamps proofs (Bitcoin). See README, sections 6 and 7.
import { parseProof, verifyBitcoin } from './opentimestamps.js';

const b64 = (s) => Buffer.from(String(s || ''), 'base64');

// Hash (hex) that the proof refers to; null if the proof is not readable
// (then it matches nothing and the caller reports it).
export function proofDigest(proofB64) {
  try {
    return parseProof(b64(proofB64)).digest.toString('hex');
  } catch {
    return null;
  }
}

// Online against Bitcoin block headers (public block explorer). Returns
// { block, time } of the earliest confirmation, or null if the proof has no
// Bitcoin attestation yet.
export async function verifyOnline(proofB64, hashHex) {
  const proof = parseProof(b64(proofB64));
  if (proof.digest.toString('hex') !== String(hashHex).toLowerCase()) throw new Error('proof belongs to a different digest');
  return verifyBitcoin(proof);
}
