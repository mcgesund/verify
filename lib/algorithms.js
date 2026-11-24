// Signature algorithms and their verification functions from public libraries.
// Keys and signatures are raw-encoded. ML-DSA and SLH-DSA in pure mode
// (no pre-hash) with an empty context string; the purpose is the `typ`
// field inside the signed payload.
import { createPublicKey, verify as nodeVerify } from 'node:crypto';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { slh_dsa_sha2_256f } from '@noble/post-quantum/slh-dsa.js';

const SPKI_ED25519 = Buffer.from('302a300506032b6570032100', 'hex');

function ed25519(sig, msg, pub) {
  const key = createPublicKey({ key: Buffer.concat([SPKI_ED25519, Buffer.from(pub)]), format: 'der', type: 'spki' });
  return nodeVerify(null, Buffer.from(msg), key, Buffer.from(sig));
}

export const ALGORITHMS = {
  ed: { name: 'Ed25519', standard: 'RFC 8032', verify: ed25519 },
  'ml-dsa-87': { name: 'ML-DSA-87', standard: 'FIPS 204', verify: (s, m, p) => ml_dsa87.verify(s, m, p) },
  'slh-dsa-256f': { name: 'SLH-DSA-SHA2-256f', standard: 'FIPS 205', verify: (s, m, p) => slh_dsa_sha2_256f.verify(s, m, p) },
  // Retired: only in older origin stamps of QR codes. The format corresponds
  // to a pre-draft of FIPS 206 and is not verified here.
  'falcon-512': { name: 'FN-DSA-512 (Falcon)', standard: 'FIPS 206 (draft)', retired: true },
  'falcon-1024': { name: 'FN-DSA-1024 (Falcon)', standard: 'FIPS 206 (draft)', retired: true },
};

// true/false = verified; null = not verifiable (unknown or retired)
export function verifySignature(id, pubBytes, msg, sig) {
  const v = ALGORITHMS[id];
  if (!v || !v.verify) return null;
  try {
    return v.verify(new Uint8Array(sig), new Uint8Array(msg), new Uint8Array(pubBytes)) === true;
  } catch {
    return false;
  }
}
