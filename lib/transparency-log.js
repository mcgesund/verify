// Verify the transparency log. See README, section 8.
//
// Merkle tree per RFC 9162 (Certificate Transparency 2.0), section 2.1:
//   leaf = sha256(0x00 ‖ entry data)
//   node = sha256(0x01 ‖ left ‖ right)
// A signed tree head states tree size and root. Inclusion proof: an entry is
// contained in this tree head. Consistency proof: a later tree head arises
// from an earlier one only by appending.
import { createHash } from 'node:crypto';
import { readEnvelope } from './envelope.js';
import { ALGORITHMS, verifySignature } from './algorithms.js';
import { proofDigest, verifyOnline } from './timestamp.js';
import { OtsError } from './opentimestamps.js';

export const ENTRY_VERSION = 1;
// imported / imported_published: review that existed before the log started,
// taken over once with its state at that time (not public / public).
const KINDS = new Set(['submitted', 'submitted_published', 'published', 'rejected', 'removed', 'hidden', 'redacted', 'imported', 'imported_published']);
const CONTRADICTS_VISIBLE = new Set(['removed', 'rejected', 'hidden', 'imported']);
// Entries that name the current redaction seal.
const NAMES_SEAL = (e) => e.kind === 'redacted' || (e.kind === 'imported_published' && Boolean(e.sealHash));

const sha256 = (...parts) => {
  const h = createHash('sha256');
  for (const t of parts) h.update(t);
  return h.digest();
};
const sha256hex = (s) => createHash('sha256').update(s, 'utf8').digest('hex');
const node = (l, r) => sha256(Buffer.from([0x01]), l, r);
const hex = (s) => Buffer.from(String(s || ''), 'hex');

// ---------------------------------------------------------------------------
// Entries and tree
// ---------------------------------------------------------------------------

// Canonical entry data, format v1. The order is part of the format.
export function canonicalEntry(e) {
  return JSON.stringify([
    ENTRY_VERSION,
    e.kind,
    new Date(e.at).toISOString(),
    e.category || null,
    e.commentDocumentId || null,
    e.firmaDocumentId || null,
    e.envelopeHash || null,
    e.sealHash || null,
    e.salt,
  ]);
}

export function leafHash(e) {
  return sha256(Buffer.from([0x00]), Buffer.from(canonicalEntry(e), 'utf8')).toString('hex');
}

const split = (n) => {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
};

export function merkleRoot(leaves) {
  if (leaves.length === 0) return sha256();
  if (leaves.length === 1) return leaves[0];
  const k = split(leaves.length);
  return node(merkleRoot(leaves.slice(0, k)), merkleRoot(leaves.slice(k)));
}

// RFC 9162, 2.1.3.2
export function verifyInclusion(index, size, leaf, proof, expected) {
  if (index >= size) return false;
  let fn = index;
  let sn = size - 1;
  let r = leaf;
  for (const p of proof) {
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      r = node(p, r);
      if (fn % 2 === 0) while (fn % 2 === 0 && fn !== 0) { fn >>= 1; sn >>= 1; }
    } else r = node(r, p);
    fn >>= 1;
    sn >>= 1;
  }
  return sn === 0 && r.equals(expected);
}

// RFC 9162, 2.1.4.2
export function verifyConsistency(size1, size2, root1, root2, proof) {
  if (size1 > size2) return false;
  if (size1 === size2) return proof.length === 0 && root1.equals(root2);
  if (size1 === 0) return proof.length === 0;
  let path = proof.slice();
  if (path.length === 0) return false;
  if ((size1 & (size1 - 1)) === 0) path = [root1, ...path];
  let fn = size1 - 1;
  let sn = size2 - 1;
  while (fn % 2 === 1) { fn >>= 1; sn >>= 1; }
  let fr = path[0];
  let sr = path[0];
  for (const c of path.slice(1)) {
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      fr = node(c, fr);
      sr = node(c, sr);
      if (fn % 2 === 0) while (fn % 2 === 0 && fn !== 0) { fn >>= 1; sn >>= 1; }
    } else sr = node(sr, c);
    fn >>= 1;
    sn >>= 1;
  }
  return fr.equals(root1) && sr.equals(root2) && sn === 0;
}

// ---------------------------------------------------------------------------
// Fetching
// ---------------------------------------------------------------------------

// Fetching that respects the rate limit: on 429 the tool waits as long as the
// server states in Retry-After (at most 2 minutes, 3 attempts).
export async function fetchJson(url, { attempts = 3, log = () => {} } = {}) {
  for (let i = 1; ; i++) {
    const res = await fetch(url, { headers: { accept: 'application/json' } });
    if (res.status === 429 && i < attempts) {
      const s = Math.min(Math.max(Number(res.headers.get('retry-after')) || 10, 1), 120);
      log(`Rate limit reached, waiting ${s} s …`);
      await new Promise((r) => setTimeout(r, s * 1000));
      continue;
    }
    if (!res.ok) throw new Error(`HTTP ${res.status} for ${url}`);
    return res.json();
  }
}

// ---------------------------------------------------------------------------
// Signed tree head
// ---------------------------------------------------------------------------

// Verifies signatures and content of a tree head. Returns a list of
// [kind, text] pairs. `keys` is the key directory (Map kid → entry).
export function verifyTreeHead(treeHead, keys) {
  const out = [];
  const u = readEnvelope(treeHead.envelope);
  if (!u.ok) return [['error', `Tree head ${treeHead.treeSize}: envelope not readable (${u.reason})`]];
  const p = u.payload;
  if (p.typ !== 'tlog-root') out.push(['error', `Tree head ${treeHead.treeSize}: wrong type ${p.typ}`]);
  if (p.n !== treeHead.treeSize || String(p.r || '').toLowerCase() !== String(treeHead.rootHash).toLowerCase()) {
    out.push(['error', `Tree head ${treeHead.treeSize}: details do not match the signed content`]);
  }
  const sigs = [['ed', p.kid, u.edSig], ...u.sigs.map((s) => [s.algorithm, s.kid, s.sig])];
  for (const v of Array.isArray(p.pv) ? p.pv : []) {
    if (!u.sigs.some((s) => s.algorithm === v)) out.push(['error', `Tree head ${treeHead.treeSize}: signature ${v} declared but missing`]);
  }
  for (const [algorithm, kid, sig] of sigs) {
    const name = ALGORITHMS[algorithm]?.name || algorithm;
    const d = keys.get(kid);
    if (!d) { out.push(['error', `Tree head ${treeHead.treeSize}: key ${kid} not in the key directory`]); continue; }
    if (d.revoked && d.revokedReason !== 'superseded' && (!d.revokedAt || Date.parse(d.revokedAt) <= Date.parse(treeHead.signedAt))) {
      out.push(['error', `Tree head ${treeHead.treeSize}: key ${kid} was revoked at signing time`]);
      continue;
    }
    const r = verifySignature(algorithm, Buffer.from(d.publicKey, 'base64'), u.payloadBytes, sig);
    if (r === true) out.push(['ok', `Tree head ${treeHead.treeSize}: signature ${name} valid`]);
    else if (r === false) out.push(['error', `Tree head ${treeHead.treeSize}: signature ${name} invalid`]);
    else out.push(['note', `Tree head ${treeHead.treeSize}: method ${algorithm} cannot be checked`]);
  }
  return out;
}

async function verifyTreeHeadAnchor(treeHead, online) {
  const a = treeHead.anchor || {};
  if (a.status !== 'anchored' || !a.otsProof) return [['note', `Tree head ${treeHead.treeSize}: not yet anchored in Bitcoin`]];
  if (proofDigest(a.otsProof) !== sha256hex(treeHead.envelope)) return [['error', `Tree head ${treeHead.treeSize}: Bitcoin proof does not belong to this tree head`]];
  if (!online) return [['ok', `Tree head ${treeHead.treeSize}: Bitcoin proof matches (block #${a.btcBlock}, checked offline)`]];
  try {
    const r = await verifyOnline(a.otsProof, sha256hex(treeHead.envelope));
    if (!r) return [['error', `Tree head ${treeHead.treeSize}: Bitcoin confirmation not found online`]];
    return [['ok', `Tree head ${treeHead.treeSize}: in Bitcoin block #${r.block} (${r.time})`]];
  } catch (e) {
    if (e instanceof OtsError) return [['error', `Tree head ${treeHead.treeSize}: Bitcoin proof invalid (${e.message})`]];
    return [['note', `Tree head ${treeHead.treeSize}: online check not possible (${e.message})`]];
  }
}

// ---------------------------------------------------------------------------
// One review in the log
// ---------------------------------------------------------------------------

// Is this review in the log, and do the entries match its envelope and
// redaction seal?
// `proof`: an already saved answer of the log API (e.g. a file passed with
// --log-proof) — checked exactly like a fresh one, without network access.
export async function verifyReviewInLog(pkg, { api, keys, online = false, log, proof = null } = {}) {
  const out = [];
  const id = pkg.comment;
  if (!/^[a-z0-9]{10,64}$/i.test(String(id || ''))) return [['note', 'Package names no review ID, log cannot be checked']];
  const d = proof || (await fetchJson(`${api}/proof/${encodeURIComponent(id)}`, { log }));
  const pending = Number(d.pending) || 0;
  if (!d.root || !d.entries?.length) {
    if (pending) return [['note', `${pending} entr${pending === 1 ? 'y' : 'ies'} not yet in a signed tree head (hourly)`]];
    return [['note', `No entries: review not in the log (log started ${String(d.logStart || '?').slice(0, 10)}; reviews existing then were taken over)`]];
  }
  out.push(...verifyTreeHead(d.root, keys));
  const expected = hex(d.root.rootHash);
  const envelopeHash = sha256hex(pkg.envelope);
  for (const { entry: e, inclusionProof } of d.entries) {
    const name = `Entry ${e.index} (${e.kind}${e.category ? `, ${e.category}` : ''})`;
    if (!KINDS.has(e.kind)) out.push(['error', `${name}: unknown kind`]);
    if (e.commentDocumentId !== id) out.push(['error', `${name}: belongs to a different review`]);
    if (leafHash(e) !== e.leafHash) { out.push(['error', `${name}: does not match its details`]); continue; }
    if (!verifyInclusion(e.index, d.root.treeSize, hex(e.leafHash), inclusionProof.map(hex), expected)) {
      out.push(['error', `${name}: not included in signed tree head ${d.root.treeSize}`]);
      continue;
    }
    if (e.envelopeHash && e.envelopeHash !== envelopeHash) out.push(['error', `${name}: names a different envelope`]);
    else out.push(['ok', `${name} of ${String(e.at).slice(0, 10)} included in tree head ${d.root.treeSize}`]);
  }
  const seal = pkg.attestation?.redaction?.envelope;
  const redaction = [...d.entries].reverse().find((x) => NAMES_SEAL(x.entry));
  if (seal && redaction) {
    if (redaction.entry.sealHash === sha256hex(seal)) out.push(['ok', 'Latest redaction in the log names exactly this seal']);
    else if (!pending) out.push(['error', 'Latest redaction in the log names a different seal']);
  } else if (seal && !pending) out.push(['note', 'Redaction not in the log (redacted before it started?)']);
  if (d.entries.some((x) => x.entry.kind.startsWith('imported'))) {
    out.push(['note', 'Review existed before the log started and was taken over with its state at that time; its submission time is proven by its own Bitcoin proof']);
  }
  const latest = d.entries[d.entries.length - 1].entry;
  if (!pending && CONTRADICTS_VISIBLE.has(latest.kind)) {
    out.push(['note', `Latest entry is "${latest.kind}" — if the review is still publicly visible, that contradicts the log`]);
  }
  if (pending) out.push(['note', `${pending} newer entr${pending === 1 ? 'y follows' : 'ies follow'} in the next signed tree head`]);
  out.push(...(await verifyTreeHeadAnchor(d.root, online)));
  return out;
}

// ---------------------------------------------------------------------------
// Whole log
// ---------------------------------------------------------------------------

// Verify all signed tree heads and link each two consecutive ones by a
// consistency proof. With `full`, additionally load all entries, recompute
// every leaf and build the latest root ourselves.
export async function verifyLog({ api, keys, online = false, full = false, log } = {}) {
  const out = [];
  const { roots } = await fetchJson(`${api}/roots?limit=200`, { log });
  if (!roots?.length) return [['note', 'No signed tree head yet']];
  const treeHeads = [...roots].sort((a, b) => a.treeSize - b.treeSize);
  if (roots.length === 200) out.push(['note', 'Only the latest 200 tree heads checked']);
  for (const s of treeHeads) out.push(...verifyTreeHead(s, keys));
  for (let i = 1; i < treeHeads.length; i++) {
    const a = treeHeads[i - 1];
    const b = treeHeads[i];
    const k = await fetchJson(`${api}/consistency?from=${a.treeSize}&to=${b.treeSize}`, { log });
    const ok = k.from?.rootHash === a.rootHash && k.to?.rootHash === b.rootHash &&
      verifyConsistency(a.treeSize, b.treeSize, hex(a.rootHash), hex(b.rootHash), (k.proof || []).map(hex));
    out.push(ok
      ? ['ok', `Tree head ${b.treeSize} extends tree head ${a.treeSize} (append-only)`]
      : ['error', `Tree head ${b.treeSize} does NOT extend tree head ${a.treeSize}: entries removed or rewritten`]);
  }
  for (const s of treeHeads) out.push(...(await verifyTreeHeadAnchor(s, online)));

  if (full) {
    const latest = treeHeads[treeHeads.length - 1];
    const leaves = [];
    let erased = 0;
    for (let from = 0; from < latest.treeSize; ) {
      const { entries } = await fetchJson(`${api}/entries?from=${from}&limit=500`, { log });
      if (!entries?.length) break;
      for (const e of entries) {
        if (e.index !== leaves.length) { out.push(['error', `Entry ${e.index}: gap in the sequence`]); return out; }
        if (e.erased) erased++;
        else if (leafHash(e) !== e.leafHash) out.push(['error', `Entry ${e.index}: does not match its details`]);
        leaves.push(hex(e.leafHash));
      }
      from += entries.length;
    }
    const own = merkleRoot(leaves.slice(0, latest.treeSize));
    if (leaves.length < latest.treeSize) out.push(['error', `Only ${leaves.length} of ${latest.treeSize} entries retrievable`]);
    else if (own.equals(hex(latest.rootHash))) {
      out.push(['ok', `All ${latest.treeSize} entries recomputed, root matches tree head ${latest.treeSize}${erased ? ` (${erased} erased on request, leaf kept)` : ''}`]);
    } else out.push(['error', `Self-computed root differs from tree head ${latest.treeSize}`]);
  }
  return out;
}
