// Tests: test vectors, example packages, tampered packages.
import fs from 'node:fs';
import { verifyPackage } from '../lib/verify.js';
import { verifySignature } from '../lib/algorithms.js';
import { decode, encode } from 'cbor-x';
import { createHash } from 'node:crypto';
import { leafHash, merkleRoot, verifyInclusion, verifyConsistency, verifyTreeHead, verifyReviewInLog } from '../lib/transparency-log.js';

// Removes all PQ signatures from a v4 envelope; the Ed25519 signature
// stays valid because it only covers the payload bytes.
const withoutPqSignatures = (envelope) => {
  const raw = Buffer.from(envelope.slice(5).replace(/-/g, '+').replace(/_/g, '/'), 'base64');
  const arr = decode(raw);
  arr[3] = [];
  return 'MCG1:' + Buffer.from(encode(arr)).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};

let failed = 0;
const check = (condition, text) => {
  console.log(`${condition ? 'ok  ' : 'FAIL'} ${text}`);
  if (!condition) failed += 1;
};
const load = (p) => JSON.parse(fs.readFileSync(new URL(p, import.meta.url), 'utf8'));
const b64 = (s) => Buffer.from(s, 'base64');
const errorCount = (findings) => findings.filter((f) => f.kind === 'error').length;

for (const v of load('./test-vectors.json').vectors) {
  check(verifySignature(v.algorithm, b64(v.publicKey), b64(v.message), b64(v.signature)) === true, `Test vector ${v.algorithm}`);
  const broken = b64(v.signature); broken[10] ^= 1;
  check(verifySignature(v.algorithm, b64(v.publicKey), b64(v.message), broken) === false, `Test vector ${v.algorithm} tampered is rejected`);
}

// Demo files (examples/generate.js). Their OpenTimestamps proofs may still be
// pending; the tool then only gives a note for the Bitcoin anchor. To keep the
// proof-to-data check strict either way, the cases below also run with the
// anchor status forced to "anchored".
const keys = load('../examples/demo-keys.json');
const anchored = (p) => { if (p.attestation.commentAnchor) p.attestation.commentAnchor.status = 'anchored'; return p; };
const keysAnchored = structuredClone(keys);
for (const k of keysAnchored.keys) if (k.anchor?.otsProof) k.anchor.status = 'anchored';
const anchorsOk = (findings) => findings
  .filter((f) => f.section === 'Timestamp' || f.section === 'Keys')
  .every((f) => f.kind === 'ok' || (f.kind === 'note' && /not yet anchored|only checked offline/.test(f.text)));
for (const name of ['unchanged', 'redacted', 'in-log']) {
  const pkg = load(`../examples/package-${name}.json`);
  const findings = await verifyPackage(pkg, { keys });
  check(errorCount(findings) === 0, `Example ${name}: no errors`);
  check(anchorsOk(findings), `Example ${name}: Bitcoin anchors confirmed or pending (note)`);
  check(errorCount(await verifyPackage(anchored(structuredClone(pkg)), { keys: keysAnchored })) === 0,
    `Example ${name}: OTS proofs belong to the envelope and the keys`);
  if (name === 'in-log') continue;

  const cases = {
    'hearts changed': (p) => { p.record.AverageRating = 1; },
    'text changed': (p) => { p.record.Content += ' (changed)'; },
    'geo status changed': (p) => { p.record.geoVerified = !p.record.geoVerified; },
    'PQ signature removed from envelope': (p) => { p.envelope = withoutPqSignatures(p.envelope); },
    'Bitcoin proof swapped': (p) => { anchored(p); p.attestation.commentAnchor.otsProof = keys.keys[0].anchor.otsProof; },
    'redaction seal removed': (p) => { if (!p.attestation.redaction) p.record.Content += 'x'; p.attestation.redaction = null; },
  };
  for (const [caseName, tamper] of Object.entries(cases)) {
    const p = structuredClone(pkg);
    tamper(p);
    check(errorCount(await verifyPackage(p, { keys })) > 0, `Example ${name}, ${caseName}: is detected`);
  }
}

// Transparency log: Merkle tree per RFC 9162 / 6962
{
  const leaf = (d) => createHash('sha256').update(Buffer.concat([Buffer.from([0]), d])).digest();
  const ref = ['', '00', '10', '2021', '3031', '40414243', '5051525354555657', '606162636465666768696a6b6c6d6e6f'].map((h) => leaf(Buffer.from(h, 'hex')));
  check(merkleRoot(ref).toString('hex') === '5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328', 'Log: reference root RFC 6962');

  // Generate proofs per RFC 9162 (test only) and verify them.
  const split = (n) => { let k = 1; while (k * 2 < n) k *= 2; return k; };
  const inclusion = (m, d) => {
    if (d.length === 1) return [];
    const k = split(d.length);
    return m < k ? [...inclusion(m, d.slice(0, k)), merkleRoot(d.slice(k))] : [...inclusion(m - k, d.slice(k)), merkleRoot(d.slice(0, k))];
  };
  const sub = (m, d, b) => {
    if (m === d.length) return b ? [] : [merkleRoot(d)];
    const k = split(d.length);
    return m <= k ? [...sub(m, d.slice(0, k), b), merkleRoot(d.slice(k))] : [...sub(m - k, d.slice(k), false), merkleRoot(d.slice(0, k))];
  };
  const all = Array.from({ length: 24 }, (_, i) => leaf(Buffer.from(`entry-${i}`)));
  let ok1 = true, ok2 = true, rejected = true;
  for (let n = 1; n <= all.length; n++) {
    const d = all.slice(0, n);
    const w = merkleRoot(d);
    for (let m = 0; m < n; m++) {
      if (!verifyInclusion(m, n, d[m], inclusion(m, d), w)) ok1 = false;
      if (n > 1 && verifyInclusion(m, n, leaf(Buffer.from('foreign')), inclusion(m, d), w)) rejected = false;
    }
    for (let m = 1; m <= n; m++) {
      const proof = m === n ? [] : sub(m, d, true);
      if (!verifyConsistency(m, n, merkleRoot(all.slice(0, m)), w, proof)) ok2 = false;
      if (m < n && verifyConsistency(m, n, merkleRoot([leaf(Buffer.from('x')), ...all.slice(1, m)]), w, proof)) rejected = false;
    }
  }
  check(ok1, 'Log: inclusion proofs for all sizes up to 24');
  check(ok2, 'Log: consistency proofs for all sizes up to 24');
  check(rejected, 'Log: foreign leaves and rewritten prefixes are rejected');

  // Example: review with entries in a signed tree head (offline,
  // server response from examples/log-proof.json).
  const kids = new Map(keys.keys.map((k) => [k.kid, k]));
  const logProof = load('../examples/log-proof.json');
  const pkg = load('../examples/package-in-log.json');
  const withResponse = async (response, fn) => {
    const original = globalThis.fetch;
    globalThis.fetch = async () => new Response(JSON.stringify(response), { status: 200 });
    try { return await fn(); } finally { globalThis.fetch = original; }
  };
  const errorsIn = (list) => list.filter(([kind]) => kind === 'error').length;
  check(verifyTreeHead(logProof.root, kids).every(([kind]) => kind === 'ok'), 'Log: tree head validly signed with Ed25519 and ML-DSA-87');
  const run = (response, p = pkg) => withResponse(response, () => verifyReviewInLog(p, { api: 'http://test', keys: kids }));
  check(errorsIn(await run(logProof)) === 0, 'Log: example review included in tree head, no errors');
  const cases = {
    'reason of an entry changed': (n) => { n.entries[0].entry.category = 'policy_violation'; },
    'entry with foreign leaf': (n) => { n.entries[1].entry.salt = '00'.repeat(16); n.entries[1].entry.leafHash = 'ab'.repeat(32); },
    'root of tree head changed': (n) => { n.root.rootHash = 'cd'.repeat(32); },
    'inclusion proof truncated': (n) => { n.entries[0].inclusionProof.pop(); },
    'redaction names a different seal': (n) => { n.entries.at(-1).entry.sealHash = 'ef'.repeat(32); },
  };
  for (const [caseName, tamper] of Object.entries(cases)) {
    const n = structuredClone(logProof);
    tamper(n);
    check(errorsIn(await run(n)) > 0, `Log, ${caseName}: is detected`);
  }
  // Bitcoin proof of the tree head (status forced to "anchored" while pending).
  const treeHeadAnchored = (n) => { n.root.anchor.status = 'anchored'; return n; };
  check(errorsIn(await run(treeHeadAnchored(structuredClone(logProof)))) === 0, 'Log: OTS proof belongs to the tree head');
  {
    const n = treeHeadAnchored(structuredClone(logProof));
    n.root.anchor.otsProof = keys.keys[0].anchor.otsProof;
    check(errorsIn(await run(n)) > 0, 'Log, Bitcoin proof of tree head swapped: is detected');
  }
  const other = structuredClone(pkg);
  other.envelope = load('../examples/package-unchanged.json').envelope;
  check(errorsIn(await run(logProof, other)) > 0, 'Log, entries for a different envelope: is detected');
}

// Domain separation: a validly signed envelope of another type is rejected
{
  const keys = load('../examples/demo-keys.json');
  const pkg = load('../examples/package-unchanged.json');
  const notAReview = (f) => f.some((x) => x.kind === 'error' && /not a review/.test(x.text));
  check(!notAReview(await verifyPackage(pkg, { keys })), 'Envelope type rev-comment: accepted');
  // A genuinely signed tree head (typ tlog-root) passed off as the review
  const swapped = structuredClone(pkg);
  swapped.envelope = load('../examples/log-proof.json').root.envelope;
  check(notAReview(await verifyPackage(swapped, { keys })), 'Signed tree head passed off as a review: is detected');
}

// Imported reviews (existed before the log started). Small single-leaf logs
// built here; their tree heads are not signed, so only the entry checks count.
{
  const keys = load('../examples/demo-keys.json');
  const kids = new Map(keys.keys.map((k) => [k.kid, k]));
  const logProof = load('../examples/log-proof.json');
  const withResponse = async (response, fn) => {
    const original = globalThis.fetch;
    globalThis.fetch = async () => new Response(JSON.stringify(response), { status: 200 });
    try { return await fn(); } finally { globalThis.fetch = original; }
  };
  const redactedPkg = load('../examples/package-redacted.json');
  const seal = redactedPkg.attestation.redaction.envelope;
  const sha = (s) => createHash('sha256').update(s).digest('hex');
  const logFor = (entries) => {
    const leaves = entries.map((e) => Buffer.from(leafHash(e), 'hex'));
    const root = merkleRoot(leaves).toString('hex');
    return { root: { treeSize: entries.length, rootHash: root, envelope: logProof.root.envelope, anchor: {} }, pending: 0,
      entries: entries.map((e, i) => ({ entry: { ...e, index: i, leafHash: leafHash(e) }, inclusionProof: entries.length === 1 ? [] : (i === 0 ? [leaves[1].toString('hex')] : [leaves[0].toString('hex')]) })) };
  };
  const base = { at: '2026-11-24T12:00:00.000Z', commentDocumentId: redactedPkg.comment, firmaDocumentId: 'demo-firma', envelopeHash: sha(redactedPkg.envelope), salt: 'ab'.repeat(16) };
  const structural = /not included|does not match its details|belongs to a different review/;
  const texts = async (log) => (await withResponse(log, () => verifyReviewInLog(redactedPkg, { api: 'http://test', keys: kids }))).map(([k, t]) => `${k} ${t}`);
  const pub = await texts(logFor([{ ...base, kind: 'imported_published', category: null, sealHash: sha(seal) }]));
  check(!pub.some((t) => structural.test(t) || /unknown kind|different envelope|different seal/.test(t)) && pub.some((t) => /^ok Latest redaction in the log names exactly this seal/.test(t)),
    'Log: imported_published with redaction seal accepted');
  check(pub.some((t) => /existed before the log started/.test(t)), 'Log: imported review is pointed out');
  const wrongSeal = await texts(logFor([{ ...base, kind: 'imported_published', category: null, sealHash: 'ef'.repeat(32) }]));
  check(wrongSeal.some((t) => /^error Latest redaction in the log names a different seal/.test(t)), 'Log: imported_published with a different seal: is detected');
  const removed = await texts(logFor([{ ...base, kind: 'imported', category: null, sealHash: null }, { ...base, kind: 'removed', category: 'not_recorded', sealHash: null }]));
  check(!removed.some((t) => structural.test(t) || /unknown kind/.test(t)) && removed.some((t) => /Latest entry is "removed"/.test(t)), 'Log: imported + removed (not_recorded) read correctly');
}

// --log-proof: the saved log proof is checked offline via verifyPackage
{
  const keys = load('../examples/demo-keys.json');
  const pkg = load('../examples/package-in-log.json');
  const logProof = load('../examples/log-proof.json');
  const errors = (f) => f.filter((x) => x.kind === 'error').length;
  check(errors(await verifyPackage(pkg, { keys, logProof })) === 0, 'Log proof file: review included, no errors');
  check(errors(await verifyPackage(load('../examples/package-unchanged.json'), { keys, logProof })) > 0, 'Log proof file of a different review: is detected');
}

// OpenTimestamps: own parser and Bitcoin check (no network: the block
// explorer is simulated with a block whose Merkle root is the proof's result)
{
  const ots = await import('../lib/opentimestamps.js');
  const throwsOts = (f) => { try { f(); return false; } catch (e) { return e instanceof ots.OtsError; } };
  const demo = Buffer.from(load('../examples/package-unchanged.json').attestation.commentAnchor.otsProof, 'base64');
  check(ots.writeProof(ots.parseProof(demo)).equals(demo), 'OTS: proof read and written back byte for byte');
  check(throwsOts(() => ots.parseProof(demo.subarray(0, demo.length - 3))), 'OTS: truncated proof is rejected');
  check(throwsOts(() => ots.parseProof(Buffer.concat([demo, Buffer.from([0])]))), 'OTS: trailing data is rejected');
  check(throwsOts(() => ots.parseProof(Buffer.from('not a proof'))), 'OTS: other file is rejected');

  const digest = createHash('sha256').update('demo').digest();
  const proof = { digest, timestamp: { msg: digest, attestations: [], ops: [] } };
  const leaf = ots.addOp(ots.addOp(proof.timestamp, 'prepend', Buffer.from('tx-prefix')), 'sha256');
  leaf.attestations.push({ type: 'bitcoin', height: 900000 });
  const header = Buffer.alloc(80);
  leaf.msg.copy(header, 36);
  header.writeUInt32LE(1750000000, 68);
  const dsha = (b) => createHash('sha256').update(createHash('sha256').update(b).digest()).digest();
  const blockHash = Buffer.from(dsha(header)).reverse().toString('hex');
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url) => {
    const body = url.endsWith('/block-height/900000') ? blockHash : url.endsWith(`/block/${blockHash}/header`) ? header.toString('hex') : null;
    return { ok: body !== null, status: body ? 200 : 404, text: async () => body };
  };
  try {
    const r = await ots.verifyBitcoin(ots.parseProof(ots.writeProof(proof)));
    check(r?.block === 900000 && r.time === new Date(1750000000 * 1000).toISOString(), 'OTS: Bitcoin attestation confirmed by the block header');
    leaf.attestations[0].height = 900000;
    proof.timestamp.ops[0].arg = Buffer.from('tx-prefiX');
    let rejected = false;
    try { await ots.verifyBitcoin(ots.parseProof(ots.writeProof(proof))); } catch (e) { rejected = e instanceof ots.OtsError; }
    check(rejected, 'OTS: forged operation on the Bitcoin path is detected');
  } finally {
    globalThis.fetch = realFetch;
  }
}

console.log(failed ? `\n${failed} test(s) failed` : '\nAll tests passed');
process.exit(failed ? 1 : 0);
