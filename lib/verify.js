// Verifies a verification package. Returns a list of findings:
//   { kind: 'ok' | 'error' | 'note', section, text }
// See README for the rules.
import { createHash } from 'node:crypto';
import { readEnvelope } from './envelope.js';
import { recordHash, sha256hex, RULE_VERSION } from './record-hash.js';
import { ALGORITHMS, verifySignature } from './algorithms.js';
import { proofDigest, verifyOnline } from './timestamp.js';
import { OtsError } from './opentimestamps.js';
import { verifyReviewInLog, fetchJson } from './transparency-log.js';

const b64 = (s) => Buffer.from(s, 'base64');

export async function verifyPackage(pkg, { keys = null, online = false, api = null, keyDirectoryUrl = null, logProof = null, log } = {}) {
  const findings = [];
  let section = 'Review';
  const ok = (text) => findings.push({ kind: 'ok', section, text });
  const error = (text) => findings.push({ kind: 'error', section, text });
  const note = (text) => findings.push({ kind: 'note', section, text });

  if (pkg?.type !== 'mcgesund-verification-package') {
    error('File is not a McGesund verification package');
    return findings;
  }
  const att = pkg.attestation || {};
  const directory = new Map((keys?.keys || []).map((k) => [k.kid, k]));
  const revocationChecked = new Set();

  // Determine the public key. With a key directory, the directory takes
  // precedence, and the package must match it.
  const keyFor = (kid, fromPackage) => {
    const d = directory.get(kid);
    if (!d) {
      if (keys) note(`Key ${kid} not in the key directory`);
      return fromPackage || null;
    }
    if (fromPackage && fromPackage !== d.publicKey) error(`Key ${kid}: verification package and key directory do not match`);
    if (d.revoked && !revocationChecked.has(kid)) {
      revocationChecked.add(kid);
      if (d.revokedReason === 'superseded') ok(`Key ${kid} superseded as planned, signatures remain valid`);
      else {
        const anchored = att.commentAnchor?.status === 'anchored' ? Date.parse(att.commentAnchor.btcAnchoredAt) : NaN;
        if (Number.isFinite(anchored) && anchored < Date.parse(d.revokedAt)) ok(`Key ${kid} revoked, but the review was anchored before: signature counts`);
        else error(`Key ${kid} revoked (compromised, ${d.revokedAt}) and review not anchored before`);
      }
    }
    return d.publicKey;
  };

  const signature = (id, pubB64, msg, sig, label) => {
    const v = ALGORITHMS[id];
    const name = v ? v.name : id;
    if (!pubB64) { error(`${label} (${name}): no public key`); return false; }
    const r = verifySignature(id, b64(pubB64), msg, sig);
    if (r === true) ok(`${label} (${name}) valid`);
    else if (r === false) error(`${label} (${name}) invalid`);
    else if (v?.retired) note(`${label} (${name}): method retired, not checked here`);
    else note(`${label}: method ${id} unknown, not checked`);
    return r;
  };

  // 1–2. Envelope of the review
  const u = readEnvelope(pkg.envelope);
  if (!u.ok) { error(`Envelope not readable (${u.reason})`); return findings; }
  ok(`Envelope v${u.version} read (review ${u.payload.c || '?'})`);
  // Domain separation: the purpose is part of the signed payload (no
  // signature context is used), so a signed QR code or tree head cannot pass
  // as a review.
  if (u.payload.typ !== 'rev-comment') error(`Envelope is not a review (type ${u.payload.typ || 'missing'})`);
  signature('ed', keyFor(u.payload.kid, att.envelope?.ed25519Pub), u.payloadBytes, u.edSig, `Signature ${u.payload.kid}`);
  const declared = Array.isArray(u.payload.pv) ? u.payload.pv : [];
  for (const v of declared) if (!u.sigs.some((s) => s.algorithm === v)) error(`Signature ${v} is declared but missing (removed?)`);
  if (u.version === 3 && declared.length) error('Envelope v3, but PQ signatures declared (removed?)');
  const stampsInPackage = new Map((att.stamps || []).map((s) => [s.kid, s.pubkey]));
  for (const s of u.sigs) signature(s.algorithm, keyFor(s.kid, stampsInPackage.get(s.kid)), u.payloadBytes, s.sig, `Signature ${s.kid}`);

  // 3 + 5. Content binding, possibly via the redaction seal
  const qrEnvelope = att.qr?.envelope || null;
  const actualHash = pkg.record ? recordHash({ ...pkg.record, qrEnvelopeHash: qrEnvelope ? sha256hex(qrEnvelope) : null }) : null;
  const textHash = sha256hex(String(pkg.record?.Content ?? ''));
  const verifyRedaction = () => {
    const red = att.redaction;
    if (!red?.envelope) return false;
    const s = readEnvelope(red.envelope);
    if (!s.ok || s.payload.typ !== 'rev-redaction') { error('Redaction seal not readable'); return true; }
    if (signature('ed', keyFor(s.payload.kid, red.ed25519Pub), s.payloadBytes, s.edSig, `Redaction seal ${s.payload.kid}`) !== true) return true;
    if (s.payload.c !== u.payload.c || String(s.payload.eh || '').toLowerCase() !== sha256hex(pkg.envelope)) {
      error('Redaction seal does not belong to this submission');
      return true;
    }
    const matches = u.payload.rh ? String(s.payload.rh || '').toLowerCase() === actualHash : String(s.payload.h || '').toLowerCase() === textHash;
    if (!matches) { error('Displayed version does not match the redaction seal'); return true; }
    const on = s.payload.iat ? new Date(s.payload.iat * 1000).toISOString().slice(0, 10) : '?';
    ok(`Displayed version is the sealed redaction of exactly this submission (on ${on}); the original text is not included`);
    return true;
  };
  if (u.payload.rh) {
    const rv = Number(u.payload.rv || RULE_VERSION);
    if (rv !== RULE_VERSION) note(`Hash rule v${rv} unknown (this tool knows v${RULE_VERSION})`);
    else if (!pkg.record) note('No record in the package, content binding cannot be checked');
    else if (actualHash === String(u.payload.rh).toLowerCase()) ok('Record (text, hearts, geo, origin) matches the signature');
    else if (!verifyRedaction()) error('Record differs from the signed version');
  } else if (u.payload.h) {
    if (textHash === String(u.payload.h).toLowerCase()) ok('Text matches the signature');
    else if (!verifyRedaction()) error('Text differs from the signed version');
  } else note('Envelope without content binding (older review)');

  // 4. Origin
  if (qrEnvelope) {
    section = 'Origin (QR code)';
    if (u.payload.qh && sha256hex(qrEnvelope) !== String(u.payload.qh).toLowerCase()) error('QR envelope does not match the review');
    const q = readEnvelope(qrEnvelope);
    if (!q.ok) error(`QR envelope not readable (${q.reason})`);
    else {
      ok('QR envelope read');
      const pub = keyFor(q.payload.kid, null) || (q.payload.kid === u.payload.kid ? att.envelope?.ed25519Pub : null);
      if (pub) signature('ed', pub, q.payloadBytes, q.edSig, `QR code signature ${q.payload.kid}`);
      else note(`QR code key ${q.payload.kid} missing (provide the key directory)`);
      if (att.qr.payloadHash && createHash('sha256').update(q.payloadBytes).digest('base64') !== att.qr.payloadHash) {
        error('Stamps do not belong to this QR envelope');
      }
      for (const s of att.qr.stamps || []) signature(s.variant, keyFor(s.kid, s.pubkey), q.payloadBytes, b64(s.sig), `Origin stamp ${s.kid}`);
    }
  }

  // 6. Key proofs
  if (keys) {
    section = 'Keys';
    const kids = new Set([u.payload.kid, ...u.sigs.map((s) => s.kid), ...(att.qr?.stamps || []).map((s) => s.kid)]);
    for (const kid of kids) {
      const d = directory.get(kid);
      if (!d) continue;
      const expected = sha256hex(`kid:${d.kid}\nvariant:${d.algorithm}\npubkey:${d.publicKey}\nactiveFrom:${new Date(d.validFrom).toISOString()}`);
      if (d.anchor?.status === 'anchored' && d.anchor.otsProof) {
        if (proofDigest(d.anchor.otsProof) === expected) ok(`Key ${kid} anchored since block #${d.anchor.bitcoinBlock}, proof matches`);
        else error(`Key ${kid}: Bitcoin proof does not match the key`);
      } else note(`Key ${kid} not yet anchored in Bitcoin`);
    }
  } else {
    // Without a key directory the signatures were only checked against the
    // public keys contained in the package itself. Anyone can build such a
    // package with their own keys, so this proves nothing about who signed it.
    section = 'Keys';
    note('No key directory given (--keys): signatures were only checked against the keys inside the package, which does not prove who signed it');
  }

  // 7. Timestamp of the review
  section = 'Timestamp';
  const ca = att.commentAnchor;
  if (ca?.status === 'anchored' && ca.otsProof) {
    const expected = sha256hex(pkg.envelope);
    if (proofDigest(ca.otsProof) === expected) ok(`Bitcoin proof belongs to exactly this envelope (block #${ca.btcBlock})`);
    else error('Bitcoin proof does not belong to this envelope');
    if (online) {
      try {
        const r = await verifyOnline(ca.otsProof, expected);
        if (!r) error('Bitcoin confirmation not found online');
        else if (Number(ca.btcBlock) && r.block !== Number(ca.btcBlock)) error(`Bitcoin confirms block #${r.block}, package states #${ca.btcBlock}`);
        else ok(`Bitcoin blockchain confirms block #${r.block} (${r.time}); block header via public explorer`);
      } catch (e) {
        if (e instanceof OtsError) error(`Bitcoin proof invalid (${e.message})`);
        else note(`Online check not possible (${e.message})`);
      }
    } else note('Bitcoin proof only checked offline: use --online or your own node with ots verify (README, level C)');
  } else note('Review not yet anchored in Bitcoin');

  // 8. Transparency log: online from the API, or from a saved log proof file
  section = 'Transparency log';
  if (logProof && !keys) {
    note('Log proof file given, but the tree head keys can only be checked with --keys');
  } else if (logProof) {
    note('Log proof read from file (not fetched from the server)');
    for (const [kind, text] of await verifyReviewInLog(pkg, { keys: directory, online, log, proof: logProof })) {
      findings.push({ kind, section, text });
    }
  } else if (online && api) {
    try {
      let kids = directory;
      if (!keys) {
        const d = await fetchJson(keyDirectoryUrl, { log });
        kids = new Map((d.keys || []).map((k) => [k.kid, k]));
        note('Keys of the log tree heads loaded from the same server; independent only with --keys');
      }
      for (const [kind, text] of await verifyReviewInLog(pkg, { api, keys: kids, online, log })) {
        findings.push({ kind, section, text });
      }
    } catch (e) {
      note(`Log not retrievable (${e.message})`);
    }
  } else note('Log not checked: use --online or --log-proof <file>');

  return findings;
}
