#!/usr/bin/env node
// Adds the Bitcoin confirmation of the OpenTimestamps proofs to the demo
// files in examples/.
//
//   node examples/update.js
//
// Only contacts the three public OpenTimestamps calendars listed in
// calendar.js, whatever a proof names. A file is written only if at least one of its proofs is now
// confirmed in Bitcoin; otherwise it stays unchanged and the script just
// prints the status.
import fs from 'node:fs';
import { parseProof, writeProof, attestations } from '../lib/opentimestamps.js';
import { upgrade } from './calendar.js';

const DIR = new URL('./', import.meta.url);
const FILES = ['demo-keys.json', 'package-unchanged.json', 'package-redacted.json', 'package-in-log.json', 'log-proof.json'];

const load = (name) => JSON.parse(fs.readFileSync(new URL(name, DIR), 'utf8'));
const content = Object.fromEntries(FILES.map((n) => [n, load(n)]));

// Every place a proof appears, with the field names of its format.
const places = [];
const place = (file, name, anchor, fields) => { if (anchor?.otsProof) places.push({ file, name, anchor, ...fields }); };
for (const k of content['demo-keys.json'].keys) place('demo-keys.json', `key ${k.kid}`, k.anchor, { block: 'bitcoinBlock', time: 'confirmedAt' });
for (const n of FILES.filter((x) => x.startsWith('package-'))) {
  const a = content[n].attestation;
  place(n, 'key anchor (attestation.anchor)', a.anchor, { block: 'btcBlock', time: 'btcAnchoredAt' });
  place(n, 'review envelope', a.commentAnchor, { block: 'btcBlock', time: 'btcAnchoredAt' });
}
place('log-proof.json', 'tree head', content['log-proof.json'].root.anchor, { block: 'btcBlock', time: null });

// Lowest Bitcoin block height in the proof, or null.
function bitcoinHeight(proof) {
  const h = attestations(proof.timestamp).filter((a) => a.type === 'bitcoin').map((a) => a.height);
  return h.length ? Math.min(...h) : null;
}

// Ask the calendars only once per digest (the Ed25519 key proof appears in
// the directory and in every package).
const groups = new Map();
for (const p of places) {
  const d = parseProof(Buffer.from(p.anchor.otsProof, 'base64'));
  const digest = d.digest.toString('hex');
  if (!groups.has(digest)) groups.set(digest, { file: d, places: [] });
  groups.get(digest).places.push(p);
}

const changed = new Set();
const now = new Date().toISOString();
let pending = 0;
for (const [digest, g] of groups) {
  const names = g.places.map((p) => `${p.file}: ${p.name}`).join('; ');
  let height = bitcoinHeight(g.file);
  if (height === null) {
    try {
      await upgrade(g.file);
    } catch (e) {
      console.log(`error    ${digest.slice(0, 16)}… (${names}): ${e.message}`);
    }
    height = bitcoinHeight(g.file);
  }
  if (height === null) {
    pending++;
    console.log(`pending  ${digest.slice(0, 16)}… ${names}`);
    continue;
  }
  const proof = writeProof(g.file).toString('base64');
  for (const p of g.places) {
    if (p.anchor.status === 'anchored' && p.anchor.otsProof === proof && p.anchor[p.block] === height) continue;
    p.anchor.status = 'anchored';
    p.anchor.otsProof = proof;
    p.anchor[p.block] = height;
    if (p.time && !p.anchor[p.time]) p.anchor[p.time] = now; // time of confirmation by this script
    changed.add(p.file);
  }
  console.log(`anchored ${digest.slice(0, 16)}… block #${height}: ${names}`);
}

for (const n of changed) {
  fs.writeFileSync(new URL(n, DIR), JSON.stringify(content[n], null, 2) + '\n', 'utf8');
  console.log(`written: examples/${n}`);
}
if (!changed.size) console.log('\nNo file changed.');
console.log(pending
  ? `${pending} of ${groups.size} proofs still pending — try again later (Bitcoin confirmation usually takes a few hours).`
  : `All ${groups.size} proofs confirmed in Bitcoin.`);
