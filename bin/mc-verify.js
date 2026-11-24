#!/usr/bin/env node
// McGesund verification tool. For usage see README.
import fs from 'node:fs';
import path from 'node:path';
import { verifyPackage } from '../lib/verify.js';
import { verifyLog, fetchJson } from '../lib/transparency-log.js';

// The tool talks to the public website: transparency log via /api/transparenz,
// key directory via /.well-known/mcgesund-keys.json (same data on all McGesund domains).
const DEFAULT_SERVER = 'https://mcgesund.eu';
const WITH_VALUE = ['--keys', '--export-ots', '--server', '--log-proof'];
const args = process.argv.slice(2);
const option = (name) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : null; };
const file = args.find((a, i) => !a.startsWith('--') && !WITH_VALUE.includes(args[i - 1]));
const server = (option('--server') || DEFAULT_SERVER).replace(/\/+$/, '');
const api = `${server}/api/transparenz`;
const keyDirectoryUrl = `${server}/.well-known/mcgesund-keys.json`;
const log = (t) => console.error(t);
const logMode = args.includes('--log');
const full = args.includes('--full');
const label = { ok: 'OK     ', error: 'ERROR  ', note: 'NOTE   ' };

function report(findings) {
  let section = null;
  for (const f of findings) {
    if (f.section !== section) { section = f.section; console.log(`\n— ${section} —`); }
    console.log(`${label[f.kind]} ${f.text}`);
  }
  const e = findings.filter((f) => f.kind === 'error').length;
  const n = findings.filter((f) => f.kind === 'note').length;
  console.log(`\nResult: ${e ? `${e} error${e === 1 ? '' : 's'}` : 'no errors'}${n ? `, ${n} note${n === 1 ? '' : 's'}` : ''}`);
  // Without --keys a package is only checked against its own keys: say so
  // right next to the result, so "no errors" is not mistaken for proof.
  if (!e && !keys && !logMode) console.log('Warning: keys not checked against the key directory (--keys) — this result does not prove the review was submitted via McGesund.');
  process.exit(e ? 1 : 0);
}

if (!file && !logMode) {
  console.error([
    'Usage:',
    '  mc-verify <verification-package.json> [--keys <mcgesund-keys.json>] [--online] [--server <url>] [--log-proof <file>] [--export-ots <folder>]',
    '  mc-verify --log [--full] [--keys <mcgesund-keys.json>] [--online] [--server <url>]',
  ].join('\n'));
  process.exit(2);
}

// Saved answer of the log API for this review (offline check, e.g. the demo).
let logProof = null;
try {
  if (option('--log-proof')) logProof = JSON.parse(fs.readFileSync(option('--log-proof'), 'utf8'));
} catch (e) {
  console.error(`File not readable: ${e.message}`);
  process.exit(2);
}

let keys = null;
try {
  if (option('--keys')) keys = JSON.parse(fs.readFileSync(option('--keys'), 'utf8'));
} catch (e) {
  console.error(`File not readable: ${e.message}`);
  process.exit(2);
}

// Whole log: all tree heads, consistency, with --full all entries.
if (!file) {
  const findings = [];
  try {
    let source = keys;
    if (!source) {
      source = await fetchJson(keyDirectoryUrl, { log });
      findings.push({ kind: 'note', section: 'Keys', text: 'Key directory loaded from the same server; independent only with --keys' });
    }
    const kids = new Map((source.keys || []).map((k) => [k.kid, k]));
    for (const [kind, text] of await verifyLog({ api, keys: kids, online: args.includes('--online'), full, log })) {
      findings.push({ kind, section: 'Transparency log', text });
    }
  } catch (e) {
    findings.push({ kind: 'error', section: 'Transparency log', text: `Not retrievable (${e.message})` });
  }
  report(findings);
}

let pkg;
try {
  pkg = JSON.parse(fs.readFileSync(file, 'utf8'));
} catch (e) {
  console.error(`File not readable: ${e.message}`);
  process.exit(2);
}

// Envelope and proof as files for `ots verify` (README, level C).
const target = option('--export-ots');
if (target) {
  const proof = pkg.attestation?.commentAnchor?.otsProof;
  if (!proof) {
    console.error('Package contains no Bitcoin proof.');
    process.exit(2);
  }
  fs.mkdirSync(target, { recursive: true });
  fs.writeFileSync(path.join(target, 'envelope.txt'), pkg.envelope, 'utf8'); // without trailing newline
  fs.writeFileSync(path.join(target, 'proof.ots'), Buffer.from(proof, 'base64'));
  console.log(`Written: ${path.join(target, 'envelope.txt')}, ${path.join(target, 'proof.ots')}`);
  console.log(`Verify with your own Bitcoin node:\n  ots verify -f ${path.join(target, 'envelope.txt')} ${path.join(target, 'proof.ots')}`);
  console.log(`Expected: Bitcoin block ${pkg.attestation.commentAnchor.btcBlock}`);
  process.exit(0);
}

report(await verifyPackage(pkg, { keys, online: args.includes('--online'), api, keyDirectoryUrl, logProof, log }));
