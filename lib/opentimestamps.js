// Minimal OpenTimestamps implementation: reads, writes and verifies .ots
// proofs. Covers what McGesund's proofs use (SHA-256, append, prepend and the
// usual hash operations, Bitcoin and pending attestations) and nothing more.
// Format: https://github.com/opentimestamps/python-opentimestamps
//
// A proof is a tree. Starting from the file digest, each operation turns the
// current message into a new one; leaves are attestations. A Bitcoin
// attestation says: "this message is the Merkle root of block N".
import { createHash } from 'node:crypto';

const MAGIC = Buffer.from('004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294', 'hex');
const MAX_MSG = 4096; // python-opentimestamps: maximum message length
const MAX_PAYLOAD = 8192;
const MAX_DEPTH = 256;

const TAG_BITCOIN = '0588960d73d71901';
const TAG_PENDING = '83dfe30d2ef90c8e';

const hash = (alg) => (m) => createHash(alg).update(m).digest();
const UNARY = { 0x08: ['sha256', hash('sha256')], 0x02: ['sha1', hash('sha1')], 0x03: ['ripemd160', hash('ripemd160')] };
const BINARY = { 0xf0: 'append', 0xf1: 'prepend' };

export class OtsError extends Error {}

// --- Reading ---------------------------------------------------------------

class Reader {
  constructor(buf) { this.buf = buf; this.pos = 0; }
  byte() {
    if (this.pos >= this.buf.length) throw new OtsError('proof truncated');
    return this.buf[this.pos++];
  }
  bytes(n) {
    if (this.pos + n > this.buf.length) throw new OtsError('proof truncated');
    const b = this.buf.subarray(this.pos, this.pos + n);
    this.pos += n;
    return b;
  }
  varuint() {
    let value = 0;
    let shift = 0;
    for (;;) {
      const b = this.byte();
      value += (b & 0x7f) * 2 ** shift;
      if (!(b & 0x80)) return value;
      shift += 7;
      if (shift > 49) throw new OtsError('number too large');
    }
  }
  varbytes(max) {
    const n = this.varuint();
    if (n > max) throw new OtsError('field too long');
    return this.bytes(n);
  }
}

function readAttestation(r) {
  const tag = r.bytes(8).toString('hex');
  const payload = new Reader(r.varbytes(MAX_PAYLOAD));
  if (tag === TAG_BITCOIN) return { type: 'bitcoin', height: payload.varuint() };
  if (tag === TAG_PENDING) {
    const uri = payload.varbytes(1000).toString('utf8');
    if (!/^[A-Za-z0-9.\-_/:]+$/.test(uri)) throw new OtsError('invalid calendar URI');
    return { type: 'pending', uri };
  }
  return { type: 'unknown', tag, payload: payload.buf };
}

function applyOp(op, arg, msg) {
  let out;
  if (op.name === 'append') out = Buffer.concat([msg, arg]);
  else if (op.name === 'prepend') out = Buffer.concat([arg, msg]);
  else out = op.fn(msg);
  if (out.length > MAX_MSG) throw new OtsError('message too long');
  return out;
}

function readOp(tag, r) {
  if (UNARY[tag]) return { op: { name: UNARY[tag][0], fn: UNARY[tag][1] }, arg: null };
  if (BINARY[tag]) {
    const arg = r.varbytes(MAX_MSG);
    if (!arg.length) throw new OtsError('empty operand');
    return { op: { name: BINARY[tag] }, arg };
  }
  throw new OtsError(`unsupported operation 0x${tag.toString(16)}`);
}

// A timestamp node: { msg, attestations: [...], ops: [{ op, arg, child }] }
export function readTimestamp(r, msg, depth = 0) {
  if (depth > MAX_DEPTH) throw new OtsError('proof nested too deeply');
  const node = { msg, attestations: [], ops: [] };
  const element = (tag) => {
    if (tag === 0x00) node.attestations.push(readAttestation(r));
    else {
      const { op, arg } = readOp(tag, r);
      node.ops.push({ op, arg, child: readTimestamp(r, applyOp(op, arg, msg), depth + 1) });
    }
  };
  let tag = r.byte();
  while (tag === 0xff) {
    element(r.byte());
    tag = r.byte();
  }
  element(tag);
  return node;
}

// Parses a detached proof (.ots file contents). Only SHA-256 file digests.
export function parseProof(bytes) {
  const r = new Reader(Buffer.from(bytes));
  if (!r.bytes(MAGIC.length).equals(MAGIC)) throw new OtsError('not an OpenTimestamps proof');
  const version = r.varuint();
  if (version !== 1) throw new OtsError(`unsupported proof version ${version}`);
  if (r.byte() !== 0x08) throw new OtsError('file digest is not SHA-256');
  const digest = Buffer.from(r.bytes(32));
  const timestamp = readTimestamp(r, digest);
  if (r.pos !== r.buf.length) throw new OtsError('trailing data after proof');
  return { digest, timestamp };
}

// Parses a bare timestamp (as returned by a calendar) for a known message.
export function parseTimestamp(bytes, msg) {
  const r = new Reader(Buffer.from(bytes));
  const node = readTimestamp(r, Buffer.from(msg));
  if (r.pos !== r.buf.length) throw new OtsError('trailing data after timestamp');
  return node;
}

// All attestations with the message they attest.
export function attestations(node, out = []) {
  for (const a of node.attestations) out.push({ ...a, msg: node.msg });
  for (const o of node.ops) attestations(o.child, out);
  return out;
}

// --- Writing ---------------------------------------------------------------

const varuint = (n) => {
  const out = [];
  do {
    let b = n % 128;
    n = Math.floor(n / 128);
    if (n > 0) b |= 0x80;
    out.push(b);
  } while (n > 0);
  return Buffer.from(out);
};
const varbytes = (b) => Buffer.concat([varuint(b.length), b]);
const OP_TAG = { sha256: 0x08, sha1: 0x02, ripemd160: 0x03, append: 0xf0, prepend: 0xf1 };

function writeAttestation(a) {
  let tag;
  let payload;
  if (a.type === 'bitcoin') [tag, payload] = [TAG_BITCOIN, varuint(a.height)];
  else if (a.type === 'pending') [tag, payload] = [TAG_PENDING, varbytes(Buffer.from(a.uri, 'utf8'))];
  else [tag, payload] = [a.tag, a.payload];
  return Buffer.concat([Buffer.from([0x00]), Buffer.from(tag, 'hex'), varbytes(payload)]);
}

export function writeTimestamp(node) {
  const items = [
    ...node.attestations.map(writeAttestation),
    ...node.ops.map((o) => Buffer.concat([Buffer.from([OP_TAG[o.op.name]]), o.arg ? varbytes(o.arg) : Buffer.alloc(0), writeTimestamp(o.child)])),
  ];
  if (!items.length) throw new OtsError('empty timestamp');
  return Buffer.concat(items.map((b, i) => (i < items.length - 1 ? Buffer.concat([Buffer.from([0xff]), b]) : b)));
}

export function writeProof({ digest, timestamp }) {
  return Buffer.concat([MAGIC, varuint(1), Buffer.from([0x08]), digest, writeTimestamp(timestamp)]);
}

// Adds an operation below a node and returns the new child node.
export function addOp(node, name, arg = null) {
  const op = UNARY[OP_TAG[name]] ? { name, fn: UNARY[OP_TAG[name]][1] } : { name };
  const child = { msg: applyOp(op, arg, node.msg), attestations: [], ops: [] };
  node.ops.push({ op, arg, child });
  return child;
}

// --- Verifying against Bitcoin ---------------------------------------------

// Block headers come from a public Esplora instance (Blockstream). Only the
// block height leaves the machine, never the digest.
export const DEFAULT_EXPLORER = 'https://blockstream.info/api';

async function get(url, as) {
  const res = await fetch(url, { signal: AbortSignal.timeout(20000) });
  if (!res.ok) throw new Error(`HTTP ${res.status} for ${url}`);
  return as === 'text' ? (await res.text()).trim() : res;
}

// Checks every Bitcoin attestation of the proof against the real block
// header. Returns the lowest confirmed block { block, time } or null when
// the proof has no Bitcoin attestation. Throws if an attestation does not
// match its block (a forged proof).
export async function verifyBitcoin(proof, { explorer = DEFAULT_EXPLORER } = {}) {
  const found = attestations(proof.timestamp).filter((a) => a.type === 'bitcoin');
  let best = null;
  for (const a of found) {
    if (a.msg.length !== 32) throw new OtsError(`block #${a.height}: attested message is not 32 bytes`);
    const blockHash = await get(`${explorer}/block-height/${a.height}`, 'text');
    if (!/^[0-9a-f]{64}$/.test(blockHash)) throw new Error(`unexpected answer for block #${a.height}`);
    const header = Buffer.from(await get(`${explorer}/block/${blockHash}/header`, 'text'), 'hex');
    // The header must really be the one of that block hash.
    const h = createHash('sha256').update(createHash('sha256').update(header).digest()).digest().reverse().toString('hex');
    if (header.length !== 80 || h !== blockHash) throw new Error(`block #${a.height}: header does not match block hash`);
    const merkleRoot = header.subarray(36, 68);
    if (!merkleRoot.equals(a.msg)) throw new OtsError(`block #${a.height}: proof does not match the block's Merkle root`);
    const time = new Date(header.readUInt32LE(68) * 1000).toISOString();
    if (!best || a.height < best.block) best = { block: a.height, time };
  }
  return best;
}
