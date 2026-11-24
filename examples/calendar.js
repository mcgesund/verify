// Talks to public OpenTimestamps calendars — used only by the demo scripts
// (generate.js, update.js), never by the verifier itself.
import { randomBytes } from 'node:crypto';
import { addOp, parseTimestamp } from '../lib/opentimestamps.js';

export const CALENDARS = [
  'https://alice.btc.calendar.opentimestamps.org',
  'https://bob.btc.calendar.opentimestamps.org',
  'https://finney.calendar.eternitywall.com',
];
const HEADERS = { accept: 'application/vnd.opentimestamps.v1', 'user-agent': 'mc-verify-demo' };

const merge = (node, upgrade) => {
  node.attestations.push(...upgrade.attestations);
  node.ops.push(...upgrade.ops);
};

// New proof for a 32-byte digest: digest → append(random nonce) → sha256 →
// submitted to every calendar. Needs at least one calendar to answer.
export async function stamp(digest) {
  const timestamp = { msg: Buffer.from(digest), attestations: [], ops: [] };
  const commitment = addOp(addOp(timestamp, 'append', randomBytes(16)), 'sha256');
  let answered = 0;
  for (const url of CALENDARS) {
    try {
      const res = await fetch(`${url}/digest`, { method: 'POST', body: commitment.msg, headers: HEADERS, signal: AbortSignal.timeout(20000) });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      merge(commitment, parseTimestamp(Buffer.from(await res.arrayBuffer()), commitment.msg));
      answered++;
    } catch (e) {
      console.error(`calendar ${url}: ${e.message}`);
    }
  }
  if (!answered) throw new Error('no calendar reachable');
  return { digest: Buffer.from(digest), timestamp };
}

// Asks the calendars for the Bitcoin confirmation of pending attestations.
// Only the calendars above are contacted, whatever URI a proof names.
// Returns true if the proof changed.
export async function upgrade(proof) {
  let changed = false;
  const walk = async (node) => {
    for (const a of [...node.attestations]) {
      if (a.type !== 'pending' || !CALENDARS.includes(a.uri)) continue;
      const res = await fetch(`${a.uri}/timestamp/${node.msg.toString('hex')}`, { headers: HEADERS, signal: AbortSignal.timeout(20000) });
      if (res.status === 404) continue; // not yet in a Bitcoin block
      if (!res.ok) throw new Error(`calendar ${a.uri}: HTTP ${res.status}`);
      const up = parseTimestamp(Buffer.from(await res.arrayBuffer()), node.msg);
      node.attestations.splice(node.attestations.indexOf(a), 1);
      merge(node, up);
      changed = true;
    }
    for (const o of node.ops) await walk(o.child);
  };
  await walk(proof.timestamp);
  return changed;
}
