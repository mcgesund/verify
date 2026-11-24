// Read an envelope "MCG1:" + base64url(CBOR(...)). See README, section 2.
import { decode } from 'cbor-x';

const PREFIX = 'MCG1:';

function base64urlDecode(s) {
  const pad = (4 - (s.length % 4)) % 4;
  return Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat(pad), 'base64');
}

const isBytes = (x) => x instanceof Uint8Array;

// Returns { ok, version, payload, payloadBytes, edSig, sigs } or { ok: false, reason }.
export function readEnvelope(text) {
  if (typeof text !== 'string' || !text.startsWith(PREFIX)) return { ok: false, reason: 'not an MCG1 envelope' };
  let arr;
  try {
    arr = decode(base64urlDecode(text.slice(PREFIX.length).trim()));
  } catch {
    return { ok: false, reason: 'not decodable' };
  }
  if (!Array.isArray(arr)) return { ok: false, reason: 'wrong structure' };
  const [version, payloadBytes, edSig, list] = arr;
  if (!((version === 3 && arr.length === 3) || (version === 4 && arr.length === 4))) {
    return { ok: false, reason: `version ${version} unknown` };
  }
  if (!isBytes(payloadBytes) || !isBytes(edSig)) return { ok: false, reason: 'wrong field types' };
  const sigs = [];
  if (version === 4) {
    if (!Array.isArray(list)) return { ok: false, reason: 'wrong field types' };
    for (const e of list) {
      if (!Array.isArray(e) || e.length !== 3 || typeof e[0] !== 'string' || typeof e[1] !== 'string' || !isBytes(e[2])) {
        return { ok: false, reason: 'wrong field types' };
      }
      sigs.push({ algorithm: e[0], kid: e[1], sig: e[2] });
    }
  }
  let payload;
  try {
    payload = decode(payloadBytes);
  } catch {
    return { ok: false, reason: 'payload not decodable' };
  }
  if (!payload || typeof payload !== 'object') return { ok: false, reason: 'payload invalid' };
  return { ok: true, version, payload, payloadBytes, edSig, sigs };
}
