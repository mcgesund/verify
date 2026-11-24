// Hash of a review's record (`rh`), rule version 1. See README, section 3.
import { createHash } from 'node:crypto';

export const RULE_VERSION = 1;

const text = (w) => (w === null || w === undefined ? null : String(w).length ? String(w) : null);
const integer = (w) => {
  if (w === null || w === undefined || w === '') return null;
  const n = Number(w);
  return Number.isFinite(n) ? Math.round(n) : null;
};
const decimal = (w) => {
  if (w === null || w === undefined || w === '') return null;
  const n = Number(w);
  return Number.isFinite(n) ? n.toFixed(2) : null;
};
const truthy = (w) => w === true || w === 1 || w === 'true';

export function canonical(r = {}) {
  return JSON.stringify([
    RULE_VERSION,
    text(r.Content),
    decimal(r.AverageRating),
    integer(r.ValueRating),
    integer(r.ServiceRating),
    integer(r.CleanlinessRating),
    integer(r.QualityRating),
    text(r.productLabel),
    text(r.eventLabel),
    text(r.geoStatus),
    truthy(r.geoVerified),
    integer(r.geoDistance),
    truthy(r.viaRotatingToken),
    text(r.qrEnvelopeHash),
  ]);
}

export const sha256hex = (s) => createHash('sha256').update(s, 'utf8').digest('hex');

export const recordHash = (r) => sha256hex(canonical(r));
