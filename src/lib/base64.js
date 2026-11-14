// Pure-JS Base64 (RFC 4648, with padding) - browser-safe, no Buffer.
const T =
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

export function base64Encode(bytes) {
  let out = '';
  const n = bytes.length;
  for (let i = 0; i < n; i += 3) {
    const b0 = bytes[i];
    const b1 = i + 1 < n ? bytes[i + 1] : 0;
    const b2 = i + 2 < n ? bytes[i + 2] : 0;
    out += T[b0 >> 2];
    out += T[((b0 & 3) << 4) | (b1 >> 4)];
    out += i + 1 < n ? T[((b1 & 15) << 2) | (b2 >> 6)] : '=';
    out += i + 2 < n ? T[b2 & 63] : '=';
  }
  return out;
}

export function base64Decode(str) {
  if (typeof str !== 'string') throw new Error('base64: input is not a string');
  const clean = str.replace(/[\r\n\s]/g, '');
  if (clean.length % 4 !== 0) throw new Error('base64: invalid length');
  const out = new Uint8Array(Math.floor((clean.length / 4) * 3));
  let o = 0;
  let pad = 0;
  for (let i = 0; i < clean.length; i += 4) {
    const c2 = clean[i + 2] === '=';
    const c3 = clean[i + 3] === '=';
    // '=' is padding: only allowed as the last (up to two) characters.
    if ((c2 && i + 2 !== clean.length - 2) || (c3 && i + 3 !== clean.length - 1)) {
      throw new Error('base64: invalid padding position');
    }
    if (c2) pad++;
    if (c3) pad++;
    const a = T.indexOf(clean[i]);
    const b = T.indexOf(clean[i + 1]);
    const c = c2 ? 0 : T.indexOf(clean[i + 2]);
    const d = c3 ? 0 : T.indexOf(clean[i + 3]);
    if (a < 0 || b < 0 || c < 0 || d < 0) throw new Error('base64: invalid character');
    out[o++] = (a << 2) | (b >> 4);
    if (!c2) out[o++] = ((b & 15) << 4) | (c >> 2);
    if (!c3) out[o++] = ((c & 15) << 6) | d;
  }
  if (pad > 0 && (pad > 2 || clean[clean.length - 2] === '=' && clean[clean.length - 1] !== '=')) {
    throw new Error('base64: invalid padding');
  }
  return out.subarray(0, o);
}
