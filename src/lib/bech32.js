// Bech32 per BIP-173 (used for nsec/npub, NIP-19 prefix handling).
const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

function polymod(values) {
  const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const v of values) {
    const top = chk >> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) {
      if ((top >> i) & 1) chk ^= GEN[i];
    }
  }
  return chk;
}

function hrpExpand(hrp) {
  const out = [];
  for (const c of hrp) out.push(c.charCodeAt(0) >> 5);
  out.push(0);
  for (const c of hrp) out.push(c.charCodeAt(0) & 31);
  return out;
}

function verifyChecksum(hrp, data) {
  return polymod([...hrpExpand(hrp), ...data]) === 1;
}

function createChecksum(hrp, data) {
  const values = [...hrpExpand(hrp), ...data, 0, 0, 0, 0, 0, 0];
  const mod = polymod(values) ^ 1;
  const out = [];
  for (let i = 0; i < 6; i++) out.push((mod >> (5 * (5 - i))) & 31);
  return out;
}

function convertBits(data, fromBits, toBits, pad) {
  let acc = 0;
  let bits = 0;
  const out = [];
  const maxv = (1 << toBits) - 1;
  const maxAcc = (1 << (fromBits + toBits - 1)) - 1;
  for (const v of data) {
    if (v < 0 || (v >> fromBits) !== 0) throw new Error('bech32: invalid value in convertBits');
    acc = ((acc << fromBits) | v) & maxAcc;
    bits += fromBits;
    while (bits >= toBits) {
      bits -= toBits;
      out.push((acc >> bits) & maxv);
    }
  }
  if (pad) {
    if (bits) out.push((acc << (toBits - bits)) & maxv);
  } else if (bits >= fromBits || ((acc << (toBits - bits)) & maxv)) {
    throw new Error('bech32: invalid padding in convertBits');
  }
  return Uint8Array.from(out);
}

export function encodeBech32(hrp, data5bit) {
  const lower = hrp.toLowerCase();
  const checksum = createChecksum(lower, data5bit);
  let s = lower + '1';
  for (const v of [...data5bit, ...checksum]) s += CHARSET[v];
  return s;
}

export function decodeBech32(str) {
  if (typeof str !== 'string') throw new Error('bech32: input is not a string');
  const s = str.trim();
  if (s !== s.toLowerCase() && s !== s.toUpperCase()) {
    throw new Error('bech32: mixed case is not allowed');
  }
  const lowered = s.toLowerCase();
  const pos = lowered.lastIndexOf('1');
  if (pos < 1 || pos + 7 > lowered.length || lowered.length > 90) {
    throw new Error('bech32: invalid separator position');
  }
  const hrp = lowered.slice(0, pos);
  for (const c of hrp) {
    if (c.charCodeAt(0) < 33 || c.charCodeAt(0) > 126) {
      throw new Error('bech32: invalid hrp character');
    }
  }
  const data = [];
  for (const c of lowered.slice(pos + 1)) {
    const v = CHARSET.indexOf(c);
    if (v < 0) throw new Error('bech32: invalid data character');
    data.push(v);
  }
  if (!verifyChecksum(hrp, data)) throw new Error('bech32: invalid checksum');
  return { hrp, data: data.slice(0, -6) };
}

// Encode bytes as e.g. "npub1..." / "nsec1...".
export function encodeBech32Bytes(hrp, bytes) {
  return encodeBech32(hrp, convertBits(bytes, 8, 5, true));
}

// Decode "npub1..."/"nsec1..." to raw bytes; checks the expected hrp.
export function decodeBech32Bytes(str, expectedHrp) {
  const { hrp, data } = decodeBech32(str);
  if (hrp !== expectedHrp) throw new Error(`bech32: expected prefix "${expectedHrp}", got "${hrp}"`);
  return convertBits(data, 5, 8, false);
}
