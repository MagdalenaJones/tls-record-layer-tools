/**
 * Core parsing and construction logic for TLS 1.2 and 1.3 record headers.
 *
 * A TLS record always starts with a 5-byte header:
 *   1 byte  content type
 *   2 bytes legacy_version (major=3, minor=1..4 for TLS 1.0..1.3)
 *   2 bytes length (big-endian, max 16384 / 2^14 bytes)
 *
 * TLS 1.3 keeps the legacy_version field for backwards compatibility but
 * hard-codes it to 0x0303 ("3.3" = TLS 1.2). The actual negotiated version is
 * carried in the encrypted handshake, so a record header alone cannot tell you
 * whether the connection is 1.2 or 1.3. We expose legacyVersion for callers
 * that need the raw wire bytes, but the helper isApplicationDataVariant is
 * the real signal for "this record is likely 0-RTT early data."
 *
 * 0-RTT early data (RFC 8446 §2.3): In TLS 1.3 a client may send early
 * application data in its first flight. Because the ClientHello is
 * unencrypted, the early data records stand out as application_data records
 * (content type 23) sent before the server has acknowledged. We can detect
 * this *structurally* only when application_data precedes handshake records.
 */

/**
 * @typedef {Object} RecordHeader
 * @property {number} contentType   The raw content-type byte (1-255).
 * @property {number} majorVersion  Always 3 for TLS.
 * @property {number} minorVersion  Legacy minor version byte.
 * @property {number} length        Payload length in bytes (0-16384).
 */

export const ContentType = Object.freeze({
  CHANGE_CIPHER_SPEC: 20,
  ALERT: 21,
  HANDSHAKE: 22,
  APPLICATION_DATA: 23,
});

export const ProtocolVersion = Object.freeze({
  TLS_1_0: { major: 3, minor: 1 },
  TLS_1_1: { major: 3, minor: 2 },
  TLS_1_2: { major: 3, minor: 3 },
  // TLS 1.3 uses legacy_version 0x0303 on the wire.
  TLS_1_3_LEGACY: { major: 3, minor: 3 },
});

const MAX_FRAGMENT_LENGTH = 1 << 14; // 16384 bytes, per RFC 8446 §5.1 & RFC 5246 §6.2.1.

/**
 * Parse a 5-byte TLS record header from a Uint8Array.
 *
 * Why return an explicit tag instead of throwing? Record parsing is the
 * first thing a network reader does; surfacing the failure mode lets the
 * caller decide whether to drop the connection or log-and-continue.
 *
 * @param {Uint8Array} buf  At least 5 bytes.
 * @returns {{ ok: true, value: RecordHeader } | { ok: false, error: string }}
 */
export function parseRecordHeader(buf) {
  if (!(buf instanceof Uint8Array)) {
    return { ok: false, error: 'parseRecordHeader: expected Uint8Array' };
  }
  if (buf.length < 5) {
    return { ok: false, error: 'parseRecordHeader: need >= 5 bytes, got ' + buf.length };
  }

  const contentType = buf[0];
  const majorVersion = buf[1];
  const minorVersion = buf[2];
  const length = (buf[3] << 8) | buf[4];

  if (majorVersion !== 3) {
    return { ok: false, error: 'parseRecordHeader: unexpected major version ' + majorVersion };
  }
  if (length > MAX_FRAGMENT_LENGTH) {
    return { ok: false, error: 'parseRecordHeader: length ' + length + ' exceeds 16384' };
  }

  return {
    ok: true,
    value: { contentType, majorVersion, minorVersion, length },
  };
}

/**
 * Build a 5-byte TLS record header.
 *
 * @param {Object} opts
 * @param {number} opts.contentType  1-255.
 * @param {number} [opts.majorVersion=3]
 * @param {number} [opts.minorVersion=3]  Default 3, matching TLS 1.2 / TLS 1.3 legacy.
 * @param {number} opts.length          Payload length in bytes.
 * @returns {{ ok: true, value: Uint8Array } | { ok: false, error: string }}
 */
export function buildRecordHeader({ contentType, majorVersion = 3, minorVersion = 3, length }) {
  if (!Number.isInteger(contentType) || contentType < 0 || contentType > 255) {
    return { ok: false, error: 'buildRecordHeader: contentType out of range' };
  }
  if (!Number.isInteger(length) || length < 0 || length > MAX_FRAGMENT_LENGTH) {
    return { ok: false, error: 'buildRecordHeader: length out of range (0..16384)' };
  }
  if (majorVersion !== 3) {
    return { ok: false, error: 'buildRecordHeader: majorVersion must be 3' };
  }
  if (minorVersion < 1 || minorVersion > 3) {
    return { ok: false, error: 'buildRecordHeader: minorVersion out of range (1..3)' };
  }

  const out = new Uint8Array(5);
  out[0] = contentType;
  out[1] = majorVersion;
  out[2] = minorVersion;
  out[3] = (length >> 8) & 0xff;
  out[4] = length & 0xff;
  return { ok: true, value: out };
}

/**
 * Heuristic: does this record look like it could be 0-RTT early data?
 *
 * We treat the *position* of application_data in a sequence of records as the
 * signal. If application_data appears before any handshake record in a batch,
 * the client is sending data before the handshake completes — that is 0-RTT.
 * This is a necessary, not sufficient, condition; callers must combine it with
 * knowledge of whether a PSK / resumption is in play.
 *
 * @param {Array<{ contentType: number }>} recordsInOrder
 * @returns {boolean}
 */
export function isApplicationDataVariant(recordsInOrder) {
  if (!Array.isArray(recordsInOrder)) {
    return false;
  }
  for (const r of recordsInOrder) {
    if (!r || typeof r.contentType !== 'number') continue;
    if (r.contentType === ContentType.APPLICATION_DATA) {
      return true;
    }
    if (r.contentType === ContentType.HANDSHAKE) {
      return false;
    }
  }
  return false;
}

/**
 * Human-readable summary of the 0-RTT state implied by a sequence of records.
 *
 * @param {Array<{ contentType: number }>} recordsInOrder
 * @returns {'early-data-likely' | 'no-early-data' | 'indeterminate'}
 */
export function describeZeroRttState(recordsInOrder) {
  if (!Array.isArray(recordsInOrder) || recordsInOrder.length === 0) {
    return 'indeterminate';
  }
  if (isApplicationDataVariant(recordsInOrder)) {
    return 'early-data-likely';
  }
  return 'no-early-data';
}
