import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  parseRecordHeader,
  buildRecordHeader,
  ContentType,
  ProtocolVersion,
  isApplicationDataVariant,
  describeZeroRttState,
} from '../src/index.js';

const HEADER_LEN = 5;

function makeHeaderBytes(type, length) {
  const r = buildRecordHeader({
    contentType: type,
    length,
    majorVersion: ProtocolVersion.TLS_1_2.major,
    minorVersion: ProtocolVersion.TLS_1_2.minor,
  });
  if (!r.ok) {
    throw new Error('test setup failed: ' + r.error);
  }
  return r.value;
}

test('parseRecordHeader: valid handshake header round-trips', () => {
  const bytes = makeHeaderBytes(ContentType.HANDSHAKE, 100);
  const r = parseRecordHeader(bytes);
  assert.equal(r.ok, true);
  if (!r.ok) return;
  assert.equal(r.value.contentType, ContentType.HANDSHAKE);
  assert.equal(r.value.majorVersion, 3);
  assert.equal(r.value.minorVersion, 3);
  assert.equal(r.value.length, 100);
});

test('parseRecordHeader: length=0 is valid', () => {
  const bytes = makeHeaderBytes(ContentType.ALERT, 0);
  const r = parseRecordHeader(bytes);
  assert.equal(r.ok, true);
  if (!r.ok) return;
  assert.equal(r.value.length, 0);
});

test('parseRecordHeader: length=16384 is the maximum', () => {
  const bytes = makeHeaderBytes(ContentType.APPLICATION_DATA, 16384);
  const r = parseRecordHeader(bytes);
  assert.equal(r.ok, true);
  if (!r.ok) return;
  assert.equal(r.value.length, 16384);
});

test('parseRecordHeader: rejects length 16385 (over max)', () => {
  const r = buildRecordHeader({
    contentType: ContentType.APPLICATION_DATA,
    length: 16385,
  });
  assert.equal(r.ok, false);
});

test('parseRecordHeader: rejects buffer shorter than 5 bytes', () => {
  const r = parseRecordHeader(new Uint8Array(4));
  assert.equal(r.ok, false);
  assert.match(r.error, />= 5 bytes/);
});

test('parseRecordHeader: rejects non-Uint8Array input', () => {
  const r = parseRecordHeader([1, 2, 3, 4, 5]);
  assert.equal(r.ok, false);
});

test('parseRecordHeader: rejects major version != 3', () => {
  const r = buildRecordHeader({
    contentType: ContentType.HANDSHAKE,
    length: 10,
    majorVersion: 2,
  });
  assert.equal(r.ok, false);
});

test('buildRecordHeader: encodes length big-endian', () => {
  const r = buildRecordHeader({
    contentType: ContentType.APPLICATION_DATA,
    length: 0x1234,
  });
  assert.equal(r.ok, true);
  if (!r.ok) return;
  assert.equal(r.value[0], ContentType.APPLICATION_DATA);
  assert.equal(r.value[1], 3);
  assert.equal(r.value[2], 3);
  assert.equal(r.value[3], 0x12);
  assert.equal(r.value[4], 0x34);
});

test('buildRecordHeader: rejects contentType 256', () => {
  const r = buildRecordHeader({ contentType: 256, length: 0 });
  assert.equal(r.ok, false);
});

test('buildRecordHeader: rejects minor version 4', () => {
  const r = buildRecordHeader({
    contentType: ContentType.HANDSHAKE,
    length: 0,
    minorVersion: 4,
  });
  assert.equal(r.ok, false);
});

test('isApplicationDataVariant: true when app_data leads the sequence (0-RTT)', () => {
  const seq = [
    { contentType: ContentType.APPLICATION_DATA },
    { contentType: ContentType.HANDSHAKE },
  ];
  assert.equal(isApplicationDataVariant(seq), true);
});

test('isApplicationDataVariant: false when handshake leads (normal 1-RTT)', () => {
  const seq = [
    { contentType: ContentType.HANDSHAKE },
    { contentType: ContentType.APPLICATION_DATA },
  ];
  assert.equal(isApplicationDataVariant(seq), false);
});

test('describeZeroRttState: empty array is indeterminate', () => {
  assert.equal(describeZeroRttState([]), 'indeterminate');
});

test('describeZeroRttState: app_data first means early-data-likely', () => {
  const seq = [
    { contentType: ContentType.APPLICATION_DATA },
    { contentType: ContentType.HANDSHAKE },
  ];
  assert.equal(describeZeroRttState(seq), 'early-data-likely');
});

test('describeZeroRttState: handshake first means no-early-data', () => {
  const seq = [
    { contentType: ContentType.HANDSHAKE },
    { contentType: ContentType.APPLICATION_DATA },
  ];
  assert.equal(describeZeroRttState(seq), 'no-early-data');
});

test('isApplicationDataVariant: ignores change_cipher_spec (not a signal)', () => {
  // change_cipher_spec records may appear before handshake completes in TLS 1.3 middlebox compatibility mode.
  // They are not application_data, so we skip past them.
  const seq = [
    { contentType: ContentType.CHANGE_CIPHER_SPEC },
    { contentType: ContentType.APPLICATION_DATA },
    { contentType: ContentType.HANDSHAKE },
  ];
  assert.equal(isApplicationDataVariant(seq), true);
});
