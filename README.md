# tls-record-layer-tools

Parses and constructs TLS 1.2 and 1.3 record headers and exposes a structural heuristic for detecting 0-RTT early data. Zero third-party dependencies; ESM only.

## Usage

```js
import {
  parseRecordHeader,
  buildRecordHeader,
  ContentType,
  ProtocolVersion,
  isApplicationDataVariant,
  describeZeroRttState,
} from 'tls-record-layer-tools';

const built = buildRecordHeader({
  contentType: ContentType.HANDSHAKE,
  length: 512,
  majorVersion: ProtocolVersion.TLS_1_2.major,
  minorVersion: ProtocolVersion.TLS_1_2.minor,
});
// built.ok === true, built.value is a 5-byte Uint8Array

const parsed = parseRecordHeader(built.value);
// parsed.ok === true, parsed.value.length === 512

const zeroRtt = describeZeroRttState([
  { contentType: ContentType.APPLICATION_DATA },
  { contentType: ContentType.HANDSHAKE },
]);
// zeroRtt === 'early-data-likely'
```

## Why this exists

TLS 1.3 keeps the `legacy_version` field in record headers hard-coded to `0x0303` for backwards compatibility, so the on-the-wire header alone cannot tell you the negotiated protocol version. This library does not pretend otherwise — `parseRecordHeader` returns the raw `majorVersion` / `minorVersion` bytes, and callers who need to distinguish TLS 1.2 from 1.3 must do so using out-of-band handshake state.

The 0-RTT detection provided here is *structural*, not cryptographic: it flags application_data records that appear before any handshake record in a sequence. This is a necessary but not sufficient signal for early data; combine it with knowledge of whether a PSK resumption is in play before making security decisions.

## Awkward edges

- `buildRecordHeader` rejects `length > 16384` (the RFC 5246 / 8446 maximum fragment size) even though some deployments tolerate larger records. We chose strictness because record framing is the first line of defence.
- `isApplicationDataVariant` skips past `change_cipher_spec` records (content type 20) because TLS 1.3 middlebox-compatibility mode inserts them before the handshake finishes, and they are not application data.
- The maximum fragment length is `2^14 = 16384` bytes; this is encoded in `MAX_FRAGMENT_LENGTH` inside `src/core.js`.

## Exports

`parseRecordHeader`, `buildRecordHeader`, `ContentType`, `ProtocolVersion`, `isApplicationDataVariant`, `describeZeroRttState`.

## Running the tests

```sh
node --test
```

## Performance

The window keeps a bounded buffer, so `push` is constant time and memory does not
grow with the length of the stream. `peak` and `trough` are linear in the window
size, which is the trade that keeps `push` cheap.

## Limitations

Values are coerced to floats, so very large integers lose precision. If you need
exact integer aggregates over a window, this is the wrong tool.

