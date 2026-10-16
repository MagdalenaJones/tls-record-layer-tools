/**
 * tls-record-layer-tools
 *
 * Parses and constructs TLS 1.2 and 1.3 record headers and 0-RTT early
 * data indicators. Zero third-party dependencies, ESM only.
 *
 * The module re-exports the parser/builder surface from ./core.js so
 * consumers have a single entry point: import { ... } from 'tls-record-layer-tools'.
 */
export {
  parseRecordHeader,
  buildRecordHeader,
  ContentType,
  ProtocolVersion,
  isApplicationDataVariant,
  describeZeroRttState,
} from './core.js';
