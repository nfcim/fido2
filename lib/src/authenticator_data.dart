import 'package:cbor/cbor.dart';
import 'cose.dart';
import 'strict_cbor.dart';

class _ItemSink implements Sink<CborValue> {
  CborValue? value;
  @override
  void add(CborValue data) {
    if (value != null) throw const FormatException('Multiple CBOR items');
    value = data;
  }

  @override
  void close() {}
}

/// Consumes one CBOR item and returns its ending byte offset.
(CborValue, int) _readItem(List<int> bytes, int offset) {
  checkCborItem(bytes, offset);
  final sink = _ItemSink();
  final decoder = const CborDecoder().startChunkedConversion(sink);
  while (offset < bytes.length && sink.value == null) {
    decoder.addSlice(bytes, offset, offset + 1, false);
    offset++;
  }
  decoder.close();
  if (sink.value == null) throw const FormatException('Truncated CBOR item');
  return (sink.value!, offset);
}

class AuthenticatorData {
  final List<int> bytes;
  final List<int> rpIdHash;
  final int flags;
  final int signCount;
  final List<int>? aaguid;
  final List<int>? credentialId;
  final CoseKey? credentialPublicKey;
  final CborMap? extensions;
  bool get userPresent => flags & 1 != 0;
  bool get userVerified => flags & 4 != 0;
  bool get backupEligible => flags & 8 != 0;
  bool get backedUp => flags & 16 != 0;

  AuthenticatorData._(
      this.bytes,
      this.rpIdHash,
      this.flags,
      this.signCount,
      this.aaguid,
      this.credentialId,
      this.credentialPublicKey,
      this.extensions);

  static AuthenticatorData parse(List<int> input,
      {CoseConfiguration? configuration}) {
    if (input.length < 37 ||
        input.length > 65536 ||
        input.any((v) => v < 0 || v > 255)) {
      throw const FormatException('Invalid authenticator data length or bytes');
    }
    final bytes = List<int>.unmodifiable(input);
    final flags = bytes[32];
    if (flags & 16 != 0 && flags & 8 == 0) {
      throw const FormatException('Backup state requires backup eligibility');
    }
    final count = bytes[33] * 0x1000000 +
        bytes[34] * 0x10000 +
        bytes[35] * 256 +
        bytes[36];
    var offset = 37;
    List<int>? aaguid;
    List<int>? id;
    CoseKey? key;
    CborMap? extensions;
    if (flags & 64 != 0) {
      if (bytes.length < offset + 18) {
        throw const FormatException('Truncated attested credential data');
      }
      aaguid = List.unmodifiable(bytes.sublist(offset, offset + 16));
      offset += 16;
      final length = bytes[offset] * 256 + bytes[offset + 1];
      offset += 2;
      if (length == 0 || length > 1023 || bytes.length < offset + length) {
        throw const FormatException('Invalid credential ID length');
      }
      id = List.unmodifiable(bytes.sublist(offset, offset + length));
      offset += length;
      final (value, end) = _readItem(bytes, offset);
      if (value is! CborMap || value.tags.isNotEmpty) {
        throw const FormatException('Expected COSE map');
      }
      key = CoseKey.fromCborMap(value, configuration: configuration);
      offset = end;
    }
    if (flags & 128 != 0) {
      final (value, end) = _readItem(bytes, offset);
      if (value is! CborMap ||
          value.tags.isNotEmpty ||
          value.keys.any((k) => k is! CborString)) {
        throw const FormatException('Expected extension map with text keys');
      }
      extensions = value;
      offset = end;
    }
    if (offset != bytes.length) {
      throw const FormatException('Trailing authenticator data');
    }
    return AuthenticatorData._(bytes, List.unmodifiable(bytes.sublist(0, 32)),
        flags, count, aaguid, id, key, extensions);
  }
}
