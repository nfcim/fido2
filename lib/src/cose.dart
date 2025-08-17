import 'dart:collection';

import 'package:cbor/cbor.dart';
import 'package:convert/convert.dart';

/// Represents a key as specified by RFC8152:
/// [CBOR Object Signing and Encryption (COSE)](https://tools.ietf.org/html/rfc8152)
///
/// Extended this class to support more COSE key types.
sealed class CoseKey extends MapView<int, dynamic> {
  static const int? algorithm = null;

  /// Constructor with optional parameters
  CoseKey(super.coseKeyParams);

  /// Method to verify a signature
  void verify(List<int> message, List<int> signature) {
    throw UnimplementedError('Signature verification not supported.');
  }

  /// Convert to standard CBOR encoded format
  CborValue toCbor() {
    throw UnimplementedError('toCbor not supported.');
  }

  /// Static method to parse a COSE key
  static CoseKey parse(Map<int, dynamic> cose) {
    int? alg = cose[3];
    if (alg == null) {
      throw ArgumentError('COSE alg identifier must be provided.');
    }
    switch (alg) {
      case ES256.algorithm:
        return ES256(cose);
    }
    return UnsupportedKey(cose);
  }

  /// Static method to get all algorithms supported by fido2 library
  static List<int> supportedAlgorithms() {
    return [ES256.algorithm];
  }

  @override
  String toString() {
    final alg = this[3];
    final buffer = StringBuffer();
    buffer.writeln('CoseKey(');
    buffer.writeln('  algorithm: $alg,');
    buffer.writeln('  params: ${Map<int, dynamic>.from(this)},');
    buffer.write(')');
    return buffer.toString();
  }
}

/// Represents a currently unsupported COSE key type
class UnsupportedKey extends CoseKey {
  UnsupportedKey(super.coseKeyParams);

  @override
  String toString() {
    final alg = this[3];
    final buffer = StringBuffer();
    buffer.writeln('UnsupportedKey(');
    buffer.writeln('  algorithm: $alg,');
    buffer.writeln('  params: ${Map<int, dynamic>.from(this)},');
    buffer.write(')');
    return buffer.toString();
  }
}

/// Represents a COSE key of type ES256 (ECDSA w/ SHA-256, see RFC8152 8.1)
class ES256 extends CoseKey {
  static const int algorithm = -7;

  ES256(super.coseKeyParams);

  /// Static method to create a new instance from public key coordinates
  static ES256 fromPublicKey(List<int> x, List<int> y) {
    return ES256({
      1: 2,
      3: ES256.algorithm,
      -1: 1,
      -2: x,
      -3: y,
    });
  }

  @override
  CborValue toCbor() {
    return CborValue({
      1: 2,
      3: ES256.algorithm,
      -1: 1,
      -2: CborBytes(this[-2]),
      -3: CborBytes(this[-3]),
    });
  }

  @override
  String toString() {
    final x = this[-2] as List<int>?;
    final y = this[-3] as List<int>?;
    final buffer = StringBuffer();
    buffer.writeln('ES256(');
    buffer.writeln('  algorithm: $algorithm,');
    buffer.writeln('  x: ${x != null ? hex.encode(x) : null},');
    buffer.writeln('  y: ${y != null ? hex.encode(y) : null},');
    buffer.write(')');
    return buffer.toString();
  }
}

/// Represents a COSE key of type ECDH-ES+HKDF-256 (see RFC8152 11.1)
class EcdhEsHkdf256 extends CoseKey {
  static const int algorithm = -25;

  EcdhEsHkdf256(super.coseKeyParams);

  /// Static method to create a new instance from public key coordinates
  static EcdhEsHkdf256 fromPublicKey(List<int> x, List<int> y) {
    return EcdhEsHkdf256({
      1: 2,
      3: EcdhEsHkdf256.algorithm,
      -1: 1,
      -2: x,
      -3: y,
    });
  }

  @override
  CborValue toCbor() {
    return CborValue({
      1: 2,
      3: EcdhEsHkdf256.algorithm,
      -1: 1,
      -2: CborBytes(this[-2]),
      -3: CborBytes(this[-3]),
    });
  }

  @override
  String toString() {
    final x = this[-2] as List<int>?;
    final y = this[-3] as List<int>?;
    final buffer = StringBuffer();
    buffer.writeln('EcdhEsHkdf256(');
    buffer.writeln('  algorithm: $algorithm,');
    buffer.writeln('  x: ${x != null ? hex.encode(x) : null},');
    buffer.writeln('  y: ${y != null ? hex.encode(y) : null},');
    buffer.write(')');
    return buffer.toString();
  }
}
