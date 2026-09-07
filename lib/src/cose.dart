import 'dart:collection';
import 'dart:convert';
import 'package:cbor/cbor.dart';
import 'crypto/crypto.dart';
import 'strict_cbor.dart';

enum SignatureEncoding { raw, der }

enum SignatureAlgorithm { es256, ed25519, sm2, mlDsa44, mlDsa65, mlDsa87 }

/// Explicit EC2 compatibility profile: SM2 has no IANA COSE allocation.
class Sm2Configuration {
  final int algorithm;
  final int curve;
  final String id;
  final SignatureEncoding signatureEncoding;
  Sm2Configuration(
      {required this.algorithm,
      required this.curve,
      this.id = '1234567812345678',
      this.signatureEncoding = SignatureEncoding.raw,
      bool allowUnassignedIdentifiers = false}) {
    // Compatibility profiles use private-use or opted-in unassigned identifiers.
    final validAlgorithm = algorithm < -65536 ||
        (allowUnassignedIdentifiers && algorithm >= -256 && algorithm <= -54);
    final validCurve = curve < -65536 ||
        (allowUnassignedIdentifiers && curve >= 9 && curve <= 255);
    if (!validAlgorithm || !validCurve || utf8.encode(id).length > 8191) {
      throw ArgumentError(
          'SM2 requires private-use or explicitly enabled unassigned identifiers and ID <=8191 UTF-8 bytes');
    }
  }
}

class CoseConfiguration {
  final Sm2Configuration? sm2;
  final Map<int, SignatureAlgorithm> compatibilityAlgorithms;
  CoseConfiguration(
      {this.sm2,
      Map<int, SignatureAlgorithm> compatibilityAlgorithms = const {}})
      : compatibilityAlgorithms = Map.unmodifiable(compatibilityAlgorithms) {
    for (final entry in compatibilityAlgorithms.entries) {
      if (entry.key >= -65536 ||
          entry.key == sm2?.algorithm ||
          entry.value == SignatureAlgorithm.sm2) {
        throw ArgumentError(
            'Conflicting compatibility algorithm; configure SM2 separately');
      }
    }
  }
  SignatureAlgorithm? resolve(int algorithm) => switch (algorithm) {
        -7 || -9 => SignatureAlgorithm.es256,
        -8 || -19 => SignatureAlgorithm.ed25519,
        -48 => SignatureAlgorithm.mlDsa44,
        -49 => SignatureAlgorithm.mlDsa65,
        -50 => SignatureAlgorithm.mlDsa87,
        _ => algorithm == sm2?.algorithm
            ? SignatureAlgorithm.sm2
            : compatibilityAlgorithms[algorithm],
      };
}

Object? _freeze(Object? value) {
  if (value is CborValue) return value;
  if (value is List<int>) return List<int>.unmodifiable(value);
  if (value is List) return List.unmodifiable(value.map(_freeze));
  if (value is Map) {
    return Map.unmodifiable(value.map((k, v) => MapEntry(k, _freeze(v))));
  }
  return value;
}

CborValue _encode(Object? value, {bool bytes = false}) {
  if (value is CborValue) return value;
  if (bytes && value is List) {
    return CborBytes(value.cast<int>());
  }
  return CborValue(value);
}

/// Parsing checks structure. [validate] checks mathematical validity in Rust.
sealed class CoseKey extends MapView<int, dynamic> {
  static const int? algorithm = null;
  CoseKey(Map<int, dynamic> params)
      : super(Map.unmodifiable(params.map((k, v) => MapEntry(k, _freeze(v))))) {
    if (this[3] is! int || this[1] is! int) {
      throw ArgumentError('COSE kty and alg must be integers');
    }
  }
  int get algorithmId => this[3] as int;
  String get rustAlgorithm =>
      throw UnsupportedError('Unsupported COSE algorithm $algorithmId');
  List<int> get publicKeyBytes =>
      throw UnsupportedError('Unsupported COSE algorithm $algorithmId');
  void validate() =>
      RustCrypto.validatePublicKey(rustAlgorithm, publicKeyBytes);

  /// ES256 defaults to WebAuthn DER; SM2 defaults to its explicit profile.
  void verify(List<int> message, List<int> signature,
      {SignatureEncoding? encoding,
      String? sm2Id,
      String mlDsaMode = 'pure',
      List<int> context = const []}) {
    if (this is MLDSA && (mlDsaMode != 'pure' || context.isNotEmpty)) {
      throw ArgumentError('RFC 9964 requires Pure ML-DSA and empty context');
    }
    final sm2 = this is SM2 ? (this as SM2).configuration : null;
    final selectedEncoding = encoding ??
        sm2?.signatureEncoding ??
        (this is ES256 ? SignatureEncoding.der : SignatureEncoding.raw);
    if (!RustCrypto.verify(rustAlgorithm, publicKeyBytes, message, signature,
        encoding: selectedEncoding.name,
        sm2Id: sm2Id ?? sm2?.id ?? '1234567812345678',
        mlDsaMode: mlDsaMode,
        context: context)) {
      throw const CryptoException('invalid_signature');
    }
  }

  CborMap toCborMap() => CborMap.fromEntries(entries.map((e) => MapEntry(
      CborSmallInt(e.key),
      _encode(e.value,
          bytes: e.key == 2 ||
              e.key == 5 ||
              (this is _Ec2 && (e.key == -2 || e.key == -3)) ||
              (this is Ed25519 && e.key == -2) ||
              (this is MLDSA && e.key == -1)))));
  CborValue toCbor() => toCborMap();

  /// Decode wire bytes with duplicate-label checks before map construction.
  static CoseKey fromCbor(List<int> bytes, {CoseConfiguration? configuration}) {
    final value = decodeStrictCbor(bytes);
    if (value is! CborMap) throw const FormatException('Expected COSE map');
    return fromCborMap(value, configuration: configuration);
  }

  static CoseKey fromCborMap(CborMap map, {CoseConfiguration? configuration}) {
    if (map.tags.isNotEmpty) {
      throw ArgumentError('Expected an untagged COSE map');
    }
    final alg = map[CborSmallInt(3)];
    final known = alg is CborInt &&
        (alg.toInt() == -25 ||
            (configuration ?? CoseConfiguration()).resolve(alg.toInt()) !=
                null);
    final params = <int, dynamic>{};
    for (final entry in map.entries) {
      if (entry.key is! CborInt || entry.key.tags.isNotEmpty) {
        throw ArgumentError('COSE labels must be untagged integers');
      }
      final label = (entry.key as CborInt).toInt();
      final value = entry.value;
      if ({1, 3}.contains(label) || (known && {-1, -2, -3}.contains(label))) {
        if (value.tags.isNotEmpty) throw ArgumentError('Tagged COSE key field');
        params[label] = value is CborBytes
            ? List<int>.from(value.bytes)
            : value is CborInt
                ? value.toInt()
                : value;
      } else {
        params[label] = value;
      }
    }
    return parse(params, configuration: configuration);
  }

  static CoseKey parse(Map<int, dynamic> cose,
      {CoseConfiguration? configuration}) {
    final config = configuration ?? CoseConfiguration();
    if (cose[3] is! int) throw ArgumentError('COSE alg must be an integer');
    if (cose[3] == -25) return EcdhEsHkdf256(cose);
    return switch (config.resolve(cose[3])) {
      SignatureAlgorithm.es256 =>
        ES256(cose, algorithmId: cose[3], configuration: config),
      SignatureAlgorithm.ed25519 =>
        Ed25519(cose, algorithmId: cose[3], configuration: config),
      SignatureAlgorithm.sm2 => SM2(cose, configuration: config.sm2!),
      SignatureAlgorithm.mlDsa44 =>
        MLDSA44(cose, algorithmId: cose[3], configuration: config),
      SignatureAlgorithm.mlDsa65 =>
        MLDSA65(cose, algorithmId: cose[3], configuration: config),
      SignatureAlgorithm.mlDsa87 =>
        MLDSA87(cose, algorithmId: cose[3], configuration: config),
      null => UnsupportedKey(cose),
    };
  }

  static List<int> supportedAlgorithms({CoseConfiguration? configuration}) => [
        ES256.algorithm,
        Ed25519.algorithm,
        Ed25519.fullySpecifiedAlgorithm,
        -9,
        MLDSA44.algorithm,
        MLDSA65.algorithm,
        MLDSA87.algorithm,
        if (configuration?.sm2 != null) configuration!.sm2!.algorithm,
        ...?configuration?.compatibilityAlgorithms.keys,
      ];
  void _field(int label, Object value) {
    if (this[label] != value) throw ArgumentError('Invalid COSE field $label');
  }

  void _algorithm(int algorithm, SignatureAlgorithm expected,
      CoseConfiguration? configuration) {
    if ((configuration ?? CoseConfiguration()).resolve(algorithm) != expected) {
      throw ArgumentError(
          'Algorithm does not match key class or explicit configuration');
    }
  }

  void _bytes(int label, int length) {
    final value = this[label];
    if (value is! List ||
        value.length != length ||
        value.any((b) => b is! int || b < 0 || b > 255)) {
      throw ArgumentError('COSE field $label must be $length bytes');
    }
  }
}

class UnsupportedKey extends CoseKey {
  UnsupportedKey(super.params);
}

abstract class _Ec2 extends CoseKey {
  _Ec2(super.params, int algorithm, int curve) {
    _field(1, 2);
    _field(3, algorithm);
    _field(-1, curve);
    _bytes(-2, 32);
    _bytes(-3, 32);
    if (containsKey(-4)) {
      throw ArgumentError('Expected public key, found private material');
    }
  }
  @override
  List<int> get publicKeyBytes =>
      [4, ...List<int>.from(this[-2]), ...List<int>.from(this[-3])];
}

class ES256 extends _Ec2 {
  static const int algorithm = -7;
  ES256(Map<int, dynamic> params,
      {int algorithmId = algorithm, CoseConfiguration? configuration})
      : super(params, algorithmId, 1) {
    _algorithm(algorithmId, SignatureAlgorithm.es256, configuration);
  }
  static ES256 fromPublicKey(List<int> x, List<int> y) =>
      ES256({1: 2, 3: algorithm, -1: 1, -2: x, -3: y});
  @override
  String get rustAlgorithm => 'es256';
}

class EcdhEsHkdf256 extends _Ec2 {
  static const int algorithm = -25;
  EcdhEsHkdf256(Map<int, dynamic> params) : super(params, algorithm, 1);
  static EcdhEsHkdf256 fromPublicKey(List<int> x, List<int> y) =>
      EcdhEsHkdf256({1: 2, 3: algorithm, -1: 1, -2: x, -3: y});
  @override
  String get rustAlgorithm => 'p256';
  @override
  void verify(List<int> message, List<int> signature,
          {SignatureEncoding? encoding,
          String? sm2Id,
          String mlDsaMode = 'pure',
          List<int> context = const []}) =>
      throw UnsupportedError('ECDH is not a signature algorithm');
}

class Ed25519 extends CoseKey {
  static const int algorithm = -8;
  static const int fullySpecifiedAlgorithm = -19;
  Ed25519(super.params,
      {int algorithmId = algorithm, CoseConfiguration? configuration}) {
    _algorithm(algorithmId, SignatureAlgorithm.ed25519, configuration);
    _field(1, 1);
    _field(3, algorithmId);
    _field(-1, 6);
    _bytes(-2, 32);
    if (containsKey(-4)) throw ArgumentError('Expected public key');
  }
  static Ed25519 fromPublicKey(List<int> key, {int algorithmId = algorithm}) =>
      Ed25519({1: 1, 3: algorithmId, -1: 6, -2: key}, algorithmId: algorithmId);
  @override
  String get rustAlgorithm => 'ed25519';
  @override
  List<int> get publicKeyBytes => List<int>.from(this[-2]);
}

class SM2 extends _Ec2 {
  final Sm2Configuration configuration;
  SM2(Map<int, dynamic> params, {required this.configuration})
      : super(params, configuration.algorithm, configuration.curve);
  static SM2 fromPublicKey(List<int> x, List<int> y,
          {required Sm2Configuration configuration}) =>
      SM2({
        1: 2,
        3: configuration.algorithm,
        -1: configuration.curve,
        -2: x,
        -3: y
      }, configuration: configuration);
  @override
  String get rustAlgorithm => 'sm2';
}

abstract class MLDSA extends CoseKey {
  final int parameterSet;
  MLDSA(super.params, int algorithm, this.parameterSet, int length) {
    _field(1, 7);
    _field(3, algorithm);
    _bytes(-1, length);
    if (containsKey(-2)) throw ArgumentError('Expected public ML-DSA key');
  }
  @override
  String get rustAlgorithm => 'ml-dsa-$parameterSet';
  @override
  List<int> get publicKeyBytes => List<int>.from(this[-1]);
}

class MLDSA44 extends MLDSA {
  static const int algorithm = -48;
  MLDSA44(Map<int, dynamic> params,
      {int algorithmId = algorithm, CoseConfiguration? configuration})
      : super(params, algorithmId, 44, 1312) {
    _algorithm(algorithmId, SignatureAlgorithm.mlDsa44, configuration);
  }
  static MLDSA44 fromPublicKey(List<int> key) =>
      MLDSA44({1: 7, 3: algorithm, -1: key});
}

class MLDSA65 extends MLDSA {
  static const int algorithm = -49;
  MLDSA65(Map<int, dynamic> params,
      {int algorithmId = algorithm, CoseConfiguration? configuration})
      : super(params, algorithmId, 65, 1952) {
    _algorithm(algorithmId, SignatureAlgorithm.mlDsa65, configuration);
  }
  static MLDSA65 fromPublicKey(List<int> key) =>
      MLDSA65({1: 7, 3: algorithm, -1: key});
}

class MLDSA87 extends MLDSA {
  static const int algorithm = -50;
  MLDSA87(Map<int, dynamic> params,
      {int algorithmId = algorithm, CoseConfiguration? configuration})
      : super(params, algorithmId, 87, 2592) {
    _algorithm(algorithmId, SignatureAlgorithm.mlDsa87, configuration);
  }
  static MLDSA87 fromPublicKey(List<int> key) =>
      MLDSA87({1: 7, 3: algorithm, -1: key});
}
