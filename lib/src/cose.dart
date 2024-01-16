import 'dart:collection';

import 'package:cbor/cbor.dart';

abstract class CoseKey extends MapView<int, dynamic> {
  static const int? algorithm = null;

  // Constructor with optional parameters
  CoseKey(super.coseKeyParams);

  // Method to verify a signature
  void verify(List<int> message, List<int> signature) {
    throw UnimplementedError('Signature verification not supported.');
  }

  CborValue toCbor() {
    throw UnimplementedError('toCbor not supported.');
  }

  // Static method to parse a COSE key
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

  // Static method to get supported algorithms
  static List<int> supportedAlgorithms() {
    return [ES256.algorithm];
  }
}

class UnsupportedKey extends CoseKey {
  UnsupportedKey(super.coseKeyParams);
}

class ES256 extends CoseKey {
  static const int algorithm = -7;

  ES256(super.coseKeyParams);

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
}

class EcdhEsHkdf256 extends CoseKey {
  static const int algorithm = -25;

  EcdhEsHkdf256(super.coseKeyParams);

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
}
