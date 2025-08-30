import 'dart:collection';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' as crypto_api;
import 'package:pointycastle/export.dart' as pc;
import 'package:asn1lib/asn1lib.dart' as asn1;

import 'package:cbor/cbor.dart';
import 'package:fido2/src/utils/serialization.dart';

/// Represents a key as specified by RFC8152:
/// [CBOR Object Signing and Encryption (COSE)](https://tools.ietf.org/html/rfc8152)
///
/// Extended this class to support more COSE key types.
sealed class CoseKey extends MapView<int, dynamic> with JsonToStringMixin {
  // Key Objects (RFC8152 Section 7.1)
  static const int ktyIdx = 1;
  static const int algIdx = 3;

  // Key Types (RFC8152 Section 13)
  static const int ktyOKP = 1;
  static const int ktyEC2 = 2;

  // EC2 Keys (RFC8152 Section 13.1.1)
  static const int ec2CrvIdx = -1;
  static const int ec2XIdx = -2;
  static const int ec2YIdx = -3;

  // EC2 Curves (RFC8152 Section 13.1)
  static const int ec2CrvP256 = 1;

  // OKP Keys (RFC8152 Section 13.2)
  static const int okpCrvIdx = -1;
  static const int okpXIdx = -2;

  // OKP Curves (RFC8152 Section 13.1)
  static const int okpCrvEd25519 = 6;

  static const int? algorithm = null;

  /// Constructor with optional parameters
  CoseKey(super.coseKeyParams);

  /// Verifies a signature for the provided message using this COSE public key.
  ///
  /// Throws an [Exception] if verification fails or the algorithm is unsupported.
  Future<void> verify(List<int> message, List<int> signature) async {
    throw UnimplementedError('Signature verification not supported.');
  }

  /// Convert to a CBOR Map representation suitable for passing through APIs
  /// that expect a [CborMap] (e.g., server verification inputs).
  CborMap toCborMap() {
    throw UnimplementedError('toCborMap not supported.');
  }

  /// Convert to standard CBOR encoded format
  CborValue toCbor() {
    return CborValue(toCborMap());
  }

  /// Static method to parse a COSE key
  static CoseKey parse(Map<int, dynamic> cose) {
    int? alg = cose[algIdx];
    if (alg == null) {
      throw ArgumentError('COSE alg identifier must be provided.');
    }
    switch (alg) {
      case ES256.algorithm:
        return ES256(cose);
      case EdDSA.algorithm:
        return EdDSA(cose);
      case EcdhEsHkdf256.algorithm:
        return EcdhEsHkdf256(cose);
    }
    return UnsupportedKey(cose);
  }

  /// Static method to get all algorithms supported by fido2 library
  static List<int> supportedAlgorithms() {
    return [ES256.algorithm, EdDSA.algorithm, EcdhEsHkdf256.algorithm];
  }

  @override
  Map<String, dynamic> toJson() {
    final map = <String, dynamic>{};
    forEach((key, value) {
      map[key.toString()] = value;
    });
    return map;
  }
}

/// Represents a currently unsupported COSE key type
class UnsupportedKey extends CoseKey {
  UnsupportedKey(super.coseKeyParams);
}

/// Represents a COSE key of type EdDSA (Ed25519, see RFC8152 8.2)
class EdDSA extends CoseKey {
  static const int algorithm = -8;

  EdDSA(super.coseKeyParams);

  /// Static method to create a new instance from public key coordinates
  static EdDSA fromPublicKey(List<int> x) {
    return EdDSA({
      CoseKey.ktyIdx: CoseKey.ktyOKP,
      CoseKey.algIdx: EdDSA.algorithm,
      CoseKey.okpCrvIdx: CoseKey.okpCrvEd25519,
      CoseKey.okpXIdx: x,
    });
  }

  @override
  CborMap toCborMap() {
    return CborMap({
      CborInt(BigInt.from(CoseKey.ktyIdx)):
          CborInt(BigInt.from(CoseKey.ktyOKP)),
      CborInt(BigInt.from(CoseKey.algIdx)):
          CborInt(BigInt.from(EdDSA.algorithm)),
      CborInt(BigInt.from(CoseKey.okpCrvIdx)):
          CborInt(BigInt.from(CoseKey.okpCrvEd25519)),
      CborInt(BigInt.from(CoseKey.okpXIdx)): CborBytes(this[CoseKey.okpXIdx]),
    });
  }

  @override
  Future<void> verify(List<int> message, List<int> signature) async {
    final xBytes = this[CoseKey.okpXIdx] as List<int>?;
    if (xBytes == null) {
      throw Exception('Ed25519 verification failed: missing public key (x).');
    }
    // Ed25519 signatures must be exactly 64 bytes (R || S)
    if (signature.length != 64) {
      throw Exception(
          'Assertion signature verification failed (Ed25519): invalid signature length ${signature.length}, expected 64 bytes.');
    }
    final pubKey = crypto_api.SimplePublicKey(
      xBytes,
      type: crypto_api.KeyPairType.ed25519,
    );
    final verified = await crypto_api.Ed25519().verify(
      message,
      signature: crypto_api.Signature(signature, publicKey: pubKey),
    );
    if (!verified) {
      throw Exception('Assertion signature verification failed (Ed25519).');
    }
  }
}

/// Represents a COSE key of type ES256 (ECDSA w/ SHA-256, see RFC8152 8.1)
class ES256 extends CoseKey {
  static const int algorithm = -7;

  ES256(super.coseKeyParams);

  /// Static method to create a new instance from public key coordinates
  static ES256 fromPublicKey(List<int> x, List<int> y) {
    return ES256({
      CoseKey.ktyIdx: CoseKey.ktyEC2,
      CoseKey.algIdx: ES256.algorithm,
      CoseKey.ec2CrvIdx: CoseKey.ec2CrvP256,
      CoseKey.ec2XIdx: x,
      CoseKey.ec2YIdx: y,
    });
  }

  @override
  CborMap toCborMap() {
    return CborMap({
      CborInt(BigInt.from(CoseKey.ktyIdx)):
          CborInt(BigInt.from(CoseKey.ktyEC2)),
      CborInt(BigInt.from(CoseKey.algIdx)):
          CborInt(BigInt.from(ES256.algorithm)),
      CborInt(BigInt.from(CoseKey.ec2CrvIdx)):
          CborInt(BigInt.from(CoseKey.ec2CrvP256)),
      CborInt(BigInt.from(CoseKey.ec2XIdx)): CborBytes(this[CoseKey.ec2XIdx]),
      CborInt(BigInt.from(CoseKey.ec2YIdx)): CborBytes(this[CoseKey.ec2YIdx]),
    });
  }

  @override
  Future<void> verify(List<int> message, List<int> signature) async {
    final xBytes = this[CoseKey.ec2XIdx] as List<int>?;
    final yBytes = this[CoseKey.ec2YIdx] as List<int>?;
    if (xBytes == null || yBytes == null) {
      throw Exception('ES256 verification failed: missing public key x/y.');
    }

    // Parse ASN.1 DER ECDSA signature: SEQUENCE(INTEGER r, INTEGER s)
    BigInt bytesToInt(List<int> bytes) =>
        bytes.fold<BigInt>(BigInt.zero, (a, b) => (a << 8) | BigInt.from(b));
    final parser = asn1.ASN1Parser(Uint8List.fromList(signature));
    final obj = parser.nextObject();
    if (obj is! asn1.ASN1Sequence || obj.elements.length != 2) {
      throw Exception('ES256 verification failed: malformed DER signature.');
    }
    // Reject trailing bytes beyond the DER SEQUENCE
    // If the parser can continue, the signature contains extra data.
    if (parser.hasNext()) {
      throw Exception(
          'ES256 verification failed: trailing bytes present in DER signature.');
    }
    final rObj = obj.elements[0];
    final sObj = obj.elements[1];
    if (rObj is! asn1.ASN1Integer || sObj is! asn1.ASN1Integer) {
      throw Exception(
          'ES256 verification failed: DER must contain two integers.');
    }
    final rBytes = rObj.valueBytes();
    final sBytes = sObj.valueBytes();
    final r = bytesToInt(rBytes);
    var s = bytesToInt(sBytes);

    // Build PointyCastle public key
    final domain = pc.ECDomainParameters('secp256r1');
    final q = domain.curve.createPoint(bytesToInt(xBytes), bytesToInt(yBytes));
    final pubKey = pc.ECPublicKey(q, domain);

    // Low-S normalization to prevent malleability: use s = min(s, n - s)
    final n = domain.n;
    final halfN = n >> 1;
    if (s > halfN) {
      s = n - s;
    }

    // Verify using SHA-256/ECDSA
    final verifier = pc.Signer('SHA-256/ECDSA');
    verifier.init(false, pc.PublicKeyParameter<pc.ECPublicKey>(pubKey));
    final ok = verifier.verifySignature(
        Uint8List.fromList(message), pc.ECSignature(r, s));
    if (!ok) {
      throw Exception('Assertion signature verification failed (ES256).');
    }
  }
}

/// Represents a COSE key of type ECDH-ES+HKDF-256 (see RFC8152 11.1)
class EcdhEsHkdf256 extends CoseKey {
  static const int algorithm = -25;

  EcdhEsHkdf256(super.coseKeyParams);

  /// Static method to create a new instance from public key coordinates
  static EcdhEsHkdf256 fromPublicKey(List<int> x, List<int> y) {
    return EcdhEsHkdf256({
      CoseKey.ktyIdx: CoseKey.ktyEC2,
      CoseKey.algIdx: EcdhEsHkdf256.algorithm,
      CoseKey.ec2CrvIdx: CoseKey.ec2CrvP256,
      CoseKey.ec2XIdx: x,
      CoseKey.ec2YIdx: y,
    });
  }

  @override
  CborMap toCborMap() {
    return CborMap({
      CborInt(BigInt.from(CoseKey.ktyIdx)):
          CborInt(BigInt.from(CoseKey.ktyEC2)),
      CborInt(BigInt.from(CoseKey.algIdx)):
          CborInt(BigInt.from(EcdhEsHkdf256.algorithm)),
      CborInt(BigInt.from(CoseKey.ec2CrvIdx)):
          CborInt(BigInt.from(CoseKey.ec2CrvP256)),
      CborInt(BigInt.from(CoseKey.ec2XIdx)): CborBytes(this[CoseKey.ec2XIdx]),
      CborInt(BigInt.from(CoseKey.ec2YIdx)): CborBytes(this[CoseKey.ec2YIdx]),
    });
  }
}
