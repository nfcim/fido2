import 'dart:convert';
import 'package:cbor/cbor.dart';
import 'package:cryptography/cryptography.dart' as reference;
import 'package:fido2/fido2.dart';
import 'package:test/test.dart';
import 'support.dart';

String b64(List<int> value) => base64Url.encode(value).replaceAll('=', '');

void main() {
  setUpAll(initializeCrypto);
  test(
    'verified BS transitions in both directions; BE and signature enforced',
    () async {
      final signer = reference.Ed25519();
      final pair = await signer.newKeyPairFromSeed(List.filled(32, 7));
      final key = Ed25519.fromPublicKey((await pair.extractPublicKey()).bytes);
      final server = Fido2Server(
        Fido2Config(rpId: 'example.com', origins: {'https://example.com'}),
      );
      final challenge = List.filled(32, 42);
      final client = utf8.encode(
        jsonEncode({
          'type': 'webauthn.get',
          'origin': 'https://example.com',
          'challenge': b64(challenge),
        }),
      );
      final rpHash = RustCrypto.sha256(utf8.encode('example.com'));
      for (final previous in [false, true]) {
        final stored = RegisteredCredential(
          id: [1],
          publicKey: key,
          backupEligible: true,
          backedUp: previous,
        );
        for (final current in [false, true]) {
          final auth = [...rpHash, current ? 0x19 : 0x09, 0, 0, 0, 1];
          final signature = await signer.sign([
            ...auth,
            ...RustCrypto.sha256(client),
          ], keyPair: pair);
          final assertion = <String, dynamic>{
            'type': 'public-key',
            'id': b64([1]),
            'rawId': b64([1]),
            'response': {
              'clientDataJSON': b64(client),
              'authenticatorData': b64(auth),
              'signature': b64(signature.bytes),
            },
          };
          final result = server.authenticateCompleteResult(
            assertion,
            credential: stored,
            expectedChallenge: challenge,
          );
          expect(result.backedUp, current);
          expect(result.signCount, 1);
          expect(
            () => server.authenticateCompleteResult(
              assertion,
              credential: RegisteredCredential(id: [1], publicKey: key),
              expectedChallenge: challenge,
            ),
            throwsFormatException,
          );
          (assertion['response'] as Map)['signature'] = b64(List.filled(64, 0));
          expect(
            () => server.authenticateCompleteResult(
              assertion,
              credential: stored,
              expectedChallenge: challenge,
            ),
            throwsA(isA<CryptoException>()),
          );
        }
        final registrationAuth = [
          ...rpHash,
          previous ? 0x59 : 0x49,
          0,
          0,
          0,
          0,
          ...List.filled(16, 0),
          0,
          1,
          1,
          ...cbor.encode(key.toCbor()),
        ];
        final registered = server.registerComplete(
          {
            'type': 'public-key',
            'id': b64([1]),
            'rawId': b64([1]),
            'response': {
              'clientDataJSON': b64(
                utf8.encode(
                  jsonEncode({
                    'type': 'webauthn.create',
                    'origin': 'https://example.com',
                    'challenge': b64(challenge),
                  }),
                ),
              ),
              'attestationObject': b64(
                cbor.encode(
                  CborValue({
                    'fmt': 'none',
                    'attStmt': <String, dynamic>{},
                    'authData': CborBytes(registrationAuth),
                  }),
                ),
              ),
            },
          },
          expectedChallenge: challenge,
          userHandle: [42],
        );
        expect(registered.backedUp, previous);
        expect(registered.backupEligible, isTrue);
      }
    },
  );
}
