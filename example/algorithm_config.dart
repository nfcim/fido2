import 'package:fido2/fido2.dart';

void main() async {
  await RustCrypto.initialize();
  final sm2 = Sm2Configuration(
    algorithm: -65537,
    curve: -65537,
    id: '1234567812345678',
    signatureEncoding: SignatureEncoding.raw,
  );
  final cose = CoseConfiguration(sm2: sm2);
  final configurations = [
    Fido2Config(rpId: 'example.com', origins: {'https://example.com'}),
    Fido2Config(
        rpId: 'example.com',
        origins: {'https://example.com'},
        cose: cose,
        signatureAlgorithms: [sm2.algorithm]),
    Fido2Config(
        rpId: 'example.com',
        origins: {'https://example.com'},
        signatureAlgorithms: [MLDSA65.algorithm]),
    Fido2Config(
        rpId: 'example.com',
        origins: {'https://example.com'},
        cose: cose,
        signatureAlgorithms: [
          MLDSA87.algorithm,
          sm2.algorithm,
          ES256.algorithm,
          Ed25519.algorithm
        ]),
  ];
  for (final config in configurations) {
    final request = Fido2Server(config).registerBegin(
      PublicKeyCredentialUserEntity(
          id: [1], name: 'alice', displayName: 'Alice'),
    );
    print(request.publicKey);
    // Persist challenge, offeredAlgorithms and the user's ID with the session.
    // Pass these to registerComplete, using userHandle for the trusted user ID.
  }
}
