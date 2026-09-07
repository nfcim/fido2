import 'dart:convert';
import 'package:convert/convert.dart';
import 'package:fido2/fido2.dart';
import 'package:test/test.dart';
import 'fixtures/fixtures.dart';
import 'support.dart';

List<int> bytes(Object? value) => (value as List).cast<int>();

void main() {
  setUpAll(initializeCrypto);
  test('SHA-256, SM3, HMAC and RFC 5869 HKDF vectors', () {
    expect(hex.encode(RustCrypto.sha256(utf8.encode('abc'))),
        'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    expect(hex.encode(RustCrypto.sm3(utf8.encode('abc'))),
        '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0');
    expect(
        hex.encode(RustCrypto.hmacSha256(
            List.filled(20, 0x0b), utf8.encode('Hi There'))),
        'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7');
    expect(
        hex.encode(RustCrypto.hkdfSha256(List.filled(22, 0x0b),
            salt: hex.decode('000102030405060708090a0b0c'),
            info: hex.decode('f0f1f2f3f4f5f6f7f8f9'),
            length: 42)),
        '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865');
  });
  test('NIST SP 800-38A AES-256-CBC and invalid lengths', () {
    final key = hex.decode(
        '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4');
    final iv = hex.decode('000102030405060708090a0b0c0d0e0f');
    final plain = hex.decode('6bc1bee22e409f96e93d7e117393172a');
    final cipher = hex.decode('f58c4c04d6e5f1ba779eabfb5f7bfbd6');
    expect(RustCrypto.aes256Cbc(key, plain, iv: iv), cipher);
    expect(RustCrypto.aes256Cbc(key, cipher, iv: iv, decrypt: true), plain);
    expect(() => RustCrypto.aes256Cbc(key, [1], iv: iv),
        throwsA(isA<CryptoException>()));
    expect(() => RustCrypto.randomBytes(-1), throwsA(isA<CryptoException>()));
    expect(RustCrypto.randomBytes(32), hasLength(32));
    expect(RustCrypto.constantTimeEquals([1], [1, 0]), isFalse);
  });
  test('RFC 8032 Ed25519 test 1', () {
    final key = Ed25519.fromPublicKey(hex.decode(
        'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'));
    final signature = hex.decode(
        'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b');
    key.verify([], signature);
    expect(() => key.verify([1], signature), throwsA(isA<CryptoException>()));
    expect(() => Ed25519.fromPublicKey(List.filled(32, 0)).validate(),
        throwsA(isA<CryptoException>()));
  });
  test('RFC 6979 P-256 SHA-256 sample (high S accepted)', () {
    final key = ES256.fromPublicKey(
        hex.decode(
            '60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6'),
        hex.decode(
            '7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299'));
    final sig = hex.decode(
        'EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8');
    key.verify(utf8.encode('sample'), sig, encoding: SignatureEncoding.raw);
    expect(() => key.verify(utf8.encode('sample'), sig),
        throwsA(isA<CryptoException>()));
  });
  group('SM2 GB/T 32918.2 example', () {
    final profile = Sm2Configuration(algorithm: -65537, curve: -65537);
    final key = SM2.fromPublicKey(
        hex.decode(
            '09F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F35020'),
        hex.decode(
            'CCEA490CE26775A52DC6EA718CC1AA600AED05FBF35E084A6632F6072DA9AD13'),
        configuration: profile);
    final raw = hex.decode(
        'F5A03B0648D2C4630EEAC513E1BB81A15944DA3827D5B74143AC7EACEEE720B3B1B6AA29DF212FD8763182BC0D421CA1BB9038FD1F7F42D4840B69C485BBC1AA');
    final message = utf8.encode('message digest');
    final der = [
      0x30,
      0x46,
      2,
      0x21,
      0,
      ...raw.sublist(0, 32),
      2,
      0x21,
      0,
      ...raw.sublist(32)
    ];
    test('valid raw and explicit DER', () {
      key.validate();
      key.verify(message, raw);
      key.verify(message, der, encoding: SignatureEncoding.der);
    });
    test('wrong ID, message, key, and signature', () {
      expect(() => key.verify(message, raw, sm2Id: 'wrong'),
          throwsA(isA<CryptoException>()));
      expect(() => key.verify([0, ...message], raw),
          throwsA(isA<CryptoException>()));
      final changed = [...raw]..[10] ^= 1;
      expect(
          () => key.verify(message, changed), throwsA(isA<CryptoException>()));
      expect(
          () => SM2
              .fromPublicKey(List.filled(32, 0), List.filled(32, 0),
                  configuration: profile)
              .validate(),
          throwsA(isA<CryptoException>()));
      expect(
          () => SM2
              .fromPublicKey(List.filled(32, 255), bytes(key[-3]),
                  configuration: profile)
              .validate(),
          throwsA(isA<CryptoException>()));
    });
    test('raw and DER encoding boundaries', () {
      for (final bad in [
        der,
        raw.sublist(1),
        [...raw, 0],
        List.filled(64, 0)
      ]) {
        expect(() => key.verify(message, bad), throwsA(isA<CryptoException>()));
      }
      for (final bad in [
        raw,
        der.sublist(0, der.length - 1),
        [...der, 0],
        [0x30, 0x81, 0x46, ...der.sublist(2)],
        [0x30, 6, 2, 1, 0, 2, 1, 0]
      ]) {
        expect(() => key.verify(message, bad, encoding: SignatureEncoding.der),
            throwsA(isA<CryptoException>()));
      }
      expect(
          () => Sm2Configuration(
              algorithm: -65537, curve: -65537, id: 'x' * 8192),
          throwsArgumentError);
    });
  });
  final fixtures = jsonDecode(fixtureJson) as Map;
  for (final entry in fixtures['rfc9964'] as List) {
    test('RFC 9964 ${entry['source']}', () {
      final algorithm = entry['algorithm'] as String;
      final key = bytes(entry['key']);
      final message = bytes(entry['message']);
      final sig = bytes(entry['signature']);
      expect(RustCrypto.verify(algorithm, key, message, sig), isTrue);
      expect(RustCrypto.verify(algorithm, key, [0, ...message], sig), isFalse);
      final wrongKey = [...key]..[0] ^= 1;
      expect(RustCrypto.verify(algorithm, wrongKey, message, sig), isFalse);
      expect(
          () =>
              RustCrypto.verify(algorithm, key, message, sig, encoding: 'der'),
          throwsA(isA<CryptoException>()));
      expect(() => RustCrypto.verify(algorithm, key.sublist(1), message, sig),
          throwsA(isA<CryptoException>()));
      expect(() => RustCrypto.verify(algorithm, key, message, sig.sublist(1)),
          throwsA(isA<CryptoException>()));
      expect(RustCrypto.verify(algorithm, key, message, sig, context: [1]),
          isFalse);
      expect(
          () => RustCrypto.verify(algorithm, key, message, sig,
              context: List.filled(256, 1)),
          throwsA(isA<CryptoException>()));
      expect(
          () => RustCrypto.verify(algorithm, key, message, sig,
              mlDsaMode: 'hash'),
          throwsA(isA<CryptoException>()));
      final changed = [...sig]..[0] ^= 1;
      expect(RustCrypto.verify(algorithm, key, message, changed), isFalse);
      expect(
          () => RustCrypto.verify(
              algorithm == 'ml-dsa-44' ? 'ml-dsa-65' : 'ml-dsa-44',
              key,
              message,
              sig),
          throwsA(isA<CryptoException>()));
    });
  }
}
