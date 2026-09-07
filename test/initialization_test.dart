import 'package:fido2/fido2.dart';
import 'package:test/test.dart';
import 'support.dart';

void main() {
  test(
      'parsing does not initialize; operations fail until initialized; retry works',
      () async {
    expect(RustCrypto.isInitialized, isFalse);
    final key = MLDSA44.fromPublicKey(List.filled(1312, 0));
    expect(key.toCborMap(), isNotEmpty);
    expect(() => RustCrypto.sha256([]), throwsStateError);
    await expectLater(
        RustCrypto.initialize(
            libraryPath: '/does-not-exist/fido2',
            wasmModuleUrl: './does-not-exist.js'),
        throwsA(anything));
    expect(RustCrypto.isInitialized, isFalse);
    final pending = initializeCrypto();
    await expectLater(
        RustCrypto.initialize(wasmModuleUrl: 'different.js'), throwsStateError);
    await Future.wait([pending, initializeCrypto()]);
    expect(RustCrypto.isInitialized, isTrue);
    expect(RustCrypto.sha256([]), hasLength(32));
    await initializeCrypto();
    await expectLater(
        RustCrypto.initialize(libraryPath: 'different'), throwsStateError);
  });
}
