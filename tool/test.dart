import 'dart:io';

Future<void> main(List<String> arguments) async {
  final name = Platform.isWindows
      ? 'fido2_crypto.dll'
      : Platform.isMacOS
      ? 'libfido2_crypto.dylib'
      : 'libfido2_crypto.so';
  final library = File('build/fido2/native/release/$name').absolute.path;
  final process = await Process.start(
    Platform.resolvedExecutable,
    ['test', ...arguments],
    environment: {'FIDO2_CRYPTO_LIBRARY': library},
    mode: ProcessStartMode.inheritStdio,
  );
  exitCode = await process.exitCode;
}
