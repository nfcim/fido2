import 'dart:typed_data';

Future<void> initialize({String? libraryPath, String? wasmModuleUrl}) =>
    throw UnsupportedError('Rust cryptography is unavailable on this platform');

Uint8List invoke(Uint8List request) =>
    throw UnsupportedError('Rust cryptography is unavailable on this platform');
