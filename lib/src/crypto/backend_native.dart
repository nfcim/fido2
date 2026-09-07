import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

typedef _AllocNative = Pointer<Uint8> Function(IntPtr);
typedef _FreeNative = Void Function(Pointer<Uint8>, IntPtr);
typedef _CallNative = Int32 Function(
    Pointer<Uint8>, IntPtr, Pointer<Uint8>, IntPtr);

late Pointer<Uint8> Function(int) _alloc;
late void Function(Pointer<Uint8>, int) _free;
late int Function(Pointer<Uint8>, int, Pointer<Uint8>, int) _call;

Future<void> initialize({String? libraryPath, String? wasmModuleUrl}) async {
  final DynamicLibrary library;
  if (Platform.isIOS && libraryPath == null) {
    library = DynamicLibrary.process();
  } else {
    final name = Platform.isWindows
        ? 'fido2_crypto.dll'
        : Platform.isMacOS
            ? 'libfido2_crypto.dylib'
            : 'libfido2_crypto.so';
    library = DynamicLibrary.open(
        libraryPath ?? Platform.environment['FIDO2_CRYPTO_LIBRARY'] ?? name);
  }
  _alloc = library.lookupFunction<_AllocNative, Pointer<Uint8> Function(int)>(
      'fido2_alloc');
  _free =
      library.lookupFunction<_FreeNative, void Function(Pointer<Uint8>, int)>(
          'fido2_free');
  _call = library.lookupFunction<_CallNative,
      int Function(Pointer<Uint8>, int, Pointer<Uint8>, int)>('fido2_call');
}

Uint8List invoke(Uint8List request) {
  const capacity = 1024 * 1024;
  final input = _alloc(request.length);
  final output = _alloc(capacity);
  try {
    if (input == nullptr || output == nullptr) {
      throw StateError('Rust wire allocation failed');
    }
    input.asTypedList(request.length).setAll(0, request);
    final length = _call(input, request.length, output, capacity);
    if (length < 0) throw StateError('Rust bridge failed ($length)');
    return Uint8List.fromList(output.asTypedList(length));
  } finally {
    _free(input, request.length);
    _free(output, capacity);
  }
}
