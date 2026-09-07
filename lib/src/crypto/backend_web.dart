import 'dart:js_interop';
import 'dart:typed_data';

@JS('fido2Crypto.initialize')
external JSPromise<JSAny?> _initialize(JSString url);

@JS('fido2Crypto.run')
external JSUint8Array _run(JSUint8Array input);

Future<void> initialize({String? libraryPath, String? wasmModuleUrl}) async {
  await _initialize((wasmModuleUrl ?? './pkg/fido2_crypto.js').toJS).toDart;
}

Uint8List invoke(Uint8List request) => _run(request.toJS).toDart;
