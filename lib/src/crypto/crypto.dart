import 'dart:convert';
import 'dart:typed_data';

import 'backend_stub.dart'
    if (dart.library.ffi) 'backend_native.dart'
    if (dart.library.js_interop) 'backend_web.dart'
    as backend;

class CryptoException implements Exception {
  final String code;
  const CryptoException(this.code);
  @override
  String toString() => 'CryptoException: $code';
}

/// All cryptographic operations use the shared Rust native/WASM core.
class RustCrypto {
  static bool _ready = false;
  static Future<void>? _initializing;
  static String? _libraryPath;
  static String? _wasmModuleUrl;
  static bool get isInitialized => _ready;

  /// Loads the backend once per isolate. Repeated calls require identical options.
  static Future<void> initialize({String? libraryPath, String? wasmModuleUrl}) {
    if ((_ready || _initializing != null) &&
        (libraryPath != _libraryPath || wasmModuleUrl != _wasmModuleUrl)) {
      return Future.error(
        StateError('Rust backend initialization configuration differs'),
      );
    }
    if (_ready) return Future.value();
    _libraryPath = libraryPath;
    _wasmModuleUrl = wasmModuleUrl;
    return _initializing ??= _initialize(libraryPath, wasmModuleUrl);
  }

  static Future<void> _initialize(String? path, String? url) async {
    try {
      await backend.initialize(libraryPath: path, wasmModuleUrl: url);
      final response = _invoke({'op': 'version'});
      if (response.length != 1 || response.single != 1) {
        throw StateError('Unsupported Rust backend ABI');
      }
      _ready = true;
    } finally {
      _initializing = null;
    }
  }

  static Uint8List _invoke(Map<String, Object> request) {
    final wire = Uint8List.fromList(utf8.encode(jsonEncode(request)));
    if (wire.length > 1024 * 1024) {
      wire.fillRange(0, wire.length, 0);
      throw const CryptoException('invalid_length');
    }
    Uint8List? response;
    try {
      response = backend.invoke(wire);
      final decoded = jsonDecode(utf8.decode(response)) as Map<String, dynamic>;
      if (decoded['error'] != null) {
        throw CryptoException(decoded['error'] as String);
      }
      return Uint8List.fromList((decoded['data'] as List).cast<int>());
    } finally {
      wire.fillRange(0, wire.length, 0);
      response?.fillRange(0, response.length, 0);
    }
  }

  static Uint8List _call(Map<String, Object> request) {
    if (!_ready) {
      throw StateError('Call and await RustCrypto.initialize() first');
    }
    return _invoke(request);
  }

  static Uint8List sha256(List<int> message) =>
      _call({'op': 'sha256', 'message': message});
  static Uint8List sm3(List<int> message) =>
      _call({'op': 'sm3', 'message': message});
  static Uint8List randomBytes(int length) =>
      _call({'op': 'random', 'length': length});
  static Uint8List hmacSha256(List<int> key, List<int> message) =>
      _call({'op': 'hmac', 'key': key, 'message': message});
  static bool verifyHmacSha256(
    List<int> key,
    List<int> message,
    List<int> signature,
  ) =>
      _call({
        'op': 'hmac_verify',
        'key': key,
        'message': message,
        'signature': signature,
      }).single ==
      1;
  static bool constantTimeEquals(List<int> a, List<int> b) =>
      _call({'op': 'equal', 'key': a, 'message': b}).single == 1;
  static Uint8List hkdfSha256(
    List<int> key, {
    required List<int> salt,
    required List<int> info,
    int length = 32,
  }) => _call({
    'op': 'hkdf',
    'key': key,
    'salt': salt,
    'info': info,
    'length': length,
  });
  static Uint8List aes256Cbc(
    List<int> key,
    List<int> message, {
    required List<int> iv,
    bool decrypt = false,
  }) => _call({
    'op': decrypt ? 'aes_decrypt' : 'aes_encrypt',
    'key': key,
    'message': message,
    'iv': iv,
  });

  /// Returns SEC1 uncompressed public key (65 bytes), followed by the derived
  /// PIN shared secret (32 bytes for v1, 64 for v2). Private key stays in Rust.
  static Uint8List encapsulatePin(List<int> peerPublicKey, int version) =>
      _call({
        'op': 'pin_encapsulate',
        'key': peerPublicKey,
        'version': version,
      });

  static void validatePublicKey(String algorithm, List<int> key) {
    _call({'op': 'validate', 'algorithm': algorithm, 'key': key});
  }

  /// Low-level Pure ML-DSA permits a context up to 255 bytes. COSE RFC 9964
  /// requires empty context.
  static bool verify(
    String algorithm,
    List<int> key,
    List<int> message,
    List<int> signature, {
    String encoding = 'raw',
    String sm2Id = '1234567812345678',
    String mlDsaMode = 'pure',
    List<int> context = const [],
  }) =>
      _call({
        'op': 'verify',
        'algorithm': algorithm,
        'key': key,
        'message': message,
        'signature': signature,
        'encoding': encoding,
        'id': sm2Id,
        'mode': mlDsaMode,
        'context': context,
      }).single ==
      1;
}
