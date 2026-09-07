import 'package:fido2/fido2.dart';

Future<void> initializeCrypto() =>
    RustCrypto.initialize(wasmModuleUrl: '../build/fido2/web/fido2_crypto.js');
