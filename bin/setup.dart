import 'dart:io';
import 'dart:isolate';

/// Build from a checkout or installed package: dart run fido2:setup [--web]
/// [--output=build/fido2]. Rust/Cargo and (for Web) wasm-pack are prerequisites.
Future<void> main(List<String> arguments) async {
  if (arguments.any((arg) => arg != '--web' && !arg.startsWith('--output='))) {
    stderr.writeln(
      'Usage: dart run fido2:setup [--web] [--output=build/fido2]',
    );
    exitCode = 64;
    return;
  }
  final library = await Isolate.resolvePackageUri(
    Uri.parse('package:fido2/fido2.dart'),
  );
  if (library == null) throw StateError('Cannot locate fido2 package');
  final root = File.fromUri(library).parent.parent.path;
  final output = Directory(
    arguments
            .where((a) => a.startsWith('--output='))
            .map((a) => a.substring('--output='.length))
            .firstOrNull ??
        'build/fido2',
  ).absolute;
  output.createSync(recursive: true);
  final web = arguments.contains('--web');
  final command = web ? 'wasm-pack' : 'cargo';
  final args = web
      ? [
          'build',
          '$root/rust',
          '--target',
          'web',
          '--out-dir',
          '${output.path}/web',
          '--release',
          '--locked',
        ]
      : [
          'build',
          '--manifest-path',
          '$root/rust/Cargo.toml',
          '--locked',
          '--release',
          '--target-dir',
          '${output.path}/native',
        ];
  final process = await Process.start(
    command,
    args,
    mode: ProcessStartMode.inheritStdio,
  );
  exitCode = await process.exitCode;
  if (exitCode != 0) return;
  if (web) {
    File(
      '$root/web/fido2_crypto_loader.js',
    ).copySync('${output.path}/web/fido2_crypto_loader.js');
    stdout.writeln('Web backend: ${output.path}/web/fido2_crypto.js');
  } else {
    final name = Platform.isWindows
        ? 'fido2_crypto.dll'
        : Platform.isMacOS
        ? 'libfido2_crypto.dylib'
        : 'libfido2_crypto.so';
    stdout.writeln(
      'RustCrypto.initialize(libraryPath: ${output.path}/native/release/$name)',
    );
  }
}
