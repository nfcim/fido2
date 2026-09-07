import '../cose.dart';

class Fido2Config {
  final String rpId;
  final String rpName;
  final Set<String> origins;
  final List<int> signatureAlgorithms;
  final CoseConfiguration cose;
  final bool requireUserVerification;

  Fido2Config({
    required this.rpId,
    String? rpName,
    Set<String>? origins,
    List<int> signatureAlgorithms = const [ES256.algorithm, Ed25519.algorithm],
    CoseConfiguration? cose,
    this.requireUserVerification = false,
  }) : rpName = rpName ?? rpId,
       origins = Set.unmodifiable(origins ?? {'https://$rpId'}),
       signatureAlgorithms = List.unmodifiable(signatureAlgorithms),
       cose = cose ?? CoseConfiguration() {
    if (rpId.isEmpty ||
        this.origins.isEmpty ||
        signatureAlgorithms.isEmpty ||
        signatureAlgorithms.toSet().length != signatureAlgorithms.length) {
      throw ArgumentError(
        'RP, origins, and unique ordered signature algorithms are required',
      );
    }
    for (final algorithm in signatureAlgorithms) {
      if (this.cose.resolve(algorithm) == null) {
        throw ArgumentError('Unsupported signature algorithm $algorithm');
      }
    }
    for (final origin in this.origins) {
      final uri = Uri.parse(origin);
      if (uri.userInfo.isNotEmpty ||
          uri.hasQuery ||
          uri.hasFragment ||
          uri.path.isNotEmpty ||
          uri.host.isEmpty ||
          (uri.scheme != 'https' &&
              !(uri.scheme == 'http' && uri.host == 'localhost')) ||
          (uri.host != rpId && !uri.host.endsWith('.$rpId'))) {
        throw ArgumentError('Invalid origin or RP relationship: $origin');
      }
    }
  }
}
