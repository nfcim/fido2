import '../cose.dart';
import 'entities/attestation.dart';

class Fido2Config {
  final String rpId;
  final String rpName;
  final Set<String> origins;
  final List<int> signatureAlgorithms;
  final CoseConfiguration cose;
  final bool requireUserVerification;

  /// Client conveyance preference; independent of the accepted response formats.
  final AttestationConveyancePreference attestation;

  /// Accepted formats. Defaults to none/packed; use {'none'} for the old policy.
  final Set<String> attestationFormats;

  /// Optional application trust policy, applied after protocol verification.
  /// Without it, packed signatures are checked but vendor trust is not asserted.
  final AttestationVerifier? attestationVerifier;

  Fido2Config({
    required this.rpId,
    String? rpName,
    Set<String>? origins,
    List<int> signatureAlgorithms = const [ES256.algorithm, Ed25519.algorithm],
    CoseConfiguration? cose,
    this.requireUserVerification = false,
    this.attestation = AttestationConveyancePreference.none,
    Set<String> attestationFormats = const {'none', 'packed'},
    this.attestationVerifier,
  }) : rpName = rpName ?? rpId,
       origins = Set.unmodifiable(origins ?? {'https://$rpId'}),
       signatureAlgorithms = List.unmodifiable(signatureAlgorithms),
       attestationFormats = Set.unmodifiable(attestationFormats),
       cose = cose ?? CoseConfiguration() {
    if (this.attestationFormats.isEmpty ||
        this.attestationFormats.any(
          (fmt) => fmt != 'none' && fmt != 'packed',
        )) {
      throw ArgumentError('Supported attestation formats: none, packed');
    }
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
