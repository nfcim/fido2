/// Configuration for the WebAuthn server.
class Fido2Config {
  /// The ID of the Relying Party. Typically the domain of your web service.
  final String rpId;

  /// The human-readable name of the Relying Party.
  final String rpName;

  Fido2Config({
    required this.rpId,
    required this.rpName,
  });
}
