/// Configuration for the WebAuthn server.
class WebAuthnConfig {
  /// The ID of the Relying Party. Typically the domain of your web service.
  final String rpId;

  /// The human-readable name of the Relying Party.
  final String rpName;

  WebAuthnConfig({
    required this.rpId,
    required this.rpName,
  });
}
