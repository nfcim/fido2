/// Configuration for the WebAuthn server.
class WebAuthnConfig {
  /// The ID of the Relying Party. Typically the domain of your web service.
  final String rpId;

  /// The human-readable name of the Relying Party.
  final String rpName;

  /// A secret key known only to the server, used to sign stateless session data.
  /// This MUST be kept secret and should be a long, random string.
  final List<int> rpSecret;

  WebAuthnConfig({
    required this.rpId,
    required this.rpName,
    required this.rpSecret,
  });
}
