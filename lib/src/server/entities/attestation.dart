import 'package:json_annotation/json_annotation.dart';
import '../../utils/serialization.dart';

part 'attestation.g.dart';

/// WebAuthn attestation conveyance preference sent to the client.
enum AttestationConveyancePreference { none, indirect, direct, enterprise }

/// The kind of proof verified during registration, independent of trust.
enum AttestationType { none, self, basic }

/// Verified attestation evidence. A valid signature does not establish trust in
/// the authenticator vendor. Validate [trustPath] against application trust
/// anchors/metadata before relying on device identity.
@JsonSerializable(createFactory: false, explicitToJson: true)
class AttestationResult with JsonToStringMixin {
  final String format;
  final AttestationType type;
  final List<int> aaguid;

  /// DER certificates in leaf-first order; empty for none/self attestation.
  final List<List<int>> trustPath;

  AttestationResult({
    required this.format,
    required this.type,
    required List<int> aaguid,
    List<List<int>> trustPath = const [],
  }) : aaguid = List.unmodifiable(aaguid),
       trustPath = List.unmodifiable(trustPath.map(List<int>.unmodifiable));

  @override
  Map<String, dynamic> toJson() => _$AttestationResultToJson(this);
}

/// Optional synchronous application policy, called after protocol and signature
/// validation for every registration (including none/self). Return false to
/// reject. For basic attestation, the application owns certificate path,
/// validity, revocation and metadata trust checks.
typedef AttestationVerifier = bool Function(AttestationResult attestation);
