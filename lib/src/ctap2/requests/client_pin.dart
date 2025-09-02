import 'package:cbor/cbor.dart';
import 'package:fido2/src/cose.dart';
import '../constants.dart';
import 'package:fido2/src/utils/serialization.dart';
import 'package:json_annotation/json_annotation.dart';

part 'client_pin.g.dart';

/// CTAP2 authenticatorClientPIN (0x06) request (spec §6.5.5).
///
/// Used by platforms to perform key agreement, set/change a PIN, and obtain a
/// pinUvAuthToken using a selected PIN/UV protocol.
@JsonSerializable(createFactory: false, explicitToJson: true)
class ClientPinRequest with JsonToStringMixin {
  static const int pinUvAuthProtocolIdx = 1;
  static const int subCommandIdx = 2;
  static const int keyAgreementIdx = 3;
  static const int pinUvAuthParamIdx = 4;
  static const int newPinEncIdx = 5;
  static const int pinHashEncIdx = 6;
  static const int permissionsIdx = 9;
  static const int rpIdIdx = 10;

  /// PIN/UV protocol version selected by the platform.
  final int? pinUvAuthProtocol;

  /// Specific subCommand to execute (e.g., getPINRetries, setPIN).
  final int subCommand;

  /// Platform key-agreement public key (COSE_Key) when required by subCommand.
  final CoseKey? keyAgreement;

  /// Authenticator input MAC parameter for subCommand contexts.
  final List<int>? pinUvAuthParam;

  /// Encrypted new PIN value.
  final List<int>? newPinEnc;

  /// Encrypted proof-of-knowledge of the PIN.
  final List<int>? pinHashEnc;

  /// Bitfield of permissions for the requested token.
  final int? permissions;

  /// RP ID to bind to the permissions, if any.
  final String? rpId;

  ClientPinRequest({
    this.pinUvAuthProtocol,
    required this.subCommand,
    this.keyAgreement,
    this.pinUvAuthParam,
    this.newPinEnc,
    this.pinHashEnc,
    this.permissions,
    this.rpId,
  });

  /// Encodes this request as a CBOR map and prefixes the command byte.
  List<int> encode() {
    final map = <int, dynamic>{};
    if (pinUvAuthProtocol != null) {
      map[pinUvAuthProtocolIdx] = pinUvAuthProtocol!;
    }
    map[subCommandIdx] = subCommand;
    if (keyAgreement != null) {
      map[keyAgreementIdx] = keyAgreement!.toCbor();
    }
    if (pinUvAuthParam != null) {
      map[pinUvAuthParamIdx] = CborBytes(pinUvAuthParam!);
    }
    if (newPinEnc != null) {
      map[newPinEncIdx] = CborBytes(newPinEnc!);
    }
    if (pinHashEnc != null) {
      map[pinHashEncIdx] = CborBytes(pinHashEnc!);
    }
    if (permissions != null) {
      map[permissionsIdx] = permissions!;
    }
    if (rpId != null) {
      map[rpIdIdx] = CborString(rpId!);
    }
    return [Ctap2Commands.clientPIN.value] + cbor.encode(CborValue(map));
  }

  @override
  Map<String, dynamic> toJson() => _$ClientPinRequestToJson(this);
}

/// CTAP2 authenticatorClientPIN (0x06) response (spec §6.5.5).
///
/// Returns the authenticator's key agreement key, an encrypted pinUvAuthToken,
/// and retry counters where applicable.
@JsonSerializable(createFactory: false, explicitToJson: true)
class ClientPinResponse with JsonToStringMixin {
  static const int keyAgreementIdx = 1;
  static const int pinUvAuthTokenIdx = 2;
  static const int pinRetriesIdx = 3;
  static const int powerCycleStateIdx = 4;
  static const int uvRetriesIdx = 5;

  /// Authenticator public key for key agreement (COSE_Key).
  final CoseKey? keyAgreement;

  /// Encrypted pinUvAuthToken.
  final List<int>? pinUvAuthToken;

  /// Remaining PIN retries before lockout.
  final int? pinRetries;

  /// Whether a power cycle is required before future PIN operations.
  final bool? powerCycleState;

  /// Remaining UV retries before lockout.
  final int? uvRetries;

  ClientPinResponse({
    this.keyAgreement,
    this.pinUvAuthToken,
    this.pinRetries,
    this.powerCycleState,
    this.uvRetries,
  });

  /// Decodes a CBOR-encoded response into [ClientPinResponse].
  static ClientPinResponse decode(List<int> data) {
    final map = cbor.decode(data).toObject() as Map;
    final keyAgreementMap =
        (map[keyAgreementIdx] as Map?)?.cast<int, dynamic>();
    return ClientPinResponse(
      keyAgreement:
          keyAgreementMap != null ? CoseKey.parse(keyAgreementMap) : null,
      pinUvAuthToken: (map[pinUvAuthTokenIdx] as List?)?.cast<int>(),
      pinRetries: map[pinRetriesIdx] as int?,
      powerCycleState: map[powerCycleStateIdx] as bool?,
      uvRetries: map[uvRetriesIdx] as int?,
    );
  }

  @override
  Map<String, dynamic> toJson() => _$ClientPinResponseToJson(this);
}
