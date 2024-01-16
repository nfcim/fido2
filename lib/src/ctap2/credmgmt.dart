import 'package:cbor/simple.dart';
import 'package:fido2/src/ctap.dart';
import 'package:fido2/src/ctap2/base.dart';
import 'package:fido2/src/ctap2/pin.dart';

enum CredentialManagementSubCommand {
  getCredsMetadata(0x01),
  enumerateRpsBegin(0x02),
  enumerateRpsGetNextRp(0x03),
  enumerateCredentialsBegin(0x04),
  enumerateCredentialsGetNextCredential(0x05),
  deleteCredential(0x06),
  updateUserInformation(0x07);

  const CredentialManagementSubCommand(this.value);

  final int value;
}

enum CredentialManagementSubCommandParams {
  rpIdHash(0x01),
  credentialId(0x02),
  user(0x03);

  const CredentialManagementSubCommandParams(this.value);

  final int value;
}

class CredentialManagement {
  final Ctap2 _ctap;
  final PinProtocol _pinProtocol;
  final List<int> _pinToken;

  CredentialManagement(this._ctap, this._pinProtocol, this._pinToken) {
    if (!isSupported(_ctap.info)) {
      throw UnsupportedError(
          'The authenticator does not support CredentialManagement command.');
    }
  }

  /// Returns true if the authenticator [info] supports the CredentialManagement command.
  static bool isSupported(AuthenticatorInfo info) {
    return info.options?.containsKey('credMgmt') ?? false;
  }

  Future<CredentialManagementResponse> getMetadata() async {
    final resp =
        await _invoke(CredentialManagementSubCommand.getCredsMetadata.value);
    if (resp.status != 0) {
      throw CtapException(resp.status);
    }
    return resp.data!;
  }

  Future<CtapResponse<CredentialManagementResponse?>> _invoke(int subCommand,
      {Map<int, dynamic>? params, bool auth = true}) async {
    List<int>? pinUvAuthParam;
    if (auth) {
      final msg = [subCommand];
      if (params != null) {
        msg.addAll(cbor.encode(params));
      }
      pinUvAuthParam = await _pinProtocol.authenticate(_pinToken, msg);
    }
    return await _ctap.credentialManagement(CredentialManagementRequest(
      subCommand: subCommand,
      params: params,
      pinUvAuthProtocol: _pinProtocol.version,
      pinUvAuthParam: pinUvAuthParam,
    ));
  }
}
