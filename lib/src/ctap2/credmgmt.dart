import 'package:cbor/cbor.dart';
import 'package:fido2/src/cose.dart';
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

class CmMetadata {
  final int existingResidentCredentialsCount;
  final int maxPossibleRemainingResidentCredentialsCount;

  CmMetadata({
    required this.existingResidentCredentialsCount,
    required this.maxPossibleRemainingResidentCredentialsCount,
  });
}

class CmRp {
  final PublickeyCredentialRpEntity rp;
  final List<int> rpIdHash;

  CmRp({
    required this.rp,
    required this.rpIdHash,
  });
}

class CmCredential {
  final PublicKeyCredentialUserEntity user;
  final PublicKeyCredentialDescriptor credentialId;
  final CoseKey publicKey;
  final int totalCredentials;
  final int credProtect;
  final List<int>? largeBlobKey;

  CmCredential({
    required this.user,
    required this.credentialId,
    required this.publicKey,
    required this.totalCredentials,
    required this.credProtect,
    this.largeBlobKey,
  });
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

  Future<CmMetadata> getMetadata() async {
    final resp =
        await _invoke(CredentialManagementSubCommand.getCredsMetadata.value);
    if (resp.status != 0) {
      throw CtapException(resp.status);
    }
    return CmMetadata(
      existingResidentCredentialsCount:
          resp.data!.existingResidentCredentialsCount!,
      maxPossibleRemainingResidentCredentialsCount:
          resp.data!.maxPossibleRemainingResidentCredentialsCount!,
    );
  }

  Future<CmRp> enumerateRpsBegin() async {
    final resp =
        await _invoke(CredentialManagementSubCommand.enumerateRpsBegin.value);
    if (resp.status != 0) {
      throw CtapException(resp.status);
    }
    return CmRp(
      rp: resp.data!.rp!,
      rpIdHash: resp.data!.rpIdHash!,
    );
  }

  Future<CmRp> enumerateRpsGetNextRp() async {
    final resp = await _invoke(
        CredentialManagementSubCommand.enumerateRpsGetNextRp.value,
        auth: false);
    if (resp.status != 0) {
      throw CtapException(resp.status);
    }
    return CmRp(
      rp: resp.data!.rp!,
      rpIdHash: resp.data!.rpIdHash!,
    );
  }

  Future<CmCredential> enumerateCredentialsBegin(List<int> rpIdHash) async {
    final resp = await _invoke(
        CredentialManagementSubCommand.enumerateCredentialsBegin.value,
        params: {
          CredentialManagementSubCommandParams.rpIdHash.value:
              CborBytes(rpIdHash)
        });
    if (resp.status != 0) {
      throw CtapException(resp.status);
    }
    return CmCredential(
      user: resp.data!.user!,
      credentialId: resp.data!.credentialId!,
      publicKey: resp.data!.publicKey!,
      totalCredentials: resp.data!.totalCredentials!,
      credProtect: resp.data!.credProtect!,
      largeBlobKey: resp.data!.largeBlobKey,
    );
  }

  Future<CmCredential> enumerateCredentialsGetNextCredential() async {
    final resp = await _invoke(
        CredentialManagementSubCommand
            .enumerateCredentialsGetNextCredential.value,
        auth: false);
    if (resp.status != 0) {
      throw CtapException(resp.status);
    }
    return CmCredential(
      user: resp.data!.user!,
      credentialId: resp.data!.credentialId!,
      publicKey: resp.data!.publicKey!,
      totalCredentials: resp.data!.totalCredentials!,
      credProtect: resp.data!.credProtect!,
      largeBlobKey: resp.data!.largeBlobKey,
    );
  }

  Future<CtapResponse<CredentialManagementResponse?>> _invoke(int subCommand,
      {Map<int, dynamic>? params, bool auth = true}) async {
    List<int>? pinUvAuthParam;
    if (auth) {
      final msg = [subCommand];
      if (params != null) {
        msg.addAll(cbor.encode(CborValue(params)));
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
