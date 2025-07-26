import 'package:cbor/cbor.dart';
import 'package:fido2/src/cose.dart';
import 'package:fido2/src/ctap.dart';
import 'package:fido2/src/ctap2/base.dart';
import 'package:fido2/src/ctap2/pin.dart';
import 'package:fido2/src/ctap2/entities/authenticator_info.dart';
import 'package:fido2/src/ctap2/entities/credential_entities.dart';
import 'package:fido2/src/ctap2/requests/credential_mgmt.dart';

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
  final PublicKeyCredentialRpEntity rp;
  final List<int> rpIdHash;
  final int? totalRPs;

  CmRp({
    required this.rp,
    required this.rpIdHash,
    this.totalRPs,
  });
}

class CmCredential {
  final PublicKeyCredentialUserEntity user;
  final PublicKeyCredentialDescriptor credentialId;
  final CoseKey publicKey;
  final int? totalCredentials;
  final int credProtect;
  final List<int>? largeBlobKey;

  CmCredential({
    required this.user,
    required this.credentialId,
    required this.publicKey,
    this.totalCredentials,
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
      throw CtapError.fromCode(resp.status);
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
      throw CtapError.fromCode(resp.status);
    }
    return CmRp(
      rp: resp.data!.rp!,
      rpIdHash: resp.data!.rpIdHash!,
      totalRPs: resp.data!.totalRPs!,
    );
  }

  Future<CmRp> enumerateRpsGetNextRp() async {
    final resp = await _invoke(
        CredentialManagementSubCommand.enumerateRpsGetNextRp.value,
        auth: false);
    if (resp.status != 0) {
      throw CtapError.fromCode(resp.status);
    }
    return CmRp(
      rp: resp.data!.rp!,
      rpIdHash: resp.data!.rpIdHash!,
    );
  }

  Future<List<CmRp>> enumerateRPs() async {
    final rps = <CmRp>[];
    var rp = await enumerateRpsBegin();
    int totalRPs = rp.totalRPs!;
    rps.add(rp);
    while (totalRPs > rps.length) {
      rp = await enumerateRpsGetNextRp();
      rps.add(rp);
    }
    return rps;
  }

  Future<CmCredential> enumerateCredentialsBegin(List<int> rpIdHash) async {
    final resp = await _invoke(
        CredentialManagementSubCommand.enumerateCredentialsBegin.value,
        params: {
          CredentialManagementSubCommandParams.rpIdHash.value:
              CborBytes(rpIdHash)
        });
    if (resp.status != 0) {
      throw CtapError.fromCode(resp.status);
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
      throw CtapError.fromCode(resp.status);
    }
    return CmCredential(
      user: resp.data!.user!,
      credentialId: resp.data!.credentialId!,
      publicKey: resp.data!.publicKey!,
      credProtect: resp.data!.credProtect!,
      largeBlobKey: resp.data!.largeBlobKey,
    );
  }

  Future<List<CmCredential>> enumerateCredentials(List<int> rpIdHash) async {
    final credentials = <CmCredential>[];
    var credential = await enumerateCredentialsBegin(rpIdHash);
    int totalCredentials = credential.totalCredentials!;
    credentials.add(credential);
    while (totalCredentials > credentials.length) {
      credential = await enumerateCredentialsGetNextCredential();
      credentials.add(credential);
    }
    return credentials;
  }

  Future<void> deleteCredential(
      PublicKeyCredentialDescriptor credentialId) async {
    final resp = await _invoke(
        CredentialManagementSubCommand.deleteCredential.value,
        params: {
          CredentialManagementSubCommandParams.credentialId.value:
              credentialId.toCbor()
        });
    if (resp.status != 0) {
      throw CtapError.fromCode(resp.status);
    }
  }

  Future<void> updateUserInformation(PublicKeyCredentialDescriptor credentialId,
      PublicKeyCredentialUserEntity user) async {
    final resp = await _invoke(
        CredentialManagementSubCommand.updateUserInformation.value,
        params: {
          CredentialManagementSubCommandParams.credentialId.value:
              credentialId.toCbor(),
          CredentialManagementSubCommandParams.user.value: user.toCbor()
        });
    if (resp.status != 0) {
      throw CtapError.fromCode(resp.status);
    }
  }

  Future<CtapResponse<CredentialManagementResponse?>> _invoke(int subCommand,
      {Map<int, dynamic>? params, bool auth = true}) async {
    CborMap? paramsMap;
    var entries = params?.entries
        .map((e) => MapEntry(CborSmallInt(e.key), CborValue(e.value)));
    if (entries != null) {
      paramsMap = CborMap.fromEntries(entries);
    }

    List<int>? pinUvAuthParam;
    if (auth) {
      final msg = [subCommand];
      if (paramsMap != null) {
        msg.addAll(cbor.encode(paramsMap));
      }
      pinUvAuthParam = await _pinProtocol.authenticate(_pinToken, msg);
    }
    return await _ctap.credentialManagement(CredentialManagementRequest(
      subCommand: subCommand,
      params: paramsMap,
      pinUvAuthProtocol: _pinProtocol.version,
      pinUvAuthParam: pinUvAuthParam,
    ));
  }
}
