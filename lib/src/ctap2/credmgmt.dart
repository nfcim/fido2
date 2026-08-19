import 'package:cbor/cbor.dart';
import 'package:fido2/src/cose.dart';
import 'package:fido2/src/ctap.dart';
import 'package:fido2/src/ctap2/base.dart';
import 'package:fido2/src/ctap2/pin.dart';
import 'package:fido2/src/ctap2/entities/authenticator_info.dart';
import 'package:fido2/src/ctap2/entities/credential_entities.dart';
import 'package:fido2/src/ctap2/requests/credential_mgmt.dart';
import 'package:fido2/src/utils/serialization.dart';
import 'package:json_annotation/json_annotation.dart';

part 'credmgmt.g.dart';

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
  user(0x03),
  metadataOnly(0x80);

  const CredentialManagementSubCommandParams(this.value);

  final int value;
}

@JsonSerializable(createFactory: false)
class CmMetadata with JsonToStringMixin {
  final int existingResidentCredentialsCount;
  final int maxPossibleRemainingResidentCredentialsCount;

  CmMetadata({
    required this.existingResidentCredentialsCount,
    required this.maxPossibleRemainingResidentCredentialsCount,
  });

  @override
  Map<String, dynamic> toJson() => _$CmMetadataToJson(this);
}

@JsonSerializable(createFactory: false, explicitToJson: true)
class CmRp with JsonToStringMixin {
  final PublicKeyCredentialRpEntity rp;
  final List<int> rpIdHash;
  final int? totalRPs;

  CmRp({required this.rp, required this.rpIdHash, this.totalRPs});

  @override
  Map<String, dynamic> toJson() => _$CmRpToJson(this);
}

@JsonSerializable(createFactory: false, explicitToJson: true)
class CmCredential with JsonToStringMixin {
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

  @override
  Map<String, dynamic> toJson() => _$CmCredentialToJson(this);
}

/// Credential fields returned by metadata-only enumeration.
///
/// Authenticators that do not support the extension may still return a
/// standard [publicKey]. In that case [metadataOnly] is false and
/// [coseAlgorithm] is read from the COSE key.
@JsonSerializable(createFactory: false, explicitToJson: true)
class CmCredentialMetadata with JsonToStringMixin {
  final PublicKeyCredentialUserEntity user;
  final PublicKeyCredentialDescriptor credentialId;
  final int coseAlgorithm;
  final bool metadataOnly;
  final CoseKey? publicKey;
  final int? totalCredentials;
  final int credProtect;
  final List<int>? largeBlobKey;

  CmCredentialMetadata({
    required this.user,
    required this.credentialId,
    required this.coseAlgorithm,
    required this.metadataOnly,
    this.publicKey,
    this.totalCredentials,
    required this.credProtect,
    this.largeBlobKey,
  });

  @override
  Map<String, dynamic> toJson() => _$CmCredentialMetadataToJson(this);
}

class CredentialManagement {
  final Ctap2 _ctap;
  final PinProtocol _pinProtocol;
  final List<int> _pinToken;

  CredentialManagement(this._ctap, this._pinProtocol, this._pinToken) {
    if (!isSupported(_ctap.info)) {
      throw UnsupportedError(
        'The authenticator does not support CredentialManagement command.',
      );
    }
  }

  /// Returns true if the authenticator [info] supports the CredentialManagement command.
  static bool isSupported(AuthenticatorInfo info) {
    return info.options?.containsKey('credMgmt') ?? false;
  }

  Future<CmMetadata> getMetadata() async {
    final resp = await _invoke(
      CredentialManagementSubCommand.getCredsMetadata.value,
    );
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
    final resp = await _invoke(
      CredentialManagementSubCommand.enumerateRpsBegin.value,
    );
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
      auth: false,
    );
    if (resp.status != 0) {
      throw CtapError.fromCode(resp.status);
    }
    return CmRp(rp: resp.data!.rp!, rpIdHash: resp.data!.rpIdHash!);
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
        CredentialManagementSubCommandParams.rpIdHash.value: CborBytes(
          rpIdHash,
        ),
      },
    );
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
          .enumerateCredentialsGetNextCredential
          .value,
      auth: false,
    );
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

  /// Enumerates credentials without requesting their full public keys.
  ///
  /// The Begin request includes the extension's private `0x80: true` parameter.
  /// GetNext requests contain no subCommandParams and inherit the mode from
  /// Begin. A standard response containing `publicKey` is accepted as a
  /// fallback for authenticators that do not support the extension.
  Future<List<CmCredentialMetadata>> enumerateCredentialsMetadataOnly(
    List<int> rpIdHash,
  ) async {
    final credentials = <CmCredentialMetadata>[];
    var credential = await _enumerateCredentialsMetadataOnlyBegin(rpIdHash);
    final totalCredentials = credential.totalCredentials!;
    credentials.add(credential);
    while (totalCredentials > credentials.length) {
      credential = await _enumerateCredentialsMetadataOnlyGetNextCredential();
      credentials.add(credential);
    }
    return credentials;
  }

  Future<CmCredentialMetadata> _enumerateCredentialsMetadataOnlyBegin(
    List<int> rpIdHash,
  ) async {
    final resp = await _invoke(
      CredentialManagementSubCommand.enumerateCredentialsBegin.value,
      params: {
        CredentialManagementSubCommandParams.rpIdHash.value: CborBytes(
          rpIdHash,
        ),
        CredentialManagementSubCommandParams.metadataOnly.value: true,
      },
    );
    if (resp.status != 0) {
      throw CtapError.fromCode(resp.status);
    }
    return _credentialMetadataFromResponse(resp.data!, includeTotal: true);
  }

  Future<CmCredentialMetadata>
  _enumerateCredentialsMetadataOnlyGetNextCredential() async {
    final resp = await _invoke(
      CredentialManagementSubCommand
          .enumerateCredentialsGetNextCredential
          .value,
      auth: false,
    );
    if (resp.status != 0) {
      throw CtapError.fromCode(resp.status);
    }
    return _credentialMetadataFromResponse(resp.data!);
  }

  CmCredentialMetadata _credentialMetadataFromResponse(
    CredentialManagementResponse response, {
    bool includeTotal = false,
  }) {
    final publicKey = response.publicKey;
    final metadataOnly = publicKey == null && response.coseAlgorithm != null;
    final coseAlgorithm =
        publicKey?[CoseKey.algIdx] as int? ??
        (metadataOnly ? response.coseAlgorithm : null);
    if (coseAlgorithm == null) {
      throw const FormatException(
        'Credential response has neither a public key nor a COSE algorithm.',
      );
    }
    return CmCredentialMetadata(
      user: response.user!,
      credentialId: response.credentialId!,
      coseAlgorithm: coseAlgorithm,
      metadataOnly: metadataOnly,
      publicKey: publicKey,
      totalCredentials: includeTotal ? response.totalCredentials! : null,
      credProtect: response.credProtect!,
      largeBlobKey: response.largeBlobKey,
    );
  }

  Future<void> deleteCredential(
    PublicKeyCredentialDescriptor credentialId,
  ) async {
    final resp = await _invoke(
      CredentialManagementSubCommand.deleteCredential.value,
      params: {
        CredentialManagementSubCommandParams.credentialId.value: credentialId
            .toCbor(),
      },
    );
    if (resp.status != 0) {
      throw CtapError.fromCode(resp.status);
    }
  }

  Future<void> updateUserInformation(
    PublicKeyCredentialDescriptor credentialId,
    PublicKeyCredentialUserEntity user,
  ) async {
    final resp = await _invoke(
      CredentialManagementSubCommand.updateUserInformation.value,
      params: {
        CredentialManagementSubCommandParams.credentialId.value: credentialId
            .toCbor(),
        CredentialManagementSubCommandParams.user.value: user.toCbor(),
      },
    );
    if (resp.status != 0) {
      throw CtapError.fromCode(resp.status);
    }
  }

  Future<CtapResponse<CredentialManagementResponse?>> _invoke(
    int subCommand, {
    Map<int, dynamic>? params,
    bool auth = true,
  }) async {
    CborMap? paramsMap;
    final sortedParams = params?.entries.toList()
      ?..sort((a, b) => a.key.compareTo(b.key));
    var entries = sortedParams?.map(
      (e) => MapEntry(CborSmallInt(e.key), CborValue(e.value)),
    );
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
    return await _ctap.credentialManagement(
      CredentialManagementRequest(
        subCommand: subCommand,
        params: paramsMap,
        pinUvAuthProtocol: _pinProtocol.version,
        pinUvAuthParam: pinUvAuthParam,
      ),
    );
  }
}
