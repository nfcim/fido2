import 'package:fido2/fido2.dart';

void main() {
  // Entities
  final rp = PublicKeyCredentialRpEntity(id: 'example.com');
  final user = PublicKeyCredentialUserEntity(
    id: [1, 2, 3, 4],
    name: 'user@example.com',
    displayName: 'User Example',
  );
  final descriptor = PublicKeyCredentialDescriptor(
    type: 'public-key',
    id: [4, 5, 6, 7],
    transports: ['usb'],
  );
  print('PublicKeyCredentialRpEntity.toJson: ${rp.toJson()}');
  print('PublicKeyCredentialUserEntity.toJson: ${user.toJson()}');
  print('PublicKeyCredentialDescriptor.toJson: ${descriptor.toJson()}');

  // AuthenticatorInfo (minimal)
  final info = AuthenticatorInfo(
    versions: ['FIDO_2_1'],
    aaguid: List.filled(16, 0),
  );
  print('AuthenticatorInfo.toJson: ${info.toJson()}');

  // Requests
  final makeReq = MakeCredentialRequest(
    clientDataHash: List.filled(32, 1),
    rp: rp,
    user: user,
    pubKeyCredParams: [
      {
        'type': 'public-key',
        'alg': ES256.algorithm,
      }
    ],
    excludeList: [descriptor],
  );
  print('MakeCredentialRequest.toJson: ${makeReq.toJson()}');

  final getReq = GetAssertionRequest(
    rpId: 'example.com',
    clientDataHash: List.filled(32, 2),
    allowList: [descriptor],
  );
  print('GetAssertionRequest.toJson: ${getReq.toJson()}');

  final credMgmtReq = CredentialManagementRequest(subCommand: 1);
  print('CredentialManagementRequest.toJson: ${credMgmtReq.toJson()}');

  final clientPinReq = ClientPinRequest(
    subCommand: ClientPinSubCommand.getPinRetries.value,
  );
  print('ClientPinRequest.toJson: ${clientPinReq.toJson()}');

  // Responses (constructed directly for demo)
  final makeResp = MakeCredentialResponse(
    fmt: 'packed',
    authData: [0, 1, 2],
    attStmt: {'alg': ES256.algorithm},
  );
  print('MakeCredentialResponse.toJson: ${makeResp.toJson()}');

  final getResp = GetAssertionResponse(
    credential: descriptor,
    authData: [3, 4, 5],
    signature: [6, 7, 8],
    user: user,
    numberOfCredentials: 1,
    userSelected: true,
  );
  print('GetAssertionResponse.toJson: ${getResp.toJson()}');

  final es256 = ES256.fromPublicKey(
    List.filled(32, 9),
    List.filled(32, 10),
  );
  final credMgmtResp = CredentialManagementResponse(
    existingResidentCredentialsCount: 1,
    maxPossibleRemainingResidentCredentialsCount: 10,
    rp: rp,
    rpIdHash: [11, 12, 13],
    totalRPs: 1,
    user: user,
    credentialId: descriptor,
    publicKey: es256,
    totalCredentials: 1,
    credProtect: 2,
    largeBlobKey: [14, 15],
  );
  print('CredentialManagementResponse.toJson: ${credMgmtResp.toJson()}');

  final clientPinResp = ClientPinResponse(
    keyAgreement: es256,
    pinUvAuthToken: [16, 17, 18],
    pinRetries: 8,
    powerCycleState: false,
    uvRetries: 3,
  );
  print('ClientPinResponse.toJson: ${clientPinResp.toJson()}');

  // CTAP wrappers
  final ctapOk = CtapResponse<String>(0, 'ok');
  print('CtapResponse<String>.toJson: ${ctapOk.toJson()}');
  final ctapErr = CtapError(CtapStatusCode.ctap1ErrInvalidCommand);
  print('CtapError.toJson: ${ctapErr.toJson()}');

  // CoseKey toJson
  final eddsa = EdDSA.fromPublicKey(List.filled(32, 1));
  print('EdDSA.toJson: ${eddsa.toJson()}');
  final es256Key = ES256.fromPublicKey(List.filled(32, 2), List.filled(32, 3));
  print('ES256.toJson: ${es256Key.toJson()}');
  final ecdh = EcdhEsHkdf256.fromPublicKey(
    List.filled(32, 4),
    List.filled(32, 5),
  );
  print('EcdhEsHkdf256.toJson: ${ecdh.toJson()}');

  // Credential Management helper entities
  final meta = CmMetadata(
    existingResidentCredentialsCount: 2,
    maxPossibleRemainingResidentCredentialsCount: 5,
  );
  print('CmMetadata.toJson: ${meta.toJson()}');
  final cmRp = CmRp(rp: rp, rpIdHash: [21, 22], totalRPs: 3);
  print('CmRp.toJson: ${cmRp.toJson()}');
  final cmCred = CmCredential(
    user: user,
    credentialId: descriptor,
    publicKey: es256,
    totalCredentials: 2,
    credProtect: 1,
    largeBlobKey: [23, 24],
  );
  print('CmCredential.toJson: ${cmCred.toJson()}');

  // EncapsulateResult toJson
  final enc = EncapsulateResult(es256Key, List.filled(32, 6));
  print('EncapsulateResult.toJson: ${enc.toJson()}');
}
