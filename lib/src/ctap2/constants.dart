enum Ctap2Commands {
  makeCredential(0x01),
  getAssertion(0x02),
  getInfo(0x04),
  clientPIN(0x06),
  reset(0x07),
  getNextAssertion(0x08),
  credentialManagement(0x0A),
  selection(0x0B),
  largeBlobs(0x0C),
  config(0x0D);

  const Ctap2Commands(this.value);

  final int value;
}

// MakeCredential parameter indices
const int mcClientDataHashIdx = 1;
const int mcRpIdx = 2;
const int mcUserIdx = 3;
const int mcPubKeyCredParamsIdx = 4;
const int mcExcludeListIdx = 5;
const int mcExtensionsIdx = 6;
const int mcOptionsIdx = 7;
const int mcPinAuthIdx = 8;
const int mcPinProtocolIdx = 9;
const int mcEnterpriseAttestationIdx = 10;

// MakeCredential response indices
const int mcRspFmtIdx = 1;
const int mcRspAuthDataIdx = 2;
const int mcRspAttStmtIdx = 3;
const int mcRspEpAttIdx = 4;
const int mcRspLargeBlobKeyIdx = 5;

// AuthenticatorInfo parameter indices
const int authInfoVersionsIdx = 1;
const int authInfoExtensionsIdx = 2;
const int authInfoAaguidIdx = 3;
const int authInfoOptionsIdx = 4;
const int authInfoMaxMsgSizeIdx = 5;
const int authInfoPinUvAuthProtocolsIdx = 6;
const int authInfoMaxCredentialCountInListIdx = 7;
const int authInfoMaxCredentialIdLengthIdx = 8;
const int authInfoTransportsIdx = 9;
const int authInfoAlgorithmsIdx = 10;
const int authInfoMaxSerializedLargeBlobArrayIdx = 11;
const int authInfoForcePinChangeIdx = 12;
const int authInfoMinPinLengthIdx = 13;
const int authInfoFirmwareVersionIdx = 14;
const int authInfoMaxCredBlobLengthIdx = 15;
const int authInfoMaxRpIdsForSetMinPinLengthIdx = 16;
const int authInfoPreferredPlatformUvAttemptsIdx = 17;
const int authInfoUvModalityIdx = 18;
const int authInfoCertificationsIdx = 19;
const int authInfoRemainingDiscoverableCredentialsIdx = 20;
const int authInfoVendorPrototypeConfigCommandsIdx = 21;

// ClientPin parameter indices
const int cpPinUvAuthProtocolIdx = 1;
const int cpSubCommandIdx = 2;
const int cpKeyAgreementIdx = 3;
const int cpPinUvAuthParamIdx = 4;
const int cpNewPinEncIdx = 5;
const int cpPinHashEncIdx = 6;
const int cpPermissionsIdx = 9;
const int cpRpIdIdx = 10;

// ClientPin response indices
const int cpRspKeyAgreementIdx = 1;
const int cpRspPinUvAuthTokenIdx = 2;
const int cpRspPinRetriesIdx = 3;
const int cpRspPowerCycleStateIdx = 4;
const int cpRspUvRetriesIdx = 5;

// CredentialManagement parameter indices
const int credMgmtSubCmdIdx = 1;
const int credMgmtParamsIdx = 2;
const int credMgmtPinUvAuthProtocolIdx = 3;
const int credMgmtPinUvAuthParamIdx = 4;

// CredentialManagement response indices
const int credMgmtRspExistingResidentCredentialsCountIdx = 1;
const int credMgmtRspMaxPossibleRemainingResidentCredentialsCountIdx = 2;
const int credMgmtRspRpIdx = 3;
const int credMgmtRspRpIdHashIdx = 4;
const int credMgmtRspTotalRPsIdx = 5;
const int credMgmtRspUserIdx = 6;
const int credMgmtRspCredentialIdIdx = 7;
const int credMgmtRspPublicKeyIdx = 8;
const int credMgmtRspTotalCredentialsIdx = 9;
const int credMgmtRspCredProtectIdx = 10;
const int credMgmtRspLargeBlobKeyIdx = 11;

// GetAssertion parameter indices
const int gaRpIdIdx = 1;
const int gaClientDataHashIdx = 2;
const int gaAllowListIdx = 3;
const int gaExtensionsIdx = 4;
const int gaOptionsIdx = 5;
const int gaPinAuthIdx = 6;
const int gaPinProtocolIdx = 7;

// GetAssertion response indices
const int gaRspCredentialIdx = 1;
const int gaRspAuthDataIdx = 2;
const int gaRspSignatureIdx = 3;
const int gaRspUserIdx = 4;
const int gaRspNumberOfCredentialsIdx = 5;
const int gaRspUserSelectedIdx = 6;
const int gaRspLargeBlobKeyIdx = 7;
