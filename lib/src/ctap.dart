/// Represents response from Client to Authenticator Protocol (CTAP) devices
class CtapResponse<T> {
  /// status code, see [CtapException]
  final int status;
  final T data;

  CtapResponse(this.status, this.data);
}

abstract class CtapDevice {
  Future<CtapResponse<List<int>>> transceive(List<int> command);
}

class CtapException {
  final int errorCode;

  CtapException(this.errorCode);

  static int ctap1ErrSuccess = 0x00;
  static int ctap1ErrInvalidCommand = 0x01;
  static int ctap1ErrInvalidParameter = 0x02;
  static int ctap1ErrInvalidLength = 0x03;
  static int ctap1ErrInvalidSeq = 0x04;
  static int ctap1ErrTimeout = 0x05;
  static int ctap1ErrChannelBusy = 0x06;
  static int ctap1ErrLockRequired = 0x0A;
  static int ctap1ErrInvalidChannel = 0x0B;
  static int ctap2ErrCborUnexpectedType = 0x11;
  static int ctap2ErrInvalidCbor = 0x12;
  static int ctap2ErrMissingParameter = 0x14;
  static int ctap2ErrLimitExceeded = 0x15;
  static int ctap2ErrFpDatabaseFull = 0x17;
  static int ctap2ErrLargeBlobStorageFull = 0x18;
  static int ctap2ErrCredentialExcluded = 0x19;
  static int ctap2ErrProcessing = 0x21;
  static int ctap2ErrInvalidCredential = 0x22;
  static int ctap2ErrUserActionPending = 0x23;
  static int ctap2ErrOperationPending = 0x24;
  static int ctap2ErrNoOperations = 0x25;
  static int ctap2ErrUnsupportedAlgorithm = 0x26;
  static int ctap2ErrOperationDenied = 0x27;
  static int ctap2ErrKeyStoreFull = 0x28;
  static int ctap2ErrUnsupportedOption = 0x2B;
  static int ctap2ErrInvalidOption = 0x2C;
  static int ctap2ErrKeepaliveCancel = 0x2D;
  static int ctap2ErrNoCredentials = 0x2E;
  static int ctap2ErrUserActionTimeout = 0x2F;
  static int ctap2ErrNotAllowed = 0x30;
  static int ctap2ErrPinInvalid = 0x31;
  static int ctap2ErrPinBlocked = 0x32;
  static int ctap2ErrPinAuthInvalid = 0x33;
  static int ctap2ErrPinAuthBlocked = 0x34;
  static int ctap2ErrPinNotSet = 0x35;
  static int ctap2ErrPuatRequired = 0x36;
  static int ctap2ErrPinPolicyViolation = 0x37;
  static int ctap2ErrReserved = 0x38;
  static int ctap2ErrRequestTooLarge = 0x39;
  static int ctap2ErrActionTimeout = 0x3A;
  static int ctap2ErrUpRequired = 0x3B;
  static int ctap2ErrUvBlocked = 0x3C;
  static int ctap2ErrIntegrityFailure = 0x3D;
  static int ctap2ErrInvalidSubcommand = 0x3E;
  static int ctap2ErrUvInvalid = 0x3F;
  static int ctap2ErrUnauthorizedPermission = 0x40;
  static int ctap1ErrOther = 0x7F;
  static int ctap2ErrSpecLast = 0xDF;
  static int ctap2ErrExtensionFirst = 0xE0;
  static int ctap2ErrExtensionLast = 0xEF;
  static int ctap2ErrVendorFirst = 0xF0;
  static int ctap2ErrVendorLast = 0xFF;
}
