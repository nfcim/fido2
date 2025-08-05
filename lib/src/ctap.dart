/// Represents response from Client to Authenticator Protocol (CTAP) devices
class CtapResponse<T> {
  /// status code, see [CtapStatusCode]
  final int status;
  final T data;

  CtapResponse(this.status, this.data);

  @override
  String toString() {
    final buffer = StringBuffer();
    buffer.writeln('CtapResponse(');
    buffer.writeln('  status: $status,');
    buffer.writeln('  data: $data');
    buffer.write(')');
    return buffer.toString();
  }
}

abstract class CtapDevice {
  Future<CtapResponse<List<int>>> transceive(List<int> command);
}

/// Status code in CTAP responses
///
/// See section 6.2 of CTAP specification
enum CtapStatusCode implements Comparable<CtapStatusCode> {
  ctap1ErrSuccess(0x00),
  ctap1ErrInvalidCommand(0x01),
  ctap1ErrInvalidParameter(0x02),
  ctap1ErrInvalidLength(0x03),
  ctap1ErrInvalidSeq(0x04),
  ctap1ErrTimeout(0x05),
  ctap1ErrChannelBusy(0x06),
  ctap1ErrLockRequired(0x0A),
  ctap1ErrInvalidChannel(0x0B),
  ctap2ErrCborUnexpectedType(0x11),
  ctap2ErrInvalidCbor(0x12),
  ctap2ErrMissingParameter(0x14),
  ctap2ErrLimitExceeded(0x15),
  ctap2ErrFpDatabaseFull(0x17),
  ctap2ErrLargeBlobStorageFull(0x18),
  ctap2ErrCredentialExcluded(0x19),
  ctap2ErrProcessing(0x21),
  ctap2ErrInvalidCredential(0x22),
  ctap2ErrUserActionPending(0x23),
  ctap2ErrOperationPending(0x24),
  ctap2ErrNoOperations(0x25),
  ctap2ErrUnsupportedAlgorithm(0x26),
  ctap2ErrOperationDenied(0x27),
  ctap2ErrKeyStoreFull(0x28),
  ctap2ErrUnsupportedOption(0x2B),
  ctap2ErrInvalidOption(0x2C),
  ctap2ErrKeepaliveCancel(0x2D),
  ctap2ErrNoCredentials(0x2E),
  ctap2ErrUserActionTimeout(0x2F),
  ctap2ErrNotAllowed(0x30),
  ctap2ErrPinInvalid(0x31),
  ctap2ErrPinBlocked(0x32),
  ctap2ErrPinAuthInvalid(0x33),
  ctap2ErrPinAuthBlocked(0x34),
  ctap2ErrPinNotSet(0x35),
  ctap2ErrPuatRequired(0x36),
  ctap2ErrPinPolicyViolation(0x37),
  ctap2ErrReserved(0x38),
  ctap2ErrRequestTooLarge(0x39),
  ctap2ErrActionTimeout(0x3A),
  ctap2ErrUpRequired(0x3B),
  ctap2ErrUvBlocked(0x3C),
  ctap2ErrIntegrityFailure(0x3D),
  ctap2ErrInvalidSubcommand(0x3E),
  ctap2ErrUvInvalid(0x3F),
  ctap2ErrUnauthorizedPermission(0x40),
  ctap1ErrOther(0x7F),
  // extension-specific error codes
  ctap2ErrExtension00(0xE0),
  ctap2ErrExtension01(0xE1),
  ctap2ErrExtension02(0xE2),
  ctap2ErrExtension03(0xE3),
  ctap2ErrExtension04(0xE4),
  ctap2ErrExtension05(0xE5),
  ctap2ErrExtension06(0xE6),
  ctap2ErrExtension07(0xE7),
  ctap2ErrExtension08(0xE8),
  ctap2ErrExtension09(0xE9),
  ctap2ErrExtension0A(0xEA),
  ctap2ErrExtension0B(0xEB),
  ctap2ErrExtension0C(0xEC),
  ctap2ErrExtension0D(0xED),
  ctap2ErrExtension0E(0xEE),
  ctap2ErrExtension0F(0xEF),
  // vendor-specific error codes
  ctap2ErrVendor00(0xF0),
  ctap2ErrVendor01(0xF1),
  ctap2ErrVendor02(0xF2),
  ctap2ErrVendor03(0xF3),
  ctap2ErrVendor04(0xF4),
  ctap2ErrVendor05(0xF5),
  ctap2ErrVendor06(0xF6),
  ctap2ErrVendor07(0xF7),
  ctap2ErrVendor08(0xF8),
  ctap2ErrVendor09(0xF9),
  ctap2ErrVendor0A(0xFA),
  ctap2ErrVendor0B(0xFB),
  ctap2ErrVendor0C(0xFC),
  ctap2ErrVendor0D(0xFD),
  ctap2ErrVendor0E(0xFE),
  ctap2ErrVendor0F(0xFF),
  // enums below won't be used by [fromCode], but can be referenced by users
  /// The last value used by CTAP spec, *DO NOT USE* unless comparing
  ctap2ErrSpecLast(0xDF),

  /// The first value used by extension-specific impls, *DO NOT USE* unless comparing
  ctap2ErrExtensionFirst(0xE0),

  /// The last value used by extension-specific impls, *DO NOT USE* unless comparing
  ctap2ErrExtensionLast(0xEF),

  /// The first value used by vendor-specific impls, *DO NOT USE* unless comparing
  ctap2ErrVendorFirst(0xF0),

  /// The last value used by vendor-specific impls, *DO NOT USE* unless comparing
  ctap2ErrVendorLast(0xFF);

  final int value;
  const CtapStatusCode(this.value);

  /// Convert an status code into [CtapStatusCode]
  static CtapStatusCode fromCode(int rawCode) {
    // skip last 5 enums that are actually boundaries defined in spec
    var numParsableCodes = CtapStatusCode.values.length - 5;
    for (var status in CtapStatusCode.values.take(numParsableCodes)) {
      if (status.value == rawCode) {
        return status;
      }
    }
    throw ArgumentError('Unknown CTAP error code: $rawCode');
  }

  @override
  int compareTo(CtapStatusCode other) => value.compareTo(other.value);
}

/// Represents an error retuned by CTAP device
class CtapError extends Error {
  final CtapStatusCode status;

  /// Create an error from [CtapStatusCode]
  CtapError(this.status);

  /// Create an error from raw status code
  static CtapError fromCode(int rawCode) {
    return CtapError(CtapStatusCode.fromCode(rawCode));
  }

  @override
  String toString() {
    final buffer = StringBuffer();
    buffer.writeln('CtapError(');
    buffer.writeln('  status: ${status.value},');
    buffer.writeln('  name: ${status.name}');
    buffer.write(')');
    return buffer.toString();
  }
}
