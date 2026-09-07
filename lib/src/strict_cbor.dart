import 'package:cbor/cbor.dart';

/// Checks map keys before the CBOR decoder collapses them into a Dart Map.
/// Value decoding remains the responsibility of package:cbor.
int checkCborItem(List<int> bytes, [int offset = 0, int depth = 0]) {
  if (depth > 64 || offset >= bytes.length) {
    throw const FormatException('Truncated or excessively nested CBOR');
  }
  final initial = bytes[offset++];
  final major = initial >> 5;
  final info = initial & 31;
  if (info >= 28 && info != 31 || initial == 255) {
    throw const FormatException('Invalid CBOR header');
  }
  var argument = BigInt.from(info);
  if (info >= 24 && info <= 27) {
    final width = 1 << (info - 24);
    if (offset + width > bytes.length) {
      throw const FormatException('Truncated CBOR header');
    }
    argument = BigInt.zero;
    for (var i = 0; i < width; i++) {
      argument = (argument << 8) | BigInt.from(bytes[offset++]);
    }
  }
  if (major == 6) return checkCborItem(bytes, offset, depth + 1);
  if (major == 0 || major == 1 || major == 7) {
    if (info == 31) throw const FormatException('Invalid indefinite CBOR');
    return offset;
  }
  final indefinite = info == 31;
  if (!indefinite && argument > BigInt.from(bytes.length - offset)) {
    throw const FormatException('Truncated CBOR value');
  }
  if ((major == 2 || major == 3) && !indefinite) {
    return offset + argument.toInt();
  }
  final keys = <CborValue>{};
  var remaining = indefinite ? -1 : argument.toInt();
  while (remaining != 0) {
    if (offset >= bytes.length) {
      throw const FormatException('Truncated CBOR container');
    }
    if (indefinite && bytes[offset] == 255) return offset + 1;
    final start = offset;
    offset = checkCborItem(bytes, offset, depth + 1);
    if (major == 5) {
      final key = cbor.decode(bytes.sublist(start, offset));
      if (!keys.add(key)) throw const FormatException('Duplicate CBOR label');
      offset = checkCborItem(bytes, offset, depth + 1);
    }
    if (!indefinite) remaining--;
  }
  return offset;
}

CborValue decodeStrictCbor(List<int> bytes) {
  if (checkCborItem(bytes) != bytes.length) {
    throw const FormatException('Trailing CBOR data');
  }
  return cbor.decode(bytes);
}
