import 'package:cbor/cbor.dart';
import '../strict_cbor.dart';

T? cborField<T extends CborValue>(
  CborMap map,
  Object label, {
  bool required = false,
}) {
  final value = map[CborValue(label)];
  if (value == null && !required) return null;
  if (value is! T || value.tags.isNotEmpty) {
    throw FormatException('Invalid CTAP field $label: expected $T');
  }
  return value;
}

CborMap ctapResponseMap(List<int> data) {
  final value = decodeStrictCbor(data);
  if (value is! CborMap || value.tags.isNotEmpty) {
    throw const FormatException('Expected untagged CTAP response map');
  }
  return value;
}
