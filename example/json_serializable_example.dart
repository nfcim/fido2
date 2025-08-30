import 'package:fido2/src/ctap2/entities/credential_entities.dart';

void main() {
  final rp = PublicKeyCredentialRpEntity(id: 'example.com');
  final jsonMap = rp.toJson();
  print('toJson map: $jsonMap');
  print('toString: $rp');
}
