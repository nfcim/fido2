import 'package:fido2/src/ctap.dart';

import 'constants.dart';
import 'entities/authenticator_info.dart';
import 'requests/client_pin.dart';
import 'requests/credential_mgmt.dart';
import 'requests/get_info.dart';

class Ctap2 {
  late final AuthenticatorInfo _info;
  final CtapDevice device;

  Ctap2._create(this.device);

  static Future<Ctap2> create(CtapDevice device) async {
    final ctap2 = Ctap2._create(device);
    final res = await ctap2.refreshInfo();
    if (res.status != 0) {
      throw Exception('GetInfo failed.');
    }
    ctap2._info = res.data;
    return ctap2;
  }

  AuthenticatorInfo get info => _info;

  Future<CtapResponse<AuthenticatorInfo>> refreshInfo() async {
    final req = GetInfoRequest().encode();
    final res = await device.transceive(req);
    return CtapResponse(res.status, AuthenticatorInfo.decode(res.data));
  }

  Future<CtapResponse<ClientPinResponse?>> clientPin(
      ClientPinRequest request) async {
    final req = request.encode();
    final res = await device.transceive(req);
    return CtapResponse(res.status,
        res.data.isEmpty ? null : ClientPinResponse.decode(res.data));
  }

  Future<CtapResponse<CredentialManagementResponse?>> credentialManagement(
      CredentialManagementRequest request) async {
    final req = request.encode();
    final res = await device.transceive(req);
    return CtapResponse(
        res.status,
        res.data.isEmpty
            ? null
            : CredentialManagementResponse.decode(res.data));
  }

  Future<CtapResponse> reset() async {
    final req = [Ctap2Commands.reset.value];
    final res = await device.transceive(req);
    return CtapResponse(res.status, null);
  }
}
