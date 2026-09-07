import 'package:fido2/src/ctap.dart';
import '../cose.dart';

import 'constants.dart';
import 'entities/authenticator_info.dart';
import 'requests/client_pin.dart';
import 'requests/credential_mgmt.dart';
import 'requests/get_info.dart';

class Ctap2 {
  late final AuthenticatorInfo _info;
  final CtapDevice device;

  final CoseConfiguration? configuration;
  CoseConfiguration? get coseConfiguration => configuration;
  Ctap2._create(this.device, this.configuration);

  static Future<Ctap2> create(
    CtapDevice device, {
    CoseConfiguration? configuration,
    CoseConfiguration? coseConfiguration,
  }) async {
    if (configuration != null &&
        coseConfiguration != null &&
        !identical(configuration, coseConfiguration)) {
      throw ArgumentError('Conflicting COSE configurations');
    }
    final ctap2 = Ctap2._create(device, configuration ?? coseConfiguration);
    final res = await ctap2.refreshInfo();
    if (res.status != 0) {
      throw Exception('GetInfo failed.');
    }
    ctap2._info = res.data;
    return ctap2;
  }

  static List<int> makeGetInfoRequest() => GetInfoRequest().encode();
  static AuthenticatorInfo parseGetInfoResponse(List<int> data) =>
      AuthenticatorInfo.decode(data);
  static List<int> makeClientPinRequest(ClientPinRequest request) =>
      request.encode();
  static ClientPinResponse parseClientPinResponse(List<int> data) =>
      ClientPinResponse.decode(data);
  static List<int> makeCredentialManagementRequest(
    CredentialManagementRequest request,
  ) => request.encode();
  static CredentialManagementResponse parseCredentialManagementResponse(
    List<int> data, {
    CoseConfiguration? configuration,
  }) => CredentialManagementResponse.decode(data, configuration: configuration);

  AuthenticatorInfo get info => _info;

  Future<CtapResponse<AuthenticatorInfo>> refreshInfo() async {
    final req = GetInfoRequest().encode();
    final res = await device.transceive(req);
    return CtapResponse(res.status, AuthenticatorInfo.decode(res.data));
  }

  Future<CtapResponse<ClientPinResponse?>> clientPin(
    ClientPinRequest request,
  ) async {
    final req = request.encode();
    final res = await device.transceive(req);
    return CtapResponse(
      res.status,
      res.data.isEmpty ? null : ClientPinResponse.decode(res.data),
    );
  }

  Future<CtapResponse<CredentialManagementResponse?>> credentialManagement(
    CredentialManagementRequest request,
  ) async {
    final req = request.encode();
    final res = await device.transceive(req);
    return CtapResponse(
      res.status,
      res.data.isEmpty
          ? null
          : CredentialManagementResponse.decode(
              res.data,
              configuration: configuration,
            ),
    );
  }

  Future<CtapResponse> reset() async {
    final req = [Ctap2Commands.reset.value];
    final res = await device.transceive(req);
    return CtapResponse(res.status, null);
  }
}
