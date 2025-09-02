import '../constants.dart';

/// CTAP2 authenticatorGetInfo (0x04) request.
///
/// Requests the authenticator's capabilities and preferences. Takes no inputs.
class GetInfoRequest {
  /// Encodes this request by returning the single command byte.
  List<int> encode() {
    return [Ctap2Commands.getInfo.value];
  }
}
