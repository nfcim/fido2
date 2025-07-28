import '../constants.dart';

class GetInfoRequest {
  List<int> encode() {
    return [Ctap2Commands.getInfo.value];
  }
}
