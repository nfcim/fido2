import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:dart_pcsc/dart_pcsc.dart';
import 'package:fido2/fido2.dart';

class CtapCcid extends CtapDevice {
  final Card _card;

  CtapCcid(this._card);

  @override
  Future<CtapResponse<List<int>>> transceive(List<int> command) async {
    List<int> lc;
    if (command.length <= 255) {
      lc = [command.length];
    } else {
      lc = [0, command.length >> 8, command.length & 0xff];
    }
    List<int> capdu = [0x80, 0x10, 0x00, 0x00, ...lc, ...command];
    List<int> rapdu = List.empty();
    do {
      if (rapdu.length >= 2) {
        var remain = rapdu[rapdu.length - 1];
        capdu = [0x80, 0xC0, 0x00, 0x00, remain];
        rapdu = rapdu.sublist(0, rapdu.length - 2);
      }
      rapdu += await _card.transmit(Uint8List.fromList(capdu));
    } while (rapdu.length >= 2 && rapdu[rapdu.length - 2] == 0x61);
    print('> ${hex.encode(capdu)}');
    print('< ${hex.encode(rapdu)}');
    return CtapResponse(rapdu[0], rapdu.sublist(1, rapdu.length - 2));
  }
}

void main() async {
  final context = Context(Scope.user);
  try {
    await context.establish();

    Card card = await context.connect(
      'Canokeys Canokey',
      ShareMode.shared,
      Protocol.any,
    );

    Uint8List resp = await card.transmit(
      Uint8List.fromList(hex.decode('00A4040008A0000006472F0001')),
    );
    int status = (resp[resp.length - 2] << 8) + resp[resp.length - 1];
    print('Status: 0x${status.toRadixString(16)}');

    CtapDevice device = CtapCcid(card);
    final ctap = await Ctap2.create(device);
    print(ctap.info.versions);
    final cp = ClientPin(ctap, pinProtocol: PinProtocolV2());
    print(await cp.getPinRetries());
    await cp.changePin('123456', '1234');
    await cp.changePin('123456', '123456');

    await card.disconnect(Disposition.resetCard);
  } finally {
    await context.release();
  }
}
