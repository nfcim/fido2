import 'package:convert/convert.dart';
import 'package:fido2/fido2.dart';
import 'package:test/test.dart';

import 'fido2_ctap.dart';

void main() {
  group('AuthenticatorInfo', () {
    test('Request', () {
      var makeGetInfoRequest = Ctap2.makeGetInfoRequest();
      expect(makeGetInfoRequest, equals([4]));
    });

    test('Response', () {
      var response = hex.decode(
          'AD0183665532465F5632684649444F5F325F30684649444F5F325F3102846863726564426C6F626B6372656450726F746563746B686D61632D7365637265746C6C61726765426C6F624B65790350244EB29EE0904E4981FE1F20F8D3B8F404A662726BF568637265644D676D74F569636C69656E7450696EF46A6C61726765426C6F6273F56E70696E557641757468546F6B656EF5706D616B654372656455764E6F74527164F5051905140682010207080818460982636E6663637573620A83A263616C672664747970656A7075626C69632D6B6579A263616C672764747970656A7075626C69632D6B6579A263616C67382F64747970656A7075626C69632D6B65790B1910000E18C90F1820');
      var info = Ctap2.parseGetInfoResponse(response);
      expect(info.versions, equals(['U2F_V2', 'FIDO_2_0', 'FIDO_2_1']));
      expect(info.options, contains('rk'));
    });

    test('With Device', () async {
      MockDevice device = MockDevice();
      Ctap2 ctap2 = await Ctap2.create(device);
      CtapResponse resp = await ctap2.refreshInfo();
      expect(resp.status, equals(0));
      expect(resp.data, isA<AuthenticatorInfo>());
    });
  });

  group('MakeCredential', () {
    test('Request', () {
      var request = MakeCredentialRequest(
        clientDataHash: List.filled(32, 0x01),
        rp: PublicKeyCredentialRpEntity(id: 'test.com'),
        user: PublicKeyCredentialUserEntity(
          id: [0x01],
          name: 'test',
          displayName: 'Test User',
        ),
        pubKeyCredParams: [
          {'alg': -7, 'type': 'public-key'}
        ],
      );

      var encoded = Ctap2.makeMakeCredentialRequest(request);

      expect(encoded.length, greaterThan(0));
      expect(encoded[0], equals(0x01));
    });

    test('Response', () {
      var responseBytes = hex.decode(
          'A301667061636B65640258250000000000000000000000000000000000000000000000000000000000000000000000000003A0');

      var response = Ctap2.parseMakeCredentialResponse(responseBytes);

      expect(response.fmt, equals('packed'));
      expect(response.authData.length, equals(37));
      expect(response.attStmt, isA<Map>());
    });
  });

  group('ClientPin', () {
    test('Request1', () {
      var request = Ctap2.makeClientPinRequest(ClientPinRequest(
          subCommand: ClientPinSubCommand.getKeyAgreement.value,
          pinUvAuthProtocol: 2));
      expect(request, equals(hex.decode('06A201020202')));
    });

    test('Request2', () {
      var request = Ctap2.makeClientPinRequest(ClientPinRequest(
        subCommand: ClientPinSubCommand.setPin.value,
        pinUvAuthProtocol: 2,
        keyAgreement: EcdhEsHkdf256.fromPublicKey(
            hex.decode(
                '9950CCD8C524DBAAB6D5ED7E4256B72A647920445DCA51DA5F1B2A6AEB9AAB18'),
            hex.decode(
                '80CC342ABC60C6FD1E8101CB3AA1D34B43CAFA6C3CA5403D70DEC1C72EC637FD')),
        pinUvAuthParam: hex.decode(
            '9941B629D9BAB9C8C578D5E7A3AE6201B7A2F90F02B238AA2674F4A976C17FF3'),
        newPinEnc: hex.decode(
            '75E69079A080945600397CC32ABE3B5CFD61C1BBBAD4CE71396EBB64D51D0198CC9D6FF8EBD14A6C9A134BE717CEBFB1CB25815B3AD0080DCC7414D8604DF1729E89EA54B1277DC701077C6ED5B8512A'),
      ));
      expect(
          request,
          equals(hex.decode(
              '06A50102020303A5010203381820012158209950CCD8C524DBAAB6D5ED7E4256B72A647920445DCA51DA5F1B2A6AEB9AAB1822582080CC342ABC60C6FD1E8101CB3AA1D34B43CAFA6C3CA5403D70DEC1C72EC637FD0458209941B629D9BAB9C8C578D5E7A3AE6201B7A2F90F02B238AA2674F4A976C17FF305585075E69079A080945600397CC32ABE3B5CFD61C1BBBAD4CE71396EBB64D51D0198CC9D6FF8EBD14A6C9A134BE717CEBFB1CB25815B3AD0080DCC7414D8604DF1729E89EA54B1277DC701077C6ED5B8512A')));
    });

    test('Response1', () {
      var response = hex.decode(
          'A101A50102033818200121582064E75C1E36EF6C3C17F609014D96D048BEB6793CD34823358E44A599B4DD2291225820235BD52FAEB2A3599F10D38EFB58E65BE58AE67AF118BF1BC528FA4B090EE763');
      var clientPinResponse = Ctap2.parseClientPinResponse(response);
      expect(clientPinResponse.keyAgreement![1], equals(2));
      expect(clientPinResponse.keyAgreement![3], equals(-25));
    });
  });
}
