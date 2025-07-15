import 'package:convert/convert.dart';
import 'package:cbor/cbor.dart';
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
          {'alg': -7, 'type': 'public-key'},
          {'alg': -257, 'type': 'public-key'}, // RS256
        ],
        excludeList: [
          PublicKeyCredentialDescriptor(
            id: [0x01, 0x02, 0x03, 0x04],
            type: 'public-key',
          )
        ],
        extensions: {
          'hmac-secret': true,
          'credProtect': 2,
        },
        options: {
          'rk': true,
          'uv': false,
        },
      );

      var encoded = Ctap2.makeMakeCredentialRequest(request);

      expect(encoded.length, greaterThan(0));
      expect(encoded[0], equals(0x01));

      var decoded = cbor.decode(encoded.sublist(1)).toObject() as Map;

      expect(decoded, containsPair(0x01, hasLength(32)));
      expect(decoded, containsPair(0x02, isA<Map>()));
      expect(decoded, containsPair(0x03, isA<Map>()));
      expect(decoded, containsPair(0x04, isA<List>()));

      expect(decoded, containsPair(0x05, isA<List>()));
      expect(decoded, containsPair(0x06, isA<Map>()));
      expect(decoded, containsPair(0x07, isA<Map>()));

      var rpEntity = decoded[0x02] as Map;
      expect(rpEntity, containsPair('id', 'test.com'));

      var userEntity = decoded[0x03] as Map;
      expect(userEntity, containsPair('id', [0x01]));
      expect(userEntity, containsPair('name', 'test'));
      expect(userEntity, containsPair('displayName', 'Test User'));

      var pubKeyCredParams = decoded[0x04] as List;
      expect(pubKeyCredParams, hasLength(2));
      expect(pubKeyCredParams[0], containsPair('alg', -7));
      expect(pubKeyCredParams[1], containsPair('alg', -257));

      var excludeList = decoded[0x05] as List;
      expect(excludeList, hasLength(1));
      var excludeItem = excludeList[0] as Map;
      expect(excludeItem, containsPair('id', [0x01, 0x02, 0x03, 0x04]));
      expect(excludeItem, containsPair('type', 'public-key'));

      var extensions = decoded[0x06] as Map;
      expect(extensions, containsPair('hmac-secret', true));
      expect(extensions, containsPair('credProtect', 2));

      var options = decoded[0x07] as Map;
      expect(options, containsPair('rk', true));
      expect(options, containsPair('uv', false));
    });

    test('Response', () {
      var responseBytes = hex.decode(
          'a501667061636b656402589499ab715d84a3bc5e0e92aa50e67a5813637fd1744bd301ab08f87191ddb816e0410000007baaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0010f1d0c41d1f054238b971e164e64941a8a50102032620012158200101010101010101010101010101010101010101010101010101010101010101225820020202020202020202020202020202020202020202020202020202020202020203a263616c67266373696758405a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a04f50558201212121212121212121212121212121212121212121212121212121212121212');

      var response = Ctap2.parseMakeCredentialResponse(responseBytes);

      expect(response.fmt, equals('packed'));

      expect(response.authData, hasLength(greaterThan(37)));

      var rpIdHash = response.authData.sublist(0, 32);
      expect(rpIdHash, hasLength(32));

      var flags = response.authData[32];
      expect(flags & 0x01, equals(0x01));
      expect(flags & 0x40, equals(0x40));

      var signCount = (response.authData[33] << 24) |
          (response.authData[34] << 16) |
          (response.authData[35] << 8) |
          response.authData[36];
      expect(signCount, equals(123));

      var aaguid = response.authData.sublist(37, 53);
      expect(aaguid, equals(List.filled(16, 0xaa)));

      var credIdLength = (response.authData[53] << 8) | response.authData[54];
      expect(credIdLength, equals(16));

      var credentialId = response.authData.sublist(55, 55 + credIdLength);
      expect(
          credentialId, equals(hex.decode('f1d0c41d1f054238b971e164e64941a8')));

      expect(response.attStmt, isA<Map>());
      expect(response.attStmt, containsPair('alg', -7));
      expect(response.attStmt, containsPair('sig', hasLength(64)));

      expect(response.epAtt, equals(true));
      expect(response.largeBlobKey, hasLength(32));
      expect(response.largeBlobKey, equals(List.filled(32, 0x12)));
    });
  });

  group('GetAssertion', () {
    test('Request', () {
      var request = GetAssertionRequest(
        rpId: 'test.com',
        clientDataHash: List.filled(32, 0x02),
      );

      var encoded = Ctap2.makeGetAssertionRequest(request);

      expect(encoded.length, greaterThan(0));
      expect(encoded[0], equals(0x02));

      var decoded = cbor.decode(encoded.sublist(1)).toObject() as Map;

      expect(decoded, containsPair(0x01, 'test.com'));
      expect(decoded, containsPair(0x02, hasLength(32)));
    });
    test('Response', () {
      var responseData = hex.decode(
          'a701a264747970656a7075626c69632d6b6579626964500102030405060708090a0b0c0d0e0f10025825d77a9ec1eac6a4e8ad1d23f53340e75efd2dbe7d00a9880a9fad6c54a334bf960951da7dbe035840e00a017858ee454f06a8ca085e2b463e20c189410e3252fbfc0a2e2fa4003472e3514dbc90418440b308504f453c3833b6a5962ecf1493ea9640aaf3ff3e0b3d04a362696444deadbeef646e616d657074657374406578616d706c652e636f6d6b646973706c61794e616d6569546573742055736572050506f50758208bee74a324a9c37f06749c2614f070e2ec96382791e66cdab1655912a74267a2');

      var response = Ctap2.parseGetAssertionResponse(responseData);

      expect(
          response.credential.id,
          equals([
            0x01,
            0x02,
            0x03,
            0x04,
            0x05,
            0x06,
            0x07,
            0x08,
            0x09,
            0x0a,
            0x0b,
            0x0c,
            0x0d,
            0x0e,
            0x0f,
            0x10
          ]));
      expect(response.credential.type, equals('public-key'));
      expect(response.authData, hasLength(37));
      expect(response.signature, hasLength(64));
      expect(response.user?.name, equals('test@example.com'));
      expect(response.user?.displayName, equals('Test User'));
      expect(response.user?.id, equals([0xde, 0xad, 0xbe, 0xef]));
      expect(response.numberOfCredentials, equals(5));
      expect(response.userSelected, equals(true));
      expect(
          response.largeBlobKey,
          equals(hex.decode(
              '8bee74a324a9c37f06749c2614f070e2ec96382791e66cdab1655912a74267a2')));
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
