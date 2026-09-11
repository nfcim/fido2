"""Generate packed attestation vectors with Python cryptography (test-only).

Public, fixed test keys. Signatures/certificate signatures use the independent
OpenSSL backend. Run tool/embed_fixtures.py afterwards for browser fixtures.
"""
import base64
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import NameOID, ObjectIdentifier

root = Path(__file__).resolve().parents[1]
b64 = lambda b: base64.urlsafe_b64encode(b).decode().rstrip('=')
leaf = ec.derive_private_key(42, ec.SECP256R1())
issuer = ed25519.Ed25519PrivateKey.from_private_bytes(bytes([43]) * 32)
credential = ed25519.Ed25519PrivateKey.from_private_bytes(bytes([44]) * 32)
aaguid = bytes(range(16))
challenge = bytes(range(32))
client = json.dumps({'type': 'webauthn.create', 'challenge': b64(challenge),
                     'origin': 'https://example.com'}, separators=(',', ':')).encode()
public = credential.public_key().public_bytes_raw()
# {1: 1, 3: -8, -1: 6, -2: bstr(32)}
cose = bytes.fromhex('a4010103272006215820') + public
id_bytes = bytes([1, 2, 3])
auth = (hashlib.sha256(b'example.com').digest() + bytes.fromhex('45000000be')
        + aaguid + len(id_bytes).to_bytes(2, 'big') + id_bytes + cose)
message = auth + hashlib.sha256(client).digest()
issuer_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'FIDO2 test issuer')])


def certificate(key=leaf, *, ou='Authenticator Attestation', ca=False,
                include_bc=True, include_aaguid=True, guid=aaguid, critical=False,
                omit=None):
    attrs = [(NameOID.COUNTRY_NAME, 'CN'), (NameOID.ORGANIZATION_NAME, 'FIDO2 tests'),
             (NameOID.ORGANIZATIONAL_UNIT_NAME, ou), (NameOID.COMMON_NAME, 'Test authenticator')]
    name = x509.Name([x509.NameAttribute(oid, value) for oid, value in attrs if oid != omit])
    builder = (x509.CertificateBuilder().subject_name(name).issuer_name(issuer_name)
               .public_key(key.public_key()).serial_number(1)
               .not_valid_before(datetime(2020, 1, 1, tzinfo=timezone.utc))
               .not_valid_after(datetime(2040, 1, 1, tzinfo=timezone.utc)))
    if include_bc:
        builder = builder.add_extension(x509.BasicConstraints(ca=ca, path_length=None), True)
    if include_aaguid:
        builder = builder.add_extension(x509.UnrecognizedExtension(
            ObjectIdentifier('1.3.6.1.4.1.45724.1.1.4'), bytes([4, len(guid)]) + guid), critical)
    return builder.sign(issuer, None).public_bytes(serialization.Encoding.DER)


certificates = {
    'valid': certificate(),
    'ed25519': certificate(credential),
    'noAaguid': certificate(include_aaguid=False),
    'wrongAaguid': certificate(guid=bytes([255]) * 16),
    'shortAaguid': certificate(guid=bytes(15)),
    'criticalAaguid': certificate(critical=True),
    'ca': certificate(ca=True),
    'noBasicConstraints': certificate(include_bc=False),
    'wrongOu': certificate(ou='Not an authenticator'),
    'missingCountry': certificate(omit=NameOID.COUNTRY_NAME),
    'missingOrganization': certificate(omit=NameOID.ORGANIZATION_NAME),
    'missingCommonName': certificate(omit=NameOID.COMMON_NAME),
}
# An intentionally self-signed test root for applications to evaluate separately.
root_cert = (x509.CertificateBuilder().subject_name(issuer_name).issuer_name(issuer_name)
             .public_key(issuer.public_key()).serial_number(2)
             .not_valid_before(datetime(2020, 1, 1, tzinfo=timezone.utc))
             .not_valid_after(datetime(2040, 1, 1, tzinfo=timezone.utc))
             .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
             .sign(issuer, None).public_bytes(serialization.Encoding.DER))
fixture = {'challenge': b64(challenge), 'clientDataJSON': b64(client),
           'authData': b64(auth), 'id': b64(id_bytes),
           'sig': b64(leaf.sign(message, ec.ECDSA(hashes.SHA256()))),
           'selfSig': b64(credential.sign(message)),
           'certificates': {name: b64(der) for name, der in certificates.items()},
           'root': b64(root_cert)}
(root / 'test/fixtures/packed.json').write_text(json.dumps(fixture, indent=2) + '\n')
