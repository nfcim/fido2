//! Packed leaf-certificate profile checks. Certificate path trust is owned by
//! the relying party; this module never treats an embedded certificate as a CA.
use der::{asn1::ObjectIdentifier, asn1::OctetStringRef, Decode, Tagged};
use x509_cert::{certificate::Version, ext::pkix::BasicConstraints, Certificate};

use crate::{Request, Result};

pub(crate) fn packed_certificate_key(r: &Request) -> Result<Vec<u8>> {
    let invalid = "invalid_attestation_certificate";
    if r.message.len() != 16 {
        return Err("invalid_length");
    }
    let cert = Certificate::from_der(&r.key).map_err(|_| invalid)?;
    let tbs = &cert.tbs_certificate;
    if tbs.version != Version::V3 || cert.signature_algorithm != tbs.signature {
        return Err(invalid);
    }
    // Packed requires C, O, OU=Authenticator Attestation and CN in Subject.
    for (oid, required) in [
        ("2.5.4.6", None),
        ("2.5.4.10", None),
        ("2.5.4.11", Some("Authenticator Attestation")),
        ("2.5.4.3", None),
    ] {
        let oid = ObjectIdentifier::new_unwrap(oid);
        let mut found = false;
        for attr in tbs.subject.0.iter().flat_map(|rdn| rdn.0.iter()) {
            if attr.oid != oid {
                continue;
            }
            // RFC 5280 conforming issuers use PrintableString or UTF8String.
            let value = match attr.value.tag() {
                der::Tag::PrintableString => attr
                    .value
                    .decode_as::<der::asn1::PrintableStringRef<'_>>()
                    .map_err(|_| invalid)?
                    .as_str(),
                der::Tag::Utf8String => attr
                    .value
                    .decode_as::<der::asn1::Utf8StringRef<'_>>()
                    .map_err(|_| invalid)?
                    .as_str(),
                _ => return Err(invalid),
            };
            if value.is_empty() || required.is_some_and(|expected| value != expected) {
                return Err(invalid);
            }
            if oid == ObjectIdentifier::new_unwrap("2.5.4.6")
                && (value.len() != 2 || !value.bytes().all(|b| b.is_ascii_uppercase()))
            {
                return Err(invalid);
            }
            found = true;
        }
        if !found {
            return Err(invalid);
        }
    }
    let extensions = tbs.extensions.as_deref().unwrap_or_default();
    for (i, extension) in extensions.iter().enumerate() {
        if extensions[..i]
            .iter()
            .any(|previous| previous.extn_id == extension.extn_id)
        {
            return Err(invalid);
        }
        if extension.extn_id == ObjectIdentifier::new_unwrap("1.3.6.1.4.1.45724.1.1.4") {
            let aaguid =
                OctetStringRef::from_der(extension.extn_value.as_bytes()).map_err(|_| invalid)?;
            if extension.critical || aaguid.as_bytes() != r.message {
                return Err(invalid);
            }
        }
    }
    let (_, constraints) = tbs
        .get::<BasicConstraints>()
        .map_err(|_| invalid)?
        .ok_or(invalid)?;
    if constraints.ca || constraints.path_len_constraint.is_some() {
        return Err(invalid);
    }
    let spki = &tbs.subject_public_key_info;
    let key = spki.subject_public_key.as_bytes().ok_or(invalid)?;
    let algorithm_matches = match r.algorithm.as_str() {
        "es256" => {
            spki.algorithm.oid == ObjectIdentifier::new_unwrap("1.2.840.10045.2.1")
                && spki
                    .algorithm
                    .parameters
                    .as_ref()
                    .and_then(|p| p.decode_as::<ObjectIdentifier>().ok())
                    == Some(ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7"))
        }
        "ed25519" => {
            spki.algorithm.oid == ObjectIdentifier::new_unwrap("1.3.101.112")
                && spki.algorithm.parameters.is_none()
        }
        _ => return Err("unsupported_algorithm"),
    };
    if !algorithm_matches {
        return Err(invalid);
    }
    // Normalize EC points before returning them across the wire boundary.
    if r.algorithm == "es256" {
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        Ok(p256::PublicKey::from_sec1_bytes(key)
            .map_err(|_| "invalid_key")?
            .to_encoded_point(false)
            .as_bytes()
            .to_vec())
    } else {
        crate::validate(&Request {
            algorithm: r.algorithm.clone(),
            key: key.to_vec(),
            ..Request::default()
        })?;
        Ok(key.to_vec())
    }
}
