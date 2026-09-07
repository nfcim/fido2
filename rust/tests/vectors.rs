use fido2_crypto::{dispatch, execute, Request};
use serde_json::{json, Value};

fn call(value: Value) -> Value {
    serde_json::from_slice(&dispatch(&serde_json::to_vec(&value).unwrap())).unwrap()
}

#[test]
fn published_rfc9964_vectors() {
    let vectors: Vec<Value> =
        serde_json::from_str(include_str!("../../test/fixtures/rfc9964.json")).unwrap();
    for mut v in vectors {
        v.as_object_mut().unwrap().remove("source");
        v["op"] = json!("verify");
        v["mode"] = json!("pure");
        v["encoding"] = json!("raw");
        assert_eq!(call(v.clone())["data"], json!([1]));
        v["message"][0] = json!(0);
        assert_eq!(call(v)["data"], json!([0]));
    }
}

#[test]
fn sm2_gb32918_vector_and_encoding() {
    let key = hex::decode("0409F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F35020CCEA490CE26775A52DC6EA718CC1AA600AED05FBF35E084A6632F6072DA9AD13").unwrap();
    let signature = hex::decode("F5A03B0648D2C4630EEAC513E1BB81A15944DA3827D5B74143AC7EACEEE720B3B1B6AA29DF212FD8763182BC0D421CA1BB9038FD1F7F42D4840B69C485BBC1AA").unwrap();
    let mut r = json!({"op":"verify","algorithm":"sm2","key":key,"message":b"message digest","signature":signature,"id":"1234567812345678","encoding":"raw"});
    assert_eq!(call(r.clone())["data"], json!([1]));
    r["id"] = json!("wrong");
    assert_eq!(call(r.clone())["data"], json!([0]));
    r["id"] = json!("1234567812345678");
    let mut der = vec![0x30, 0x46, 0x02, 0x21, 0];
    der.extend_from_slice(&signature[..32]);
    der.extend_from_slice(&[0x02, 0x21, 0]);
    der.extend_from_slice(&signature[32..]);
    r["signature"] = json!(der);
    r["encoding"] = json!("der");
    assert_eq!(call(r.clone())["data"], json!([1]));
    r["signature"].as_array_mut().unwrap().push(json!(0));
    assert_eq!(call(r)["error"], "invalid_signature_encoding");
}

#[test]
fn pin_ecdh_and_kdf_both_versions() {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use sha2::{Digest, Sha256};
    let peer = p256::SecretKey::from_slice(&[7; 32]).unwrap();
    for version in [1, 2] {
        let request: Request = serde_json::from_value(json!({"op":"pin_encapsulate","version":version,"key":peer.public_key().to_encoded_point(false).as_bytes()})).unwrap();
        let result = execute(&request).unwrap();
        let public = p256::PublicKey::from_sec1_bytes(&result[..65]).unwrap();
        let shared = p256::ecdh::diffie_hellman(peer.to_nonzero_scalar(), public.as_affine());
        let expected = if version == 1 {
            Sha256::digest(shared.raw_secret_bytes()).to_vec()
        } else {
            let kdf = hkdf::Hkdf::<Sha256>::new(Some(&[0; 32]), shared.raw_secret_bytes());
            let mut key = [0; 64];
            kdf.expand(b"CTAP2 HMAC key", &mut key[..32]).unwrap();
            kdf.expand(b"CTAP2 AES key", &mut key[32..]).unwrap();
            key.to_vec()
        };
        assert_eq!(&result[65..], expected);
    }
}

#[test]
fn malformed_bridge_requests_fail_closed() {
    for input in [
        b"".as_slice(),
        b"{}",
        b"{\"op\":\"sha256\",\"message\":[256]}",
    ] {
        let r: Value = serde_json::from_slice(&dispatch(input)).unwrap();
        assert!(r["error"].is_string());
    }
    assert_eq!(
        call(json!({"op":"random","length":65537}))["error"],
        "invalid_length"
    );
}

#[test]
fn pure_mldsa_context_is_not_prehash() {
    use ml_dsa::{Keypair, SignatureEncoding};
    macro_rules! check {
        ($p:ty, $name:literal) => {{
            let sk = ml_dsa::SigningKey::<$p>::from_seed(&[8;32].into());
            let expanded = ml_dsa::ExpandedSigningKey::<$p>::from_seed(&[8;32].into());
            for context in [vec![], vec![42;255]] {
                let sig = expanded.sign_deterministic(b"context", &context).unwrap();
                let mut request = json!({"op":"verify","algorithm":$name,"mode":"pure","encoding":"raw",
                    "key":sk.verifying_key().encode().as_slice(),"message":b"context",
                    "context":context,"signature":sig.to_bytes().as_slice()});
                assert_eq!(call(request.clone())["data"],json!([1]));
                request["mode"] = json!("hash");
                assert_eq!(call(request)["error"],json!("unsupported_mode"));
            }
        }};
    }
    check!(ml_dsa::MlDsa44, "ml-dsa-44");
    check!(ml_dsa::MlDsa65, "ml-dsa-65");
    check!(ml_dsa::MlDsa87, "ml-dsa-87");
}
