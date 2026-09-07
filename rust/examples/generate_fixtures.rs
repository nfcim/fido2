//! Deterministic integration fixtures. These complement the independent RFC vectors.
use p256::ecdsa::signature::Signer;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::io::Write;

fn main() {
    let challenge = vec![42u8; 32];
    // Base64url of 32 repeated 0x2a bytes.
    let client = br#"{"type":"webauthn.get","challenge":"KioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKio","origin":"https://example.com","crossOrigin":false}"#;
    let mut auth = Sha256::digest(b"example.com").to_vec();
    auth.extend_from_slice(&[1, 0, 0, 0, 1]);
    let mut message = auth.clone();
    message.extend_from_slice(&Sha256::digest(client));
    let mut vectors = vec![];
    let es = p256::ecdsa::SigningKey::from_slice(&[1; 32]).unwrap();
    let sig: p256::ecdsa::Signature = es.sign(&message);
    vectors.push(json!({"algorithm":"es256", "alg":-7, "key":es.verifying_key().to_encoded_point(false).as_bytes(), "signature":sig.to_der().as_bytes()}));
    let ed = ed25519_dalek::SigningKey::from_bytes(&[2; 32]);
    let sig: ed25519_dalek::Signature = ed.sign(&message);
    vectors.push(json!({"algorithm":"ed25519", "alg":-8, "key":ed.verifying_key().as_bytes(), "signature":sig.to_bytes().as_slice()}));
    let sm = sm2::dsa::SigningKey::new(
        "1234567812345678",
        &sm2::SecretKey::from_slice(&[3; 32]).unwrap(),
    )
    .unwrap();
    let sig: sm2::dsa::Signature = sm.sign(&message);
    vectors.push(json!({"algorithm":"sm2", "alg":-65537, "key":sm.verifying_key().to_sec1_bytes().as_ref(), "signature":sig.to_bytes().as_slice()}));
    macro_rules! ml {
        ($p:ty, $name:literal, $alg:expr) => {{
            use ml_dsa::{Keypair, Signer, SignatureEncoding};
            let sk = ml_dsa::SigningKey::<$p>::from_seed(&[4;32].into());
            let sig = sk.sign(&message);
            vectors.push(json!({"algorithm":$name,"alg":$alg,"key":sk.verifying_key().encode().as_slice(),"signature":sig.to_bytes().as_slice()}));
        }};
    }
    ml!(ml_dsa::MlDsa44, "ml-dsa-44", -48);
    ml!(ml_dsa::MlDsa65, "ml-dsa-65", -49);
    ml!(ml_dsa::MlDsa87, "ml-dsa-87", -50);
    let output = json!({"challenge":challenge,"clientDataJSON":client.as_slice(),"authenticatorData":auth,"vectors":vectors});
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../test/fixtures/webauthn.json");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut file = std::fs::File::create(path).unwrap();
    serde_json::to_writer(&mut file, &output).unwrap();
    file.write_all(b"\n").unwrap();
}
