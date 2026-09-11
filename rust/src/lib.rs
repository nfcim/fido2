//! Shared native/WASM cryptography. The wire interface is versioned JSON with byte arrays.
mod attestation;
use aes::cipher::{block_padding::NoPadding, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use der::{asn1::UintRef, Decode, Sequence};
use hmac::{Hmac, Mac};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sm2::dsa::signature::Verifier;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

const MAX_WIRE: usize = 1024 * 1024;

#[derive(Default, Deserialize, Zeroize)]
#[serde(default, deny_unknown_fields)]
pub struct Request {
    op: String,
    algorithm: String,
    key: Vec<u8>,
    message: Vec<u8>,
    signature: Vec<u8>,
    iv: Vec<u8>,
    salt: Vec<u8>,
    info: Vec<u8>,
    context: Vec<u8>,
    id: String,
    encoding: String,
    mode: String,
    length: usize,
    version: u8,
}

#[derive(Serialize)]
struct Response {
    data: Vec<u8>,
    error: Option<&'static str>,
}

type Result<T> = std::result::Result<T, &'static str>;

fn random(length: usize) -> Result<Vec<u8>> {
    if length > 65536 {
        return Err("invalid_length");
    }
    let mut bytes = vec![0; length];
    getrandom::getrandom(&mut bytes).map_err(|_| "random_unavailable")?;
    Ok(bytes)
}

fn mac(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut h = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    h.update(message);
    h.finalize().into_bytes().to_vec()
}

fn derive(key: &[u8], salt: &[u8], info: &[u8], length: usize) -> Result<Vec<u8>> {
    if length > 255 * 32 {
        return Err("invalid_length");
    }
    let mut out = vec![0; length];
    hkdf::Hkdf::<Sha256>::new(Some(salt), key)
        .expand(info, &mut out)
        .map_err(|_| "invalid_length")?;
    Ok(out)
}

#[derive(Sequence)]
struct Sm2Der<'a> {
    r: UintRef<'a>,
    s: UintRef<'a>,
}

fn sm2_signature(bytes: &[u8], encoding: &str) -> Result<sm2::dsa::Signature> {
    match encoding {
        "raw" => sm2::dsa::Signature::from_slice(bytes).map_err(|_| "invalid_signature_encoding"),
        "der" => {
            let parsed = Sm2Der::from_der(bytes).map_err(|_| "invalid_signature_encoding")?;
            let mut raw = [0u8; 64];
            let (r_out, s_out) = raw.split_at_mut(32);
            for (value, target) in [(parsed.r.as_bytes(), r_out), (parsed.s.as_bytes(), s_out)] {
                if value.len() > 32 {
                    return Err("invalid_signature_encoding");
                }
                target[32 - value.len()..].copy_from_slice(value);
            }
            sm2::dsa::Signature::from_slice(&raw).map_err(|_| "invalid_signature_encoding")
        }
        _ => Err("unsupported_encoding"),
    }
}

fn ml_verify<P: ml_dsa::MlDsaParams>(r: &Request) -> Result<bool> {
    if r.encoding != "raw" {
        return Err("unsupported_encoding");
    }
    if r.mode != "pure" {
        return Err("unsupported_mode");
    }
    if r.context.len() > 255 {
        return Err("invalid_context");
    }
    let encoded =
        ml_dsa::EncodedVerifyingKey::<P>::try_from(r.key.as_slice()).map_err(|_| "invalid_key")?;
    let key = ml_dsa::VerifyingKey::<P>::decode(&encoded);
    let signature = ml_dsa::Signature::<P>::try_from(r.signature.as_slice())
        .map_err(|_| "invalid_signature_encoding")?;
    Ok(key.verify_with_context(&r.message, &r.context, &signature))
}

fn validate(r: &Request) -> Result<()> {
    match r.algorithm.as_str() {
        "es256" | "p256" => {
            p256::PublicKey::from_sec1_bytes(&r.key).map_err(|_| "invalid_key")?;
        }
        "ed25519" => {
            let bytes = r.key.as_slice().try_into().map_err(|_| "invalid_key")?;
            let key = ed25519_dalek::VerifyingKey::from_bytes(bytes).map_err(|_| "invalid_key")?;
            if key.is_weak() {
                return Err("invalid_key");
            }
        }
        "sm2" => {
            sm2::PublicKey::from_sec1_bytes(&r.key).map_err(|_| "invalid_key")?;
        }
        "ml-dsa-44" if r.key.len() == 1312 => {}
        "ml-dsa-65" if r.key.len() == 1952 => {}
        "ml-dsa-87" if r.key.len() == 2592 => {}
        "ml-dsa-44" | "ml-dsa-65" | "ml-dsa-87" => return Err("invalid_key"),
        _ => return Err("unsupported_algorithm"),
    }
    Ok(())
}

fn verify(r: &Request) -> Result<bool> {
    if r.algorithm == "ed25519" && r.encoding != "raw" {
        return Err("unsupported_encoding");
    }
    validate(r)?;
    match r.algorithm.as_str() {
        "es256" => {
            let key =
                p256::ecdsa::VerifyingKey::from_sec1_bytes(&r.key).map_err(|_| "invalid_key")?;
            let sig = match r.encoding.as_str() {
                "der" => p256::ecdsa::Signature::from_der(&r.signature),
                "raw" => p256::ecdsa::Signature::from_slice(&r.signature),
                _ => return Err("unsupported_encoding"),
            }
            .map_err(|_| "invalid_signature_encoding")?;
            Ok(key.verify(&r.message, &sig).is_ok())
        }
        "ed25519" => {
            let bytes = r.key.as_slice().try_into().map_err(|_| "invalid_key")?;
            let key = ed25519_dalek::VerifyingKey::from_bytes(bytes).map_err(|_| "invalid_key")?;
            let sig = ed25519_dalek::Signature::from_slice(&r.signature)
                .map_err(|_| "invalid_signature_encoding")?;
            Ok(key.verify_strict(&r.message, &sig).is_ok())
        }
        "sm2" => {
            if r.id.len() > 8191 {
                return Err("invalid_id");
            }
            let key = sm2::dsa::VerifyingKey::from_sec1_bytes(&r.id, &r.key)
                .map_err(|_| "invalid_key")?;
            Ok(key
                .verify(&r.message, &sm2_signature(&r.signature, &r.encoding)?)
                .is_ok())
        }
        "ml-dsa-44" => ml_verify::<ml_dsa::MlDsa44>(r),
        "ml-dsa-65" => ml_verify::<ml_dsa::MlDsa65>(r),
        "ml-dsa-87" => ml_verify::<ml_dsa::MlDsa87>(r),
        _ => Err("unsupported_algorithm"),
    }
}

pub fn execute(r: &Request) -> Result<Vec<u8>> {
    if [&r.key, &r.signature, &r.iv, &r.salt, &r.info]
        .iter()
        .any(|bytes| bytes.len() > 65536)
    {
        return Err("invalid_length");
    }
    let message_limit = if r.op == "verify" { 65568 } else { 65536 };
    if r.message.len() > message_limit {
        return Err("invalid_length");
    }
    match r.op.as_str() {
        "version" => Ok(vec![1]),
        "random" => random(r.length),
        "sha256" => Ok(Sha256::digest(&r.message).to_vec()),
        "sm3" => Ok(sm3::Sm3::digest(&r.message).to_vec()),
        "hmac" => Ok(mac(&r.key, &r.message)),
        "hmac_verify" => Ok(vec![mac(&r.key, &r.message)
            .ct_eq(&r.signature)
            .unwrap_u8()]),
        "equal" => Ok(vec![r.key.ct_eq(&r.message).unwrap_u8()]),
        "hkdf" => derive(&r.key, &r.salt, &r.info, r.length),
        "validate" => {
            validate(r)?;
            Ok(vec![])
        }
        "verify" => Ok(vec![u8::from(verify(r)?)]),
        "packed_certificate_key" => attestation::packed_certificate_key(r),
        "aes_encrypt" | "aes_decrypt" => {
            if r.key.len() != 32 || r.iv.len() != 16 || r.message.len() % 16 != 0 {
                return Err("invalid_length");
            }
            if r.op == "aes_encrypt" {
                Ok(
                    cbc::Encryptor::<aes::Aes256>::new_from_slices(&r.key, &r.iv)
                        .map_err(|_| "invalid_length")?
                        .encrypt_padded_vec_mut::<NoPadding>(&r.message),
                )
            } else {
                cbc::Decryptor::<aes::Aes256>::new_from_slices(&r.key, &r.iv)
                    .map_err(|_| "invalid_length")?
                    .decrypt_padded_vec_mut::<NoPadding>(&r.message)
                    .map_err(|_| "invalid_length")
            }
        }
        "pin_encapsulate" => {
            if r.version != 1 && r.version != 2 {
                return Err("unsupported_version");
            }
            let peer = p256::PublicKey::from_sec1_bytes(&r.key).map_err(|_| "invalid_key")?;
            let private = loop {
                let bytes = Zeroizing::new(random(32)?);
                if let Ok(key) = p256::SecretKey::from_slice(&bytes) {
                    break key;
                }
            };
            let public = private.public_key().to_encoded_point(false);
            let shared = p256::ecdh::diffie_hellman(private.to_nonzero_scalar(), peer.as_affine());
            let mut out = public.as_bytes().to_vec();
            if r.version == 1 {
                out.extend_from_slice(&Sha256::digest(shared.raw_secret_bytes()));
            } else {
                out.extend_from_slice(&Zeroizing::new(derive(
                    shared.raw_secret_bytes(),
                    &[0; 32],
                    b"CTAP2 HMAC key",
                    32,
                )?));
                out.extend_from_slice(&Zeroizing::new(derive(
                    shared.raw_secret_bytes(),
                    &[0; 32],
                    b"CTAP2 AES key",
                    32,
                )?));
            }
            Ok(out)
        }
        _ => Err("unsupported_operation"),
    }
}

pub fn dispatch(input: &[u8]) -> Vec<u8> {
    let result = if input.len() > MAX_WIRE {
        Err("invalid_length")
    } else {
        serde_json::from_slice::<Request>(input)
            .map_err(|_| "invalid_request")
            .and_then(|r| execute(&Zeroizing::new(r)))
    };
    let mut response = match result {
        Ok(data) => Response { data, error: None },
        Err(error) => Response {
            data: vec![],
            error: Some(error),
        },
    };
    let wire = serde_json::to_vec(&response).expect("byte response serializes");
    response.data.zeroize();
    wire
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn run(input: Vec<u8>) -> Vec<u8> {
    dispatch(&Zeroizing::new(input))
}

/// Allocate a zeroed wire buffer. Only the pointer and exact size returned here may be freed.
#[no_mangle]
pub extern "C" fn fido2_alloc(length: usize) -> *mut u8 {
    if length == 0 || length > MAX_WIRE {
        return std::ptr::null_mut();
    }
    Box::into_raw(vec![0; length].into_boxed_slice()).cast::<u8>()
}

/// # Safety
/// `pointer` must be a live allocation from fido2_alloc with exactly `length` bytes.
#[no_mangle]
pub unsafe extern "C" fn fido2_free(pointer: *mut u8, length: usize) {
    if !pointer.is_null() {
        let mut bytes = Box::from_raw(std::ptr::slice_from_raw_parts_mut(pointer, length));
        bytes.zeroize();
    }
}

/// # Safety
/// Input/output must reference disjoint readable/writable buffers of the supplied sizes.
#[no_mangle]
pub unsafe extern "C" fn fido2_call(
    input: *const u8,
    length: usize,
    output: *mut u8,
    capacity: usize,
) -> i32 {
    if input.is_null() || output.is_null() || length > MAX_WIRE || capacity > MAX_WIRE {
        return -1;
    }
    let response = std::panic::catch_unwind(|| dispatch(std::slice::from_raw_parts(input, length)));
    match response {
        Ok(bytes) => {
            let bytes = Zeroizing::new(bytes);
            if bytes.len() > capacity {
                return -2;
            }
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), output, bytes.len());
            bytes.len() as i32
        }
        Err(_) => -3,
    }
}
