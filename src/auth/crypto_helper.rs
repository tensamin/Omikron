use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, OsRng},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use rand_core::RngCore;
use sha2::{Digest, Sha256};
use x448::{PublicKey, Secret, SharedSecret};

/// Errors for crypto operations
#[derive(Debug)]
pub enum CryptoError {
    Base64Decode(base64::DecodeError),
    InvalidKey,
    AgreementError,
    EncryptionError(aes_gcm::Error),
    DecryptionError(aes_gcm::Error),
}

impl From<base64::DecodeError> for CryptoError {
    fn from(err: base64::DecodeError) -> Self {
        CryptoError::Base64Decode(err)
    }
}

pub struct KeyPair {
    pub secret: Secret,
    pub public: PublicKey,
}

pub fn generate_keypair() -> KeyPair {
    let mut buf = [0u8; 56];
    let mut rng = OsRng;
    rng.fill_bytes(&mut buf);
    let secret = Secret::from_bytes(&buf).unwrap();
    let public = PublicKey::from(&secret);
    KeyPair { secret, public }
}

pub fn public_key_to_base64(pubkey: &PublicKey) -> String {
    STANDARD.encode(pubkey.as_bytes().as_ref())
}

pub fn secret_key_to_base64(secret: &Secret) -> String {
    STANDARD.encode(secret.as_bytes().as_ref())
}

pub fn load_public_key(base64_pub: &str) -> Option<PublicKey> {
    let bytes = STANDARD.decode(base64_pub).unwrap();
    PublicKey::from_bytes(&bytes)
}

pub fn load_secret_key(base64_secret: &str) -> Option<Secret> {
    let bytes = STANDARD.decode(base64_secret).unwrap();
    Secret::from_bytes(&bytes)
}

fn derive_aes_key(shared: &SharedSecret) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(shared.as_bytes());
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result[..32]);
    key
}

pub fn encrypt_b64(
    base64_secret: &str,
    base64_peer_pub: &str,
    plaintext: &str,
) -> Result<String, CryptoError> {
    let secret = load_secret_key(base64_secret).unwrap();
    let peer_pub = load_public_key(base64_peer_pub).unwrap();
    encrypt(secret, peer_pub, plaintext)
}
pub fn encrypt(
    secret: Secret,
    peer_pub: PublicKey,
    plaintext: &str,
) -> Result<String, CryptoError> {
    let shared = secret
        .to_diffie_hellman(&peer_pub)
        .ok_or(CryptoError::AgreementError)?;
    let key_bytes = derive_aes_key(&shared);
    let cipher = Aes256Gcm::new_from_slice(&key_bytes).expect("Key length should be correct");
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(CryptoError::EncryptionError)?;
    // prefix nonce to ciphertext
    let mut out = Vec::with_capacity(nonce_bytes.len() + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(STANDARD.encode(&out))
}

pub fn decrypt_b64(
    base64_secret: &str,
    base64_peer_pub: &str,
    encrypted_base64: &str,
) -> Result<String, CryptoError> {
    let secret = load_secret_key(base64_secret).unwrap();
    let peer_pub = load_public_key(base64_peer_pub).unwrap();
    decrypt(secret, peer_pub, encrypted_base64)
}
pub fn decrypt(
    secret: Secret,
    peer_pub: PublicKey,
    encrypted_base64: &str,
) -> Result<String, CryptoError> {
    let shared = secret
        .to_diffie_hellman(&peer_pub)
        .ok_or(CryptoError::AgreementError)?;
    let key_bytes = derive_aes_key(&shared);
    let cipher = Aes256Gcm::new_from_slice(&key_bytes).expect("Key length should be correct");

    let encrypted = STANDARD.decode(encrypted_base64)?;
    if encrypted.len() < 12 {
        return Err(CryptoError::DecryptionError(aes_gcm::Error));
    }
    let nonce_bytes = &encrypted[..12];
    let ciphertext = &encrypted[12..];
    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext_bytes = cipher
        .decrypt(nonce, ciphertext)
        .map_err(CryptoError::DecryptionError)?;
    let plaintext = String::from_utf8(plaintext_bytes)
        .map_err(|_| CryptoError::DecryptionError(aes_gcm::Error))?;
    Ok(plaintext)
}

pub fn hash_it(input: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hasher.finalize().to_vec()
}

pub fn hex_hash(input: &str) -> String {
    let digest = hash_it(input);
    digest.iter().map(|b| format!("{:02x}", b)).collect()
}
