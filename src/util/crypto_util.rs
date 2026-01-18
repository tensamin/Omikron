use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STD};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use std::fmt;
use x448::{PublicKey, Secret};

// --- Custom Errors ---
#[derive(Debug)]
pub enum SecurePayloadError {
    InvalidBase64,
    InvalidHex,
    EncryptionError,
    DecryptionError,
    InvalidKeyLength,
}

// --- Data Format Enum ---
#[derive(Clone, Copy, Debug)]
pub enum DataFormat {
    Raw,
    Base64,
    Hex,
}

// --- Main Class Structure ---
pub struct SecurePayload {
    /// The internal canonical representation is always raw bytes.
    inner_data: Vec<u8>,
    /// The private key of the user associated with this payload instance.
    private_key: Secret,
}

impl Clone for SecurePayload {
    fn clone(&self) -> Self {
        Self {
            inner_data: self.inner_data.clone(),
            private_key: Secret::from_bytes(self.private_key.as_bytes()).unwrap(),
        }
    }
}

impl SecurePayload {
    /// Clear Constructor: Takes data in any format and the user's private key.
    pub fn new<S, T: AsRef<[u8]>>(
        data: T,
        format: DataFormat,
        private_key: S,
    ) -> Result<Self, SecurePayloadError>
    where
        S: Into<Secret>,
    {
        let raw_data = match format {
            DataFormat::Raw => data.as_ref().to_vec(),
            DataFormat::Base64 => BASE64_STD
                .decode(data.as_ref())
                .map_err(|_| SecurePayloadError::InvalidBase64)?,
            DataFormat::Hex => {
                hex::decode(data.as_ref()).map_err(|_| SecurePayloadError::InvalidHex)?
            }
        };

        Ok(Self {
            inner_data: raw_data,
            private_key: private_key.into(),
        })
    }

    /// Helper to get the public key associated with this instance's private key.
    pub fn get_public_key(&self) -> [u8; 56] {
        *PublicKey::from(&self.private_key).as_bytes()
    }

    /// Exports the internal data to the requested format
    pub fn export(&self, format: DataFormat) -> String {
        match format.into() {
            DataFormat::Raw => String::from_utf8_lossy(&self.inner_data).to_string(),
            DataFormat::Base64 => BASE64_STD.encode(&self.inner_data),
            DataFormat::Hex => hex::encode(&self.inner_data),
        }
    }

    /// Access raw bytes directly
    pub fn get_bytes(&self) -> &[u8] {
        &self.inner_data
    }

    /// Returns the SHA-256 Hash of the data in the requested format
    pub fn get_hash(&self, format: DataFormat) -> String {
        let mut hasher = Sha256::new();
        hasher.update(&self.inner_data);
        let result = hasher.finalize();

        match format {
            DataFormat::Raw => String::from_utf8_lossy(&result).to_string(),
            DataFormat::Base64 => BASE64_STD.encode(result),
            DataFormat::Hex => hex::encode(result),
        }
    }

    /// Encrypts the held data for a specific recipient using AES-256-GCM.
    /// The message will contain ONLY the ciphertext.
    pub fn encrypt_x448<S>(&self, public_key: S) -> Result<SecurePayload, SecurePayloadError>
    where
        S: Into<PublicKey>,
    {
        let peer_pub = public_key.into();
        let shared_secret = self.private_key.as_diffie_hellman(&peer_pub).unwrap();

        println!(
            "Encryption Shared Secret (Hex): {}",
            hex::encode(shared_secret.as_bytes())
        );

        // 3. Key & Nonce Derivation (HKDF)
        // We derive 32 bytes for the key and 12 bytes for a deterministic nonce.
        let hkdf = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
        let mut okm = [0u8; 44]; // 32 (Key) + 12 (Nonce)
        hkdf.expand(b"x448-aes-gcm-no-overhead", &mut okm)
            .map_err(|_| SecurePayloadError::EncryptionError)?;

        let key = &okm[..32];
        let nonce_bytes = &okm[32..];

        // 4. Encrypt with AES-256-GCM
        let cipher = Aes256Gcm::new(key.into());
        let nonce = Nonce::from_slice(nonce_bytes);

        let ciphertext = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: &self.inner_data,
                    aad: &[],
                },
            )
            .map_err(|_| SecurePayloadError::EncryptionError)?;

        // 5. Result is ONLY the ciphertext. No key or nonce is packed.
        Ok(SecurePayload {
            inner_data: ciphertext,
            private_key: Secret::from_bytes(self.private_key.as_bytes()).unwrap(),
        })
    }

    /// Decrypts the held data providing the sender's public key manually.
    pub fn decrypt_to_format(
        &self,
        peer_public_key_bytes: &[u8; 56],
        output_format: DataFormat,
    ) -> Result<String, SecurePayloadError> {
        let decrypted_instance = self.decrypt_x448(peer_public_key_bytes)?;
        Ok(decrypted_instance.export(output_format))
    }

    /// Decrypts the held data using the internal Private Key and the provided Peer Public Key.
    pub fn decrypt_x448(
        &self,
        peer_public_key_bytes: &[u8; 56],
    ) -> Result<SecurePayload, SecurePayloadError> {
        // 1. Perform Exchange
        let peer_pub = PublicKey::from_bytes(peer_public_key_bytes).unwrap();
        let shared_secret = self.private_key.as_diffie_hellman(&peer_pub).unwrap();

        // LOGGING: Shared Secret
        println!(
            "Decryption Shared Secret (Hex): {}",
            hex::encode(shared_secret.as_bytes())
        );

        // 2. Key & Nonce Derivation (Must match encryption exactly)
        let hkdf = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
        let mut okm = [0u8; 44];
        hkdf.expand(b"x448-aes-gcm-no-overhead", &mut okm)
            .map_err(|_| SecurePayloadError::DecryptionError)?;

        let key = &okm[..32];
        let nonce_bytes = &okm[32..];

        // 3. Decrypt with AES-256-GCM
        let cipher = Aes256Gcm::new(key.into());
        let nonce = Nonce::from_slice(nonce_bytes);

        let plaintext = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &self.inner_data,
                    aad: &[],
                },
            )
            .map_err(|_| SecurePayloadError::DecryptionError)?;

        Ok(SecurePayload {
            inner_data: plaintext,
            private_key: Secret::from_bytes(self.private_key.as_bytes()).unwrap(),
        })
    }
}
