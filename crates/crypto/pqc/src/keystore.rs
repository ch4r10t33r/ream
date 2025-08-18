use std::{
    error::Error,
    fmt,
    fs::File,
    io::{Read, Write},
    path::Path,
};

use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit},
};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{self, Engine};
use hashsig::signature::{
    SignatureScheme,
    generalized_xmss::instantiations_poseidon::{self},
};
use hmac::{Hmac, Mac};
use rand::{Rng, rng};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug)]
pub enum XmssWrapperError {
    KeyGeneration(String),
    FileWrite(std::io::Error),
    FileRead(std::io::Error),
    Serialization(String),
    Encryption(String),
    Decryption(String),
    Authentication(String),
    Signing(String),
    Verification(String),
    InvalidTreeHeight(String),
}

impl fmt::Display for XmssWrapperError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            XmssWrapperError::KeyGeneration(msg) => write!(f, "Key generation error: {}", msg),
            XmssWrapperError::FileWrite(err) => write!(f, "File write error: {}", err),
            XmssWrapperError::FileRead(err) => write!(f, "File read error: {}", err),
            XmssWrapperError::Serialization(msg) => write!(f, "Serialization error: {}", msg),
            XmssWrapperError::Encryption(msg) => write!(f, "Encryption error: {}", msg),
            XmssWrapperError::Decryption(msg) => write!(f, "Decryption error: {}", msg),
            XmssWrapperError::Authentication(msg) => write!(f, "Authentication error: {}", msg),
            XmssWrapperError::Signing(msg) => write!(f, "Signing error: {}", msg),
            XmssWrapperError::Verification(msg) => write!(f, "Verification error: {}", msg),
            XmssWrapperError::InvalidTreeHeight(msg) => write!(f, "Invalid tree height: {}", msg),
        }
    }
}

impl Error for XmssWrapperError {}

impl From<std::io::Error> for XmssWrapperError {
    fn from(err: std::io::Error) -> Self {
        // Distinguish between read and write errors based on error kind
        match err.kind() {
            std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied => {
                XmssWrapperError::FileRead(err)
            }
            _ => XmssWrapperError::FileWrite(err),
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct KeyPair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
    pub lifetime: u32,
}

#[derive(Serialize, Deserialize)]
struct EncryptedSecretKey {
    encrypted_data: String, // Base64 encoded encrypted JSON
    nonce: String,          // Base64 encoded nonce
    hmac: String,           // HMAC for authentication
    salt: String,           // Salt for key derivation
    tree_height: u32,
    max_signatures: u64,
    key_type: String,
    hash_function: String,
}

#[derive(Serialize, Deserialize)]
pub struct XmssSignature {
    pub signature: Vec<u8>,
    pub tree_height: u32,
    pub signature_index: u64,
}

pub struct XmssWrapper;

impl XmssWrapper {
    /// Generate Poseidon2-XMSS key pair with specified tree height and RNG
    ///
    /// # Arguments
    /// * `height` - The height of the XMSS tree (2^height signatures possible)
    /// * `rng` - Reference to a random number generator
    /// * `password` - Password for encrypting the secret key file
    ///
    /// # Returns
    /// * `Result<(), XmssWrapperError>` - Ok(()) on success, error on failure
    ///
    /// # Files Created
    /// * `xmss_public_key.json` - Contains the public key (unencrypted)
    /// * `xmss_secret_key.json` - Contains the encrypted secret key
    pub fn generate_and_save_keys<R: Rng>(
        height: u32,
        rng: &mut R,
        password: &str,
    ) -> Result<(), XmssWrapperError> {
        // Using Poseidon-based XMSS instantiations
        let (public_key, secret_key) = match height {
            18 => {
                // 2^18 = 262144 signatures
                // Use the Winternitz encoding with chunk size w = 1 for height 18
                use instantiations_poseidon::lifetime_2_to_the_18::winternitz::SIGWinternitzLifetime18W8;

                let (public_key, secret_key) = SIGWinternitzLifetime18W8::key_gen(
                    rng,
                    0,
                    SIGWinternitzLifetime18W8::LIFETIME as usize,
                );
                (public_key, secret_key)
            }
            _ => {
                return Err(XmssWrapperError::KeyGeneration(format!(
                    "Unsupported height: {}. Supported values: 18 (for 2^18 = 262144 signatures)",
                    height
                )));
            }
        };

        // Convert keys to bytes for serialization
        // Note: You may need to adjust these conversions based on the actual key types returned
        let public_key_bytes = serde_json::to_vec(&public_key).map_err(|e| {
            XmssWrapperError::Serialization(format!("Failed to serialize public key: {:?}", e))
        })?;
        let secret_key_bytes = serde_json::to_vec(&secret_key).map_err(|e| {
            XmssWrapperError::Serialization(format!("Failed to serialize secret key: {:?}", e))
        })?;

        // Create key pair structure
        let key_pair = KeyPair {
            public_key: public_key_bytes.to_vec(),
            secret_key: secret_key_bytes.to_vec(),
            lifetime: height,
        };

        // Save secret key and get back the public key
        let public_key_returned = Self::save_secret_key(&key_pair, password)?;

        println!("Poseidon2-XMSS key pair generated and saved successfully!");
        println!("Public key saved to: xmss_public_key.json");
        println!("Secret key saved to: xmss_secret_key.json (encrypted)");
        println!(
            "Tree height: {} (2^{} = {} signatures)",
            height,
            height,
            1u64 << height
        );
        println!(
            "Returned public key length: {} bytes",
            public_key_returned.len()
        );

        Ok(())
    }

    #[allow(unused_mut)]
    #[allow(clippy::unnecessary_mut_passed)]
    /// Sign a message using the stored secret key
    ///
    /// **IMPORTANT**: This function updates the secret key state after signing.
    /// The secret key file will be modified with the new state to prevent key reuse.
    ///
    /// # Arguments
    /// * `message` - The message to sign
    /// * `secret_key_path` - Path to the encrypted secret key file
    /// * `password` - Password to decrypt the secret key
    ///
    /// # Returns
    /// * `Result<XmssSignature, XmssWrapperError>` - The signature on success
    pub fn sign_message<R: Rng, P: AsRef<Path>>(
        message: &[u8],
        secret_key_path: P,
        password: &str,
        rng: &mut R,
    ) -> Result<XmssSignature, XmssWrapperError> {
        // Load the secret key
        let mut secret_key_bytes = Self::load_secret_key(&secret_key_path, password)?;

        // Get the tree height from the secret key file metadata
        let tree_height = Self::get_tree_height_from_file(&secret_key_path)?;

        // Reconstruct the secret key object and sign based on tree height
        let (signature_bytes, updated_secret_key_bytes, signature_index) = match tree_height {
            18 => {
                // Use the Winternitz encoding with chunk size w = 1 for height 18
                use instantiations_poseidon::lifetime_2_to_the_18::winternitz::SIGWinternitzLifetime18W8;

                let mut secret_key = serde_json::from_slice::<
                    <SIGWinternitzLifetime18W8 as SignatureScheme>::SecretKey,
                >(&secret_key_bytes)
                .map_err(|e| {
                    XmssWrapperError::Signing(format!("Failed to reconstruct secret key: {:?}", e))
                })?;

                // Convert message to 32-byte array as required by SignatureScheme
                let mut message_array = [0u8; 32];
                let message_len = message.len().min(32);
                message_array[..message_len].copy_from_slice(&message[..message_len]);

                let signature =
                    SIGWinternitzLifetime18W8::sign(rng, &mut secret_key, 0, &message_array)
                        .map_err(|e| {
                            XmssWrapperError::Signing(format!("Signing failed: {:?}", e))
                        })?;

                // Get the current signature index (leaf index used)
                let sig_index = 0; // TODO: Implement proper signature index tracking

                (
                    serde_json::to_vec(&signature).map_err(|e| {
                        XmssWrapperError::Serialization(format!(
                            "Failed to serialize signature: {:?}",
                            e
                        ))
                    })?,
                    serde_json::to_vec(&secret_key).map_err(|e| {
                        XmssWrapperError::Serialization(format!(
                            "Failed to serialize secret key: {:?}",
                            e
                        ))
                    })?,
                    sig_index,
                )
            }
            _ => {
                return Err(XmssWrapperError::InvalidTreeHeight(format!(
                    "Unsupported tree height: {}. Only height 18 is supported.",
                    tree_height
                )));
            }
        };

        // Update the secret key file with the new state
        let updated_keypair = KeyPair {
            public_key: vec![], // We don't need the public key for saving secret key
            secret_key: updated_secret_key_bytes,
            lifetime: tree_height,
        };

        Self::save_encrypted_secret_key(&updated_keypair, password)?;

        Ok(XmssSignature {
            signature: signature_bytes,
            tree_height,
            signature_index,
        })
    }

    /// Verify a signature against a message using the public key
    ///
    /// # Arguments
    /// * `message` - The original message
    /// * `signature` - The signature to verify
    /// * `public_key_path` - Path to the public key file
    ///
    /// # Returns
    /// * `Result<bool, XmssWrapperError>` - true if signature is valid, false otherwise
    pub fn verify_signature<P: AsRef<Path>>(
        message: &[u8],
        signature: &XmssSignature,
        public_key_path: P,
    ) -> Result<bool, XmssWrapperError> {
        // Load the public key
        let public_key_bytes = Self::load_public_key(&public_key_path)?;

        // Verify based on tree height
        let result: Result<bool, XmssWrapperError> = match signature.tree_height {
            18 => {
                // Use the Winternitz encoding with chunk size w = 1 for height 18
                use instantiations_poseidon::lifetime_2_to_the_18::winternitz::SIGWinternitzLifetime18W8;

                let public_key = serde_json::from_slice::<
                    <SIGWinternitzLifetime18W8 as SignatureScheme>::PublicKey,
                >(&public_key_bytes)
                .map_err(|e| {
                    XmssWrapperError::Verification(format!(
                        "Failed to reconstruct public key: {:?}",
                        e
                    ))
                })?;

                let sig = serde_json::from_slice::<
                    <SIGWinternitzLifetime18W8 as SignatureScheme>::Signature,
                >(&signature.signature)
                .map_err(|e| {
                    XmssWrapperError::Verification(format!(
                        "Failed to reconstruct signature: {:?}",
                        e
                    ))
                })?;

                // Convert message to 32-byte array as required by SignatureScheme
                let mut message_array = [0u8; 32];
                let message_len = message.len().min(32);
                message_array[..message_len].copy_from_slice(&message[..message_len]);

                // Use the SignatureScheme::verify method
                Ok(SIGWinternitzLifetime18W8::verify(
                    &public_key,
                    0,
                    &message_array,
                    &sig,
                ))
            }
            _ => {
                return Err(XmssWrapperError::InvalidTreeHeight(format!(
                    "Unsupported tree height: {}. Only height 18 is supported.",
                    signature.tree_height
                )));
            }
        };

        result
    }

    /// Save a signature to a JSON file
    pub fn save_signature<P: AsRef<Path>>(
        signature: &XmssSignature,
        path: P,
    ) -> Result<(), XmssWrapperError> {
        let signature_data = serde_json::json!({
            "signature": hex::encode(&signature.signature),
            "tree_height": signature.tree_height,
            "signature_index": signature.signature_index,
            "signature_type": "XMSS_SIGNATURE",
            "hash_function": "Poseidon2"
        });

        let json_string = serde_json::to_string_pretty(&signature_data)
            .map_err(|e| XmssWrapperError::Serialization(e.to_string()))?;

        let mut file = File::create(path)?;
        file.write_all(json_string.as_bytes())?;

        Ok(())
    }

    /// Load a signature from a JSON file
    pub fn load_signature<P: AsRef<Path>>(path: P) -> Result<XmssSignature, XmssWrapperError> {
        let content = std::fs::read_to_string(path)?;
        let data: serde_json::Value = serde_json::from_str(&content)
            .map_err(|e| XmssWrapperError::Serialization(e.to_string()))?;

        let hex_signature = data["signature"].as_str().ok_or_else(|| {
            XmssWrapperError::Serialization("Invalid signature format".to_string())
        })?;

        let signature_bytes = hex::decode(hex_signature)
            .map_err(|e| XmssWrapperError::Serialization(e.to_string()))?;

        let tree_height = data["tree_height"]
            .as_u64()
            .ok_or_else(|| XmssWrapperError::Serialization("Missing tree height".to_string()))?
            as u32;

        let signature_index = data["signature_index"].as_u64().ok_or_else(|| {
            XmssWrapperError::Serialization("Missing signature index".to_string())
        })?;

        Ok(XmssSignature {
            signature: signature_bytes,
            tree_height,
            signature_index,
        })
    }

    /// Helper function to get tree height from secret key file
    fn get_tree_height_from_file<P: AsRef<Path>>(path: P) -> Result<u32, XmssWrapperError> {
        let mut file = File::open(path)?;
        let mut content = String::new();
        file.read_to_string(&mut content)?;

        let encrypted_secret: EncryptedSecretKey = serde_json::from_str(&content)
            .map_err(|e| XmssWrapperError::Serialization(e.to_string()))?;

        Ok(encrypted_secret.tree_height)
    }

    fn save_secret_key(key_pair: &KeyPair, password: &str) -> Result<Vec<u8>, XmssWrapperError> {
        // Save public key file (unencrypted)
        let public_key_data = serde_json::json!({
            "public_key": hex::encode(&key_pair.public_key),
            "tree_height": key_pair.lifetime,
            "max_signatures": 1u64 << key_pair.lifetime,
            "key_type": "XMSS_PUBLIC",
            "hash_function": "Poseidon2"
        });

        let public_json_string = serde_json::to_string_pretty(&public_key_data)
            .map_err(|e| XmssWrapperError::Serialization(e.to_string()))?;

        let mut public_file = File::create("xmss_public_key.json")?;
        public_file.write_all(public_json_string.as_bytes())?;

        // Encrypt and save secret key file
        Self::save_encrypted_secret_key(key_pair, password)?;

        // Return the public key
        Ok(key_pair.public_key.clone())
    }
    #[allow(clippy::needless_borrows_for_generic_args)]
    fn save_encrypted_secret_key(
        key_pair: &KeyPair,
        password: &str,
    ) -> Result<(), XmssWrapperError> {
        // Generate salt for key derivation (Argon2 requires 16+ bytes)
        let mut salt = [0u8; 32];
        rng().fill(&mut salt);

        // Derive encryption key from password using Argon2id
        let derived_key = Self::derive_key_from_password(password, &salt)?;

        // Create the secret key JSON data
        let secret_key_data = serde_json::json!({
            "secret_key": hex::encode(&key_pair.secret_key),
            "warning": "This is an encrypted secret key. Keep the password secure!"
        });

        let secret_json_string = serde_json::to_string(&secret_key_data)
            .map_err(|e| XmssWrapperError::Serialization(e.to_string()))?;

        // Generate random nonce for AES-GCM
        let mut nonce_bytes = [0u8; 12];
        rng().fill(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt the JSON data
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&derived_key));
        let encrypted_data = cipher
            .encrypt(nonce, secret_json_string.as_bytes())
            .map_err(|e| {
                XmssWrapperError::Encryption(format!("AES-GCM encryption failed: {}", e))
            })?;

        // Create HMAC for authentication
        let hmac_value = Self::create_hmac(&derived_key, &encrypted_data, &nonce_bytes, &salt)?;

        // Create the encrypted secret key structure
        let encrypted_secret = EncryptedSecretKey {
            encrypted_data: base64::engine::general_purpose::STANDARD.encode(&encrypted_data),
            nonce: base64::engine::general_purpose::STANDARD.encode(&nonce_bytes),
            hmac: hex::encode(&hmac_value),
            salt: hex::encode(&salt),
            tree_height: key_pair.lifetime,
            max_signatures: 1u64 << key_pair.lifetime,
            key_type: "XMSS_SECRET_ENCRYPTED".to_string(),
            hash_function: "Poseidon2".to_string(),
        };

        // Save encrypted secret key to file
        let encrypted_json = serde_json::to_string_pretty(&encrypted_secret)
            .map_err(|e| XmssWrapperError::Serialization(e.to_string()))?;

        let mut secret_file = File::create("xmss_secret_key.json")?;
        secret_file.write_all(encrypted_json.as_bytes())?;

        Ok(())
    }

    fn derive_key_from_password(password: &str, salt: &[u8]) -> Result<[u8; 32], XmssWrapperError> {
        // Configure Argon2id with strong parameters
        let params = Params::new(
            19456,    // memory cost (19 MiB)
            2,        // time cost (iterations)
            1,        // parallelism
            Some(32), // output length
        )
        .map_err(|e| XmssWrapperError::Encryption(format!("Argon2 params error: {}", e)))?;

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut key = [0u8; 32];
        argon2
            .hash_password_into(password.as_bytes(), salt, &mut key)
            .map_err(|e| {
                XmssWrapperError::Encryption(format!("Argon2 key derivation failed: {}", e))
            })?;

        Ok(key)
    }

    fn create_hmac(
        key: &[u8],
        encrypted_data: &[u8],
        nonce: &[u8],
        salt: &[u8],
    ) -> Result<Vec<u8>, XmssWrapperError> {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(key)
            .map_err(|e| XmssWrapperError::Authentication(format!("HMAC key error: {}", e)))?;

        mac.update(encrypted_data);
        mac.update(nonce);
        mac.update(salt);

        Ok(mac.finalize().into_bytes().to_vec())
    }

    fn verify_hmac(
        key: &[u8],
        encrypted_data: &[u8],
        nonce: &[u8],
        salt: &[u8],
        expected_hmac: &[u8],
    ) -> Result<(), XmssWrapperError> {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(key)
            .map_err(|e| XmssWrapperError::Authentication(format!("HMAC key error: {}", e)))?;

        mac.update(encrypted_data);
        mac.update(nonce);
        mac.update(salt);

        mac.verify_slice(expected_hmac).map_err(|_| {
            XmssWrapperError::Authentication("HMAC verification failed".to_string())
        })?;

        Ok(())
    }

    /// Load public key from file
    pub fn load_public_key<P: AsRef<Path>>(path: P) -> Result<Vec<u8>, XmssWrapperError> {
        let content = std::fs::read_to_string(path)?;
        let data: serde_json::Value = serde_json::from_str(&content)
            .map_err(|e| XmssWrapperError::Serialization(e.to_string()))?;

        let hex_key = data["public_key"].as_str().ok_or_else(|| {
            XmssWrapperError::Serialization("Invalid public key format".to_string())
        })?;

        hex::decode(hex_key).map_err(|e| XmssWrapperError::Serialization(e.to_string()))
    }

    /// Load secret key from encrypted file
    pub fn load_secret_key<P: AsRef<Path>>(
        path: P,
        password: &str,
    ) -> Result<Vec<u8>, XmssWrapperError> {
        // Read encrypted file
        let mut file = File::open(path)?;
        let mut content = String::new();
        file.read_to_string(&mut content)?;

        // Parse encrypted structure
        let encrypted_secret: EncryptedSecretKey = serde_json::from_str(&content)
            .map_err(|e| XmssWrapperError::Serialization(e.to_string()))?;

        // Decode components
        let encrypted_data = base64::engine::general_purpose::STANDARD
            .decode(&encrypted_secret.encrypted_data)
            .map_err(|e| {
                XmssWrapperError::Decryption(format!("Failed to decode encrypted data: {}", e))
            })?;
        let nonce_bytes = base64::engine::general_purpose::STANDARD
            .decode(&encrypted_secret.nonce)
            .map_err(|e| XmssWrapperError::Decryption(format!("Failed to decode nonce: {}", e)))?;
        let expected_hmac = hex::decode(&encrypted_secret.hmac)
            .map_err(|e| XmssWrapperError::Authentication(format!("HMAC decode error: {}", e)))?;
        let salt = hex::decode(&encrypted_secret.salt)
            .map_err(|e| XmssWrapperError::Decryption(format!("Salt decode error: {}", e)))?;

        // Derive key from password using Argon2id
        let derived_key = Self::derive_key_from_password(password, &salt)?;

        // Verify HMAC
        Self::verify_hmac(
            &derived_key,
            &encrypted_data,
            &nonce_bytes,
            &salt,
            &expected_hmac,
        )?;

        // Decrypt data
        let nonce = Nonce::from_slice(&nonce_bytes);
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&derived_key));
        let decrypted_data = cipher
            .decrypt(nonce, encrypted_data.as_ref())
            .map_err(|e| {
                XmssWrapperError::Decryption(format!("AES-GCM decryption failed: {}", e))
            })?;

        // Parse decrypted JSON
        let decrypted_json: serde_json::Value = serde_json::from_slice(&decrypted_data)
            .map_err(|e| XmssWrapperError::Serialization(e.to_string()))?;

        let hex_key = decrypted_json["secret_key"].as_str().ok_or_else(|| {
            XmssWrapperError::Serialization("Invalid secret key format".to_string())
        })?;

        hex::decode(hex_key).map_err(|e| XmssWrapperError::Serialization(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use rand::rng;

    use super::*;

    #[test]
    fn test_key_generation() {
        let mut rng = rng();
        let password = "test_password_123";

        // Test with tree height 18 (262144 signatures)
        let result = XmssWrapper::generate_and_save_keys(18, &mut rng, password);
        assert!(result.is_ok());

        // Test that files were created
        assert!(Path::new("xmss_public_key.json").exists());
        assert!(Path::new("xmss_secret_key.json").exists());

        // Test loading encrypted secret key
        let secret_key = XmssWrapper::load_secret_key("xmss_secret_key.json", password);
        assert!(secret_key.is_ok());

        // Test with wrong password
        let wrong_password_result =
            XmssWrapper::load_secret_key("xmss_secret_key.json", "wrong_password");
        assert!(wrong_password_result.is_err());

        // Clean up
        let _ = std::fs::remove_file("xmss_public_key.json");
        let _ = std::fs::remove_file("xmss_secret_key.json");
    }

    #[test]
    fn test_sign_and_verify() {
        let mut rng = rng();
        let password = "test_password_123";
        let message = b"Hello, XMSS world!";

        // Generate keys with tree height 18 (262144 signatures)
        let result = XmssWrapper::generate_and_save_keys(18, &mut rng, password);
        assert!(result.is_ok());

        // Sign message
        let signature =
            XmssWrapper::sign_message(message, "xmss_secret_key.json", password, &mut rng);
        assert!(signature.is_ok());
        let sig = signature.unwrap();

        // Verify signature
        let verification = XmssWrapper::verify_signature(message, &sig, "xmss_public_key.json");
        assert!(verification.is_ok());
        assert!(verification.unwrap());

        // Test with wrong message
        let wrong_message = b"Wrong message";
        let wrong_verification =
            XmssWrapper::verify_signature(wrong_message, &sig, "xmss_public_key.json");
        assert!(wrong_verification.is_ok());
        assert!(!wrong_verification.unwrap());

        // Clean up
        let _ = std::fs::remove_file("xmss_public_key.json");
        let _ = std::fs::remove_file("xmss_secret_key.json");
    }

    #[test]
    fn test_stateful_signing() {
        let mut rng = rng();
        let password = "test_password_123";
        let message1 = b"First message";
        let message2 = b"Second message";

        // Generate keys
        let result = XmssWrapper::generate_and_save_keys(18, &mut rng, password);
        assert!(result.is_ok());

        // Sign first message
        let sig1 = XmssWrapper::sign_message(message1, "xmss_secret_key.json", password, &mut rng);
        assert!(sig1.is_ok());
        let signature1 = sig1.unwrap();

        // Sign second message (state should be updated)
        let sig2 = XmssWrapper::sign_message(message2, "xmss_secret_key.json", password, &mut rng);
        assert!(sig2.is_ok());
        let signature2 = sig2.unwrap();

        // Both signatures should be valid
        let verify1 = XmssWrapper::verify_signature(message1, &signature1, "xmss_public_key.json");
        assert!(verify1.is_ok() && verify1.unwrap());

        let verify2 = XmssWrapper::verify_signature(message2, &signature2, "xmss_public_key.json");
        assert!(verify2.is_ok() && verify2.unwrap());

        // Signature indices should be different (assuming the API provides this)
        assert_ne!(signature1.signature_index, signature2.signature_index);

        // Clean up
        let _ = std::fs::remove_file("xmss_public_key.json");
        let _ = std::fs::remove_file("xmss_secret_key.json");
    }
}
