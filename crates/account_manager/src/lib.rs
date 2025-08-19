use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};

use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit},
};
use anyhow::Result;
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{self, Engine};
use hmac::{Hmac, Mac};
use rand::{Rng, rng};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

// Re-export the KeyPair and XmssSignature from the pqc crate
pub use ream_pqc::keystore::{KeyPair, XmssSignature};

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

/// Error enum for account manager operations
#[derive(Debug, thiserror::Error)]
pub enum AccountManagerError {
    #[error("File I/O error: {0}")]
    FileIO(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Encryption error: {0}")]
    Encryption(String),
    #[error("Decryption error: {0}")]
    Decryption(String),
    #[error("Authentication error: {0}")]
    Authentication(String),
}

/// Generate and save XMSS key pair with encryption
pub fn generate_and_save_keys(height: u32, password: &str) -> Result<(), AccountManagerError> {
    use ream_pqc::keystore::XmssWrapper;

    let mut rng = rng();

    // Generate keys using the pqc crate
    let key_pair = XmssWrapper::generate_keys(height, &mut rng)
        .map_err(|e| AccountManagerError::Serialization(e.to_string()))?;

    // Save keys
    save_secret_key(&key_pair, password)?;

    println!("Poseidon2-XMSS key pair generated and saved successfully!");
    println!("Public key saved to: xmss_public_key.json");
    println!("Secret key saved to: xmss_secret_key.json (encrypted)");
    println!(
        "Tree height: {} (2^{} = {} signatures)",
        height,
        height,
        1u64 << height
    );

    Ok(())
}

/// Save encrypted secret key and public key
fn save_secret_key(key_pair: &KeyPair, password: &str) -> Result<(), AccountManagerError> {
    // Save public key file (unencrypted)
    let public_key_data = serde_json::json!({
        "public_key": hex::encode(&key_pair.public_key),
        "tree_height": key_pair.lifetime,
        "max_signatures": 1u64 << key_pair.lifetime,
        "key_type": "XMSS_PUBLIC",
        "hash_function": "Poseidon2"
    });

    let public_json_string = serde_json::to_string_pretty(&public_key_data)
        .map_err(|e| AccountManagerError::Serialization(e.to_string()))?;

    let mut public_file = File::create("xmss_public_key.json")?;
    public_file.write_all(public_json_string.as_bytes())?;

    // Encrypt and save secret key file
    save_encrypted_secret_key(key_pair, password)?;

    Ok(())
}

/// Save encrypted secret key with AES-GCM encryption and HMAC authentication
fn save_encrypted_secret_key(
    key_pair: &KeyPair,
    password: &str,
) -> Result<(), AccountManagerError> {
    // Generate salt for key derivation (Argon2 requires 16+ bytes)
    let mut salt = [0u8; 32];
    rng().fill(&mut salt);

    // Derive encryption key from password using Argon2id
    let derived_key = derive_key_from_password(password, &salt)?;

    // Create the secret key JSON data
    let secret_key_data = serde_json::json!({
        "secret_key": hex::encode(&key_pair.secret_key),
        "warning": "This is an encrypted secret key. Keep the password secure!"
    });

    let secret_json_string = serde_json::to_string(&secret_key_data)
        .map_err(|e| AccountManagerError::Serialization(e.to_string()))?;

    // Generate random nonce for AES-GCM
    let mut nonce_bytes = [0u8; 12];
    rng().fill(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt the JSON data
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&derived_key));
    let encrypted_data = cipher
        .encrypt(nonce, secret_json_string.as_bytes())
        .map_err(|e| {
            AccountManagerError::Encryption(format!("AES-GCM encryption failed: {}", e))
        })?;

    // Create HMAC for authentication
    let hmac_value = create_hmac(&derived_key, &encrypted_data, &nonce_bytes, &salt)?;

    // Create the encrypted secret key structure
    let encrypted_secret = EncryptedSecretKey {
        encrypted_data: base64::engine::general_purpose::STANDARD.encode(&encrypted_data),
        nonce: base64::engine::general_purpose::STANDARD.encode(nonce_bytes),
        hmac: hex::encode(&hmac_value),
        salt: hex::encode(salt),
        tree_height: key_pair.lifetime,
        max_signatures: 1u64 << key_pair.lifetime,
        key_type: "XMSS_SECRET_ENCRYPTED".to_string(),
        hash_function: "Poseidon2".to_string(),
    };

    // Save encrypted secret key to file
    let encrypted_json = serde_json::to_string_pretty(&encrypted_secret)
        .map_err(|e| AccountManagerError::Serialization(e.to_string()))?;

    let mut secret_file = File::create("xmss_secret_key.json")?;
    secret_file.write_all(encrypted_json.as_bytes())?;

    Ok(())
}

/// Derive encryption key from password using Argon2id
fn derive_key_from_password(password: &str, salt: &[u8]) -> Result<[u8; 32], AccountManagerError> {
    // Configure Argon2id with strong parameters
    let params = Params::new(
        19456,    // memory cost (19 MiB)
        2,        // time cost (iterations)
        1,        // parallelism
        Some(32), // output length
    )
    .map_err(|e| AccountManagerError::Encryption(format!("Argon2 params error: {}", e)))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| {
            AccountManagerError::Encryption(format!("Argon2 key derivation failed: {}", e))
        })?;

    Ok(key)
}

/// Create HMAC for authentication
fn create_hmac(
    key: &[u8],
    encrypted_data: &[u8],
    nonce: &[u8],
    salt: &[u8],
) -> Result<Vec<u8>, AccountManagerError> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key)
        .map_err(|e| AccountManagerError::Authentication(format!("HMAC key error: {}", e)))?;

    mac.update(encrypted_data);
    mac.update(nonce);
    mac.update(salt);

    Ok(mac.finalize().into_bytes().to_vec())
}

/// Verify HMAC for authentication
fn verify_hmac(
    key: &[u8],
    encrypted_data: &[u8],
    nonce: &[u8],
    salt: &[u8],
    expected_hmac: &[u8],
) -> Result<(), AccountManagerError> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key)
        .map_err(|e| AccountManagerError::Authentication(format!("HMAC key error: {}", e)))?;

    mac.update(encrypted_data);
    mac.update(nonce);
    mac.update(salt);

    mac.verify_slice(expected_hmac)
        .map_err(|_| AccountManagerError::Authentication("HMAC verification failed".to_string()))?;

    Ok(())
}

/// Load public key from file
pub fn load_public_key<P: AsRef<Path>>(path: P) -> Result<Vec<u8>, AccountManagerError> {
    let content = std::fs::read_to_string(path)?;
    let data: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| AccountManagerError::Serialization(e.to_string()))?;

    let hex_key = data["public_key"].as_str().ok_or_else(|| {
        AccountManagerError::Serialization("Invalid public key format".to_string())
    })?;

    hex::decode(hex_key).map_err(|e| AccountManagerError::Serialization(e.to_string()))
}

/// Load secret key from encrypted file
pub fn load_secret_key<P: AsRef<Path>>(
    path: P,
    password: &str,
) -> Result<Vec<u8>, AccountManagerError> {
    // Read encrypted file
    let mut file = File::open(path)?;
    let mut content = String::new();
    file.read_to_string(&mut content)?;

    // Parse encrypted structure
    let encrypted_secret: EncryptedSecretKey = serde_json::from_str(&content)
        .map_err(|e| AccountManagerError::Serialization(e.to_string()))?;

    // Decode components
    let encrypted_data = base64::engine::general_purpose::STANDARD
        .decode(&encrypted_secret.encrypted_data)
        .map_err(|e| {
            AccountManagerError::Decryption(format!("Failed to decode encrypted data: {}", e))
        })?;
    let nonce_bytes = base64::engine::general_purpose::STANDARD
        .decode(&encrypted_secret.nonce)
        .map_err(|e| AccountManagerError::Decryption(format!("Failed to decode nonce: {}", e)))?;
    let expected_hmac = hex::decode(&encrypted_secret.hmac)
        .map_err(|e| AccountManagerError::Authentication(format!("HMAC decode error: {}", e)))?;
    let salt = hex::decode(&encrypted_secret.salt)
        .map_err(|e| AccountManagerError::Decryption(format!("Salt decode error: {}", e)))?;

    // Derive key from password using Argon2id
    let derived_key = derive_key_from_password(password, &salt)?;

    // Verify HMAC
    verify_hmac(
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
            AccountManagerError::Decryption(format!("AES-GCM decryption failed: {}", e))
        })?;

    // Parse decrypted JSON
    let decrypted_json: serde_json::Value = serde_json::from_slice(&decrypted_data)
        .map_err(|e| AccountManagerError::Serialization(e.to_string()))?;

    let hex_key = decrypted_json["secret_key"].as_str().ok_or_else(|| {
        AccountManagerError::Serialization("Invalid secret key format".to_string())
    })?;

    hex::decode(hex_key).map_err(|e| AccountManagerError::Serialization(e.to_string()))
}

/// Sign a message using stored secret key
pub fn sign_message(
    message: &[u8],
    secret_key_path: &Path,
    password: &str,
) -> Result<XmssSignature, AccountManagerError> {
    use ream_pqc::keystore::XmssWrapper;

    let mut rng = rng();

    // Load the secret key
    let secret_key_bytes = load_secret_key(secret_key_path, password)?;

    // Get tree height from the secret key file metadata
    let tree_height = get_tree_height_from_file(secret_key_path)?;

    // Sign the message
    let (signature, updated_secret_key_bytes) =
        XmssWrapper::sign_message(message, &secret_key_bytes, tree_height, &mut rng)
            .map_err(|e| AccountManagerError::Serialization(e.to_string()))?;

    // Update the secret key file with the new state
    let updated_keypair = KeyPair {
        public_key: vec![], // We don't need the public key for saving secret key
        secret_key: updated_secret_key_bytes,
        lifetime: tree_height,
    };

    save_encrypted_secret_key(&updated_keypair, password)?;

    Ok(signature)
}

/// Verify a signature against a message using stored public key
pub fn verify_signature(
    message: &[u8],
    signature: &XmssSignature,
    public_key_path: &Path,
) -> Result<bool, AccountManagerError> {
    use ream_pqc::keystore::XmssWrapper;

    // Load the public key
    let public_key_bytes = load_public_key(public_key_path)?;

    // Verify the signature
    let is_valid = XmssWrapper::verify_signature(message, signature, &public_key_bytes)
        .map_err(|e| AccountManagerError::Serialization(e.to_string()))?;

    Ok(is_valid)
}

/// Helper function to get tree height from secret key file
fn get_tree_height_from_file<P: AsRef<Path>>(path: P) -> Result<u32, AccountManagerError> {
    let mut file = File::open(path)?;
    let mut content = String::new();
    file.read_to_string(&mut content)?;

    let encrypted_secret: EncryptedSecretKey = serde_json::from_str(&content)
        .map_err(|e| AccountManagerError::Serialization(e.to_string()))?;

    Ok(encrypted_secret.tree_height)
}
