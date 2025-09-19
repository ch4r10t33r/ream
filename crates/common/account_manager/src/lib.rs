pub mod keystore;
pub mod message_types;
pub mod utils;

use std::str::FromStr;

use bip39::Mnemonic;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use ream_post_quantum_crypto::hashsig::{private_key::PrivateKey, public_key::PublicKey};
use sha2::{Digest, Sha256};
use tracing::info;

pub fn generate_key_pair_with_salt(
    seed_phrase: &str,
    wallet_index: u32,
    activation_epoch: u32,
    num_active_epochs: u32,
    passphrase: &str,
) -> (PublicKey, PrivateKey) {
    info!(
        "Generating lean consensus validator keys for index {wallet_index} with activation_epoch={activation_epoch}, num_active_epochs={num_active_epochs}....."
    );

    // Parse the mnemonic phrase
    let mnemonic = Mnemonic::from_str(seed_phrase).expect("Invalid mnemonic phrase");

    // Generate seed from mnemonic using provided passphrase
    let seed = mnemonic.to_seed(passphrase);

    // Create a deterministic seed based on the original seed and wallet index
    let mut hasher = Sha256::new();
    hasher.update(seed);
    hasher.update(wallet_index.to_be_bytes());
    let derived_seed: [u8; 32] = hasher.finalize().into();

    // Use the derived seed directly for hashsig key generation
    let (public_key, private_key) = PrivateKey::generate_key_pair(
        &mut <ChaCha20Rng as SeedableRng>::from_seed(derived_seed),
        activation_epoch as usize,
        num_active_epochs as usize,
    );

    // Display public key contents
    match serde_json::to_string_pretty(&public_key.inner) {
        Ok(json) => info!("Public key contents: {json}"),
        Err(err) => info!("Public key generated successfully (could not serialize) due to {err}"),
    }

    (public_key, private_key)
}
