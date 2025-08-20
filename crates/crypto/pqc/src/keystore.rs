use std::{error::Error, fmt};

use hashsig::{
    inc_encoding::basic_winternitz::WinternitzEncoding,
    signature::{
        SignatureScheme,
        generalized_xmss::{
            GeneralizedXMSSSignatureScheme,
            instantiations_poseidon::{self},
        },
    },
    symmetric::{
        message_hash::poseidon::PoseidonMessageHash, prf::shake_to_field::ShakePRFtoF,
        tweak_hash::poseidon::PoseidonTweakHash,
    },
};
use rand::Rng;
use serde::{Deserialize, Serialize};

// Custom signature scheme with lifetime 2^8
mod custom_lifetime_8 {
    use super::*;

    // Configuration constants for lifetime 2^8
    const LOG_LIFETIME: usize = 8;
    const PARAMETER_LEN: usize = 5;

    const HASH_LEN_FE: usize = 7;
    const MSG_LEN_FE: usize = 9;
    const TWEAK_LEN_FE: usize = 2;
    const RAND_LEN: usize = 5;
    const CAPACITY: usize = 9;

    // Winternitz encoding parameters for chunk size 8
    const CHUNK_SIZE_W8: usize = 8;
    const BASE_W8: usize = 256;
    const NUM_CHUNKS_W8: usize = 20;
    const NUM_CHUNKS_CHECKSUM_W8: usize = 2;

    // Type definitions
    type MHw8 = PoseidonMessageHash<
        PARAMETER_LEN,
        RAND_LEN,
        HASH_LEN_FE,
        NUM_CHUNKS_W8,
        BASE_W8,
        TWEAK_LEN_FE,
        MSG_LEN_FE,
    >;
    type THw8 =
        PoseidonTweakHash<PARAMETER_LEN, HASH_LEN_FE, TWEAK_LEN_FE, CAPACITY, NUM_CHUNKS_W8>;
    type PRFw8 = ShakePRFtoF<HASH_LEN_FE>;
    type IEw8 = WinternitzEncoding<MHw8, CHUNK_SIZE_W8, NUM_CHUNKS_CHECKSUM_W8>;

    /// Custom instantiation with Lifetime 2^8, Winternitz encoding, chunk size w = 8
    pub type CustomSIGWinternitzLifetime8W8 =
        GeneralizedXMSSSignatureScheme<PRFw8, IEw8, THw8, LOG_LIFETIME>;
}

#[allow(unused_imports)]
use custom_lifetime_8::CustomSIGWinternitzLifetime8W8;

#[derive(Debug)]
pub enum XmssWrapperError {
    KeyGeneration(String),
    Serialization(String),
    Signing(String),
    Verification(String),
    InvalidTreeHeight(String),
}

impl fmt::Display for XmssWrapperError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            XmssWrapperError::KeyGeneration(msg) => write!(f, "Key generation error: {}", msg),
            XmssWrapperError::Serialization(msg) => write!(f, "Serialization error: {}", msg),
            XmssWrapperError::Signing(msg) => write!(f, "Signing error: {}", msg),
            XmssWrapperError::Verification(msg) => write!(f, "Verification error: {}", msg),
            XmssWrapperError::InvalidTreeHeight(msg) => write!(f, "Invalid tree height: {}", msg),
        }
    }
}

impl Error for XmssWrapperError {}

#[derive(Serialize, Deserialize, Clone)]
pub struct KeyPair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
    pub lifetime: u32,
}

#[derive(Serialize, Deserialize)]
pub struct XmssSignature {
    pub signature: Vec<u8>,
    pub tree_height: u32,
    pub signature_index: u32, // TODO: Implement proper signature index tracking
}

pub struct XmssWrapper;

impl XmssWrapper {
    /// Generate XMSS key pair (serialized) for a given tree height.
    pub fn generate_keys<R: Rng>(height: u32, rng: &mut R) -> Result<KeyPair, XmssWrapperError> {
        let (public_key, secret_key) = match height {
            18 => {
                use instantiations_poseidon::lifetime_2_to_the_18::winternitz::SIGWinternitzLifetime18W8;
                let (public_key, secret_key) = SIGWinternitzLifetime18W8::key_gen(
                    rng,
                    0,
                    SIGWinternitzLifetime18W8::LIFETIME as usize,
                );
                (public_key, secret_key)
            }
            8 => {
                use custom_lifetime_8::CustomSIGWinternitzLifetime8W8;
                let (public_key, secret_key) = CustomSIGWinternitzLifetime8W8::key_gen(
                    rng,
                    0,
                    CustomSIGWinternitzLifetime8W8::LIFETIME as usize,
                );
                (public_key, secret_key)
            }
            _ => {
                return Err(XmssWrapperError::KeyGeneration(format!(
                    "Unsupported height: {}. Supported values: 18 (for 2^18 = 262144 signatures), 8 (for 2^8 = 256 signatures)",
                    height
                )));
            }
        };

        let public_key_bytes = serde_json::to_vec(&public_key).map_err(|e| {
            XmssWrapperError::Serialization(format!("Failed to serialize public key: {:?}", e))
        })?;
        let secret_key_bytes = serde_json::to_vec(&secret_key).map_err(|e| {
            XmssWrapperError::Serialization(format!("Failed to serialize secret key: {:?}", e))
        })?;

        Ok(KeyPair {
            public_key: public_key_bytes,
            secret_key: secret_key_bytes,
            lifetime: height,
        })
    }

    /// Sign a message using the serialized secret key. Returns signature and updated secret key
    /// bytes.
    pub fn sign_message<R: Rng>(
        message: &[u8],
        secret_key_bytes: &[u8],
        tree_height: u32,
        rng: &mut R,
        epoch: u32,
    ) -> Result<(XmssSignature, Vec<u8>), XmssWrapperError> {
        // TODO: Implement proper signature index tracking

        let secret_key_bytes_vec = secret_key_bytes.to_vec();

        // Reconstruct the secret key object and sign based on tree height
        let (signature_bytes, updated_secret_key_bytes, sig_index) = match tree_height {
            18 => {
                // Use the Winternitz encoding with chunk size w = 1 for height 18
                use instantiations_poseidon::lifetime_2_to_the_18::winternitz::SIGWinternitzLifetime18W8;

                let mut secret_key = serde_json::from_slice::<
                    <SIGWinternitzLifetime18W8 as SignatureScheme>::SecretKey,
                >(&secret_key_bytes_vec)
                .map_err(|e| {
                    XmssWrapperError::Signing(format!("Failed to reconstruct secret key: {:?}", e))
                })?;

                // Convert message to 32-byte array as required by SignatureScheme
                let mut message_array = [0u8; 32];
                let message_len = message.len().min(32);
                message_array[..message_len].copy_from_slice(&message[..message_len]);

                #[allow(clippy::unnecessary_mut_passed)]
                let signature =
                    SIGWinternitzLifetime18W8::sign(rng, &mut secret_key, epoch, &message_array)
                        .map_err(|e| {
                            XmssWrapperError::Signing(format!("Signing failed: {:?}", e))
                        })?;

                // Assign the epoch to sig_index
                let sig_index = epoch;

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
            8 => {
                use custom_lifetime_8::CustomSIGWinternitzLifetime8W8;
                let mut secret_key = serde_json::from_slice::<
                    <CustomSIGWinternitzLifetime8W8 as SignatureScheme>::SecretKey,
                >(&secret_key_bytes_vec)
                .map_err(|e| {
                    XmssWrapperError::Signing(format!("Failed to reconstruct secret key: {:?}", e))
                })?;

                // Convert message to 32-byte array as required by SignatureScheme
                let mut message_array = [0u8; 32];
                let message_len = message.len().min(32);
                message_array[..message_len].copy_from_slice(&message[..message_len]);

                #[allow(clippy::unnecessary_mut_passed)]
                let signature = CustomSIGWinternitzLifetime8W8::sign(
                    rng,
                    &mut secret_key,
                    epoch,
                    &message_array,
                )
                .map_err(|e| XmssWrapperError::Signing(format!("Signing failed: {:?}", e)))?;

                // Assign the epoch to sig_index
                let sig_index = epoch;

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
                    "Unsupported tree height: {}. Only height 18 and 8 are supported.",
                    tree_height
                )));
            }
        };

        Ok((
            XmssSignature {
                signature: signature_bytes,
                tree_height,
                signature_index: sig_index,
            },
            updated_secret_key_bytes,
        ))
    }

    /// Verify a signature against a message using the serialized public key.
    pub fn verify_signature(
        message: &[u8],
        signature: &XmssSignature,
        public_key_bytes: &[u8],
        epoch: u32,
    ) -> Result<bool, XmssWrapperError> {
        // Verify based on tree height
        let result: Result<bool, XmssWrapperError> = match signature.tree_height {
            18 => {
                // Use the Winternitz encoding with chunk size w = 1 for height 18
                use instantiations_poseidon::lifetime_2_to_the_18::winternitz::SIGWinternitzLifetime18W8;

                let public_key = serde_json::from_slice::<
                    <SIGWinternitzLifetime18W8 as SignatureScheme>::PublicKey,
                >(public_key_bytes)
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
                    epoch,
                    &message_array,
                    &sig,
                ))
            }
            8 => {
                use custom_lifetime_8::CustomSIGWinternitzLifetime8W8;
                let public_key = serde_json::from_slice::<
                    <CustomSIGWinternitzLifetime8W8 as SignatureScheme>::PublicKey,
                >(public_key_bytes)
                .map_err(|e| {
                    XmssWrapperError::Verification(format!(
                        "Failed to reconstruct public key: {:?}",
                        e
                    ))
                })?;

                let sig = serde_json::from_slice::<
                    <CustomSIGWinternitzLifetime8W8 as SignatureScheme>::Signature,
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
                Ok(CustomSIGWinternitzLifetime8W8::verify(
                    &public_key,
                    epoch,
                    &message_array,
                    &sig,
                ))
            }
            _ => {
                return Err(XmssWrapperError::InvalidTreeHeight(format!(
                    "Unsupported tree height: {}. Only height 18 and 8 are supported.",
                    signature.tree_height
                )));
            }
        };

        result
    }
}

#[cfg(test)]
mod tests {
    use rand::rng;

    use super::*;

    #[test]
    fn test_key_generation() {
        let mut rng = rng();

        let result = XmssWrapper::generate_keys(8, &mut rng);
        assert!(result.is_ok());

        let key_pair = result.unwrap();
        assert_eq!(key_pair.lifetime, 8);
        assert!(!key_pair.public_key.is_empty());
        assert!(!key_pair.secret_key.is_empty());

        // Test with tree height 8 (256 signatures)
        let result_8 = XmssWrapper::generate_keys(8, &mut rng);
        assert!(result_8.is_ok());

        let key_pair_8 = result_8.unwrap();
        assert_eq!(key_pair_8.lifetime, 8);
        assert!(!key_pair_8.public_key.is_empty());
        assert!(!key_pair_8.secret_key.is_empty());
    }

    #[test]
    fn test_sign_and_verify() {
        let mut rng = rng();
        let message = b"Hello, XMSS world!";

        // Generate keys with tree height 8 (256 signatures)
        let result = XmssWrapper::generate_keys(8, &mut rng);
        assert!(result.is_ok());
        let key_pair = result.unwrap();

        // Sign message with epoch 0
        let signature = XmssWrapper::sign_message(message, &key_pair.secret_key, 8, &mut rng, 0);
        assert!(signature.is_ok());
        let (sig, _updated_secret_key) = signature.unwrap();

        // Verify signature with epoch 0
        let verification = XmssWrapper::verify_signature(message, &sig, &key_pair.public_key, 0);
        assert!(verification.is_ok());
        assert!(verification.unwrap());

        // Test with wrong message
        let wrong_message = b"Wrong message";
        let wrong_verification =
            XmssWrapper::verify_signature(wrong_message, &sig, &key_pair.public_key, 0);
        assert!(wrong_verification.is_ok());
        assert!(!wrong_verification.unwrap());

        // Test with different epoch
        let result_8 = XmssWrapper::generate_keys(8, &mut rng);
        assert!(result_8.is_ok());
        let key_pair_8 = result_8.unwrap();

        let signature_8 =
            XmssWrapper::sign_message(message, &key_pair_8.secret_key, 8, &mut rng, 1);
        assert!(signature_8.is_ok());
        let (sig_8, _updated_secret_key_8) = signature_8.unwrap();

        let verification_8 =
            XmssWrapper::verify_signature(message, &sig_8, &key_pair_8.public_key, 1);
        assert!(verification_8.is_ok());
        assert!(verification_8.unwrap());
    }
}
