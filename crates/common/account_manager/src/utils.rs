use anyhow::anyhow;

/// Validates that a string contains only valid hexadecimal characters
///
/// # Arguments
/// * `hex_str` - The string to validate
///
/// # Returns
/// * `Result<()>` - Ok if valid, Err with descriptive message if invalid
pub fn validate_hex_string(hex_str: &str) -> anyhow::Result<()> {
    if !hex_str.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(anyhow!("{hex_str} must be a valid hex string"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_hex_string_valid() {
        assert!(validate_hex_string("0123456789abcdef").is_ok());
        assert!(validate_hex_string("ABCDEF").is_ok());
        assert!(validate_hex_string("").is_ok());
    }

    #[test]
    fn test_validate_hex_string_invalid() {
        assert!(validate_hex_string("0123456789abcdefg").is_err());
        assert!(validate_hex_string("hello world").is_err());
        assert!(validate_hex_string("0123456789abcdef!").is_err());
    }
}
