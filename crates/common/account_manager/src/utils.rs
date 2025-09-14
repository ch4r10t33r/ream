use anyhow::{Result, anyhow};

/// Validates that a string contains only valid hexadecimal characters
///
/// # Arguments
/// * `hex_str` - The string to validate
/// * `field_name` - The name of the field being validated (for error messages)
///
/// # Returns
/// * `Result<()>` - Ok if valid, Err with descriptive message if invalid
pub fn validate_hex_string(hex_str: &str, field_name: &str) -> Result<()> {
    if !hex_str.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(anyhow!("{} must be a valid hex string", field_name));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_hex_string_valid() {
        assert!(validate_hex_string("0123456789abcdef", "test").is_ok());
        assert!(validate_hex_string("ABCDEF", "test").is_ok());
        assert!(validate_hex_string("", "test").is_ok());
    }

    #[test]
    fn test_validate_hex_string_invalid() {
        assert!(validate_hex_string("0123456789abcdefg", "test").is_err());
        assert!(validate_hex_string("hello world", "test").is_err());
        assert!(validate_hex_string("0123456789abcdef!", "test").is_err());
    }
}
