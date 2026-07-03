//! Encoded variant detection for secret leakage.
//!
//! This module pre-computes various encoded forms of secrets to detect
//! them even when transformed through common encodings:
//!
//! - Base64 (standard and URL-safe, with and without padding)
//! - URL/percent encoding (single and double)
//! - Hexadecimal (lowercase and uppercase)
//! - HTML entities (decimal and hex)
//! - JSON escape sequences
//! - Unicode escape sequences
//! - Reversed strings
//! - ROT13 transformation

use crate::EncodingType;
use base64::{engine::general_purpose, Engine};
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};

/// An encoded variant of a secret.
#[derive(Debug, Clone)]
pub struct EncodedVariant {
    /// The encoding type.
    pub encoding: EncodedVariantType,
    /// The encoded bytes.
    pub bytes: Vec<u8>,
}

/// Specific encoding variant type (more detailed than EncodingType).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncodedVariantType {
    /// Plain text (no encoding).
    Plain,
    /// Standard Base64 with padding.
    Base64Standard,
    /// Standard Base64 without padding.
    Base64StandardNoPad,
    /// URL-safe Base64 with padding.
    Base64UrlSafe,
    /// URL-safe Base64 without padding.
    Base64UrlSafeNoPad,
    /// URL/percent encoding.
    UrlEncoded,
    /// Double URL encoding.
    DoubleUrlEncoded,
    /// Lowercase hexadecimal.
    HexLower,
    /// Uppercase hexadecimal.
    HexUpper,
    /// HTML decimal entities (&#N;).
    HtmlDecimal,
    /// HTML hex entities (&#xN;).
    HtmlHex,
    /// JSON escape sequences (\\uXXXX).
    JsonEscape,
    /// Unicode escape sequences (\\u{XXXX}).
    UnicodeEscape,
    /// Reversed string.
    Reversed,
    /// ROT13 transformation.
    Rot13,
}

impl From<EncodedVariantType> for EncodingType {
    fn from(variant: EncodedVariantType) -> Self {
        match variant {
            EncodedVariantType::Plain => EncodingType::Plain,
            EncodedVariantType::Base64Standard
            | EncodedVariantType::Base64StandardNoPad
            | EncodedVariantType::Base64UrlSafe
            | EncodedVariantType::Base64UrlSafeNoPad => EncodingType::Base64,
            EncodedVariantType::UrlEncoded | EncodedVariantType::DoubleUrlEncoded => {
                EncodingType::UrlEncoded
            }
            EncodedVariantType::HexLower | EncodedVariantType::HexUpper => EncodingType::Hex,
            EncodedVariantType::HtmlDecimal | EncodedVariantType::HtmlHex => {
                EncodingType::HtmlEntity
            }
            EncodedVariantType::JsonEscape
            | EncodedVariantType::UnicodeEscape
            | EncodedVariantType::Reversed
            | EncodedVariantType::Rot13 => EncodingType::Plain, // These are still "plain-ish"
        }
    }
}

/// Generator for all encoded variants of a secret.
pub struct EncodedGenerator {
    /// Minimum secret length to generate variants for.
    min_length: usize,
}

impl EncodedGenerator {
    /// Create a new encoded generator.
    pub fn new() -> Self {
        Self { min_length: 4 }
    }

    /// Set the minimum secret length for variant generation.
    ///
    /// Secrets shorter than this won't have variants generated
    /// (too many false positives).
    pub fn with_min_length(mut self, min_length: usize) -> Self {
        self.min_length = min_length;
        self
    }

    /// Generate all encoded variants of a secret.
    ///
    /// # Arguments
    ///
    /// * `secret` - The raw secret bytes
    ///
    /// # Returns
    ///
    /// A vector of all encoded variants, including the original.
    pub fn generate_variants(&self, secret: &[u8]) -> Vec<EncodedVariant> {
        if secret.len() < self.min_length {
            // For very short secrets, only return plain to avoid false positives
            return vec![EncodedVariant {
                encoding: EncodedVariantType::Plain,
                bytes: secret.to_vec(),
            }];
        }

        let mut variants = Vec::with_capacity(16);

        // Original (plain)
        variants.push(EncodedVariant {
            encoding: EncodedVariantType::Plain,
            bytes: secret.to_vec(),
        });

        // Base64 standard with padding
        let b64_std = general_purpose::STANDARD.encode(secret);
        variants.push(EncodedVariant {
            encoding: EncodedVariantType::Base64Standard,
            bytes: b64_std.into_bytes(),
        });

        // Base64 standard without padding
        let b64_std_no_pad = general_purpose::STANDARD_NO_PAD.encode(secret);
        if b64_std_no_pad != general_purpose::STANDARD.encode(secret) {
            variants.push(EncodedVariant {
                encoding: EncodedVariantType::Base64StandardNoPad,
                bytes: b64_std_no_pad.into_bytes(),
            });
        }

        // Base64 URL-safe with padding
        let b64_url = general_purpose::URL_SAFE.encode(secret);
        if b64_url.as_bytes() != variants[1].bytes {
            variants.push(EncodedVariant {
                encoding: EncodedVariantType::Base64UrlSafe,
                bytes: b64_url.into_bytes(),
            });
        }

        // Base64 URL-safe without padding
        let b64_url_no_pad = general_purpose::URL_SAFE_NO_PAD.encode(secret);
        variants.push(EncodedVariant {
            encoding: EncodedVariantType::Base64UrlSafeNoPad,
            bytes: b64_url_no_pad.into_bytes(),
        });

        // URL encoding
        if let Ok(s) = std::str::from_utf8(secret) {
            let url_encoded = utf8_percent_encode(s, NON_ALPHANUMERIC).to_string();
            variants.push(EncodedVariant {
                encoding: EncodedVariantType::UrlEncoded,
                bytes: url_encoded.clone().into_bytes(),
            });

            // Double URL encoding
            let double_url = utf8_percent_encode(&url_encoded, NON_ALPHANUMERIC).to_string();
            if double_url != url_encoded {
                variants.push(EncodedVariant {
                    encoding: EncodedVariantType::DoubleUrlEncoded,
                    bytes: double_url.into_bytes(),
                });
            }
        }

        // Hex lowercase
        let hex_lower = hex::encode(secret);
        variants.push(EncodedVariant {
            encoding: EncodedVariantType::HexLower,
            bytes: hex_lower.clone().into_bytes(),
        });

        // Hex uppercase
        let hex_upper = hex::encode_upper(secret);
        variants.push(EncodedVariant {
            encoding: EncodedVariantType::HexUpper,
            bytes: hex_upper.into_bytes(),
        });

        // HTML decimal entities
        let html_decimal = self.encode_html_decimal(secret);
        variants.push(EncodedVariant {
            encoding: EncodedVariantType::HtmlDecimal,
            bytes: html_decimal.into_bytes(),
        });

        // HTML hex entities
        let html_hex = self.encode_html_hex(secret);
        variants.push(EncodedVariant {
            encoding: EncodedVariantType::HtmlHex,
            bytes: html_hex.into_bytes(),
        });

        // JSON escape
        if let Ok(s) = std::str::from_utf8(secret) {
            let json_escaped = self.encode_json_escape(s);
            variants.push(EncodedVariant {
                encoding: EncodedVariantType::JsonEscape,
                bytes: json_escaped.into_bytes(),
            });
        }

        // Unicode escape
        if let Ok(s) = std::str::from_utf8(secret) {
            let unicode_escaped = self.encode_unicode_escape(s);
            variants.push(EncodedVariant {
                encoding: EncodedVariantType::UnicodeEscape,
                bytes: unicode_escaped.into_bytes(),
            });
        }

        // Reversed
        let reversed: Vec<u8> = secret.iter().rev().copied().collect();
        variants.push(EncodedVariant {
            encoding: EncodedVariantType::Reversed,
            bytes: reversed,
        });

        // ROT13 (only for ASCII alphabetic content)
        if let Ok(s) = std::str::from_utf8(secret) {
            if s.chars().all(|c| c.is_ascii()) {
                let rot13 = self.encode_rot13(s);
                // Only add if different from original
                if rot13.as_bytes() != secret {
                    variants.push(EncodedVariant {
                        encoding: EncodedVariantType::Rot13,
                        bytes: rot13.into_bytes(),
                    });
                }
            }
        }

        variants
    }

    /// Encode bytes as HTML decimal entities (&#N;).
    fn encode_html_decimal(&self, data: &[u8]) -> String {
        let mut result = String::with_capacity(data.len() * 5);
        for &byte in data {
            result.push_str(&format!("&#{};", byte));
        }
        result
    }

    /// Encode bytes as HTML hex entities (&#xN;).
    fn encode_html_hex(&self, data: &[u8]) -> String {
        let mut result = String::with_capacity(data.len() * 6);
        for &byte in data {
            result.push_str(&format!("&#x{:02x};", byte));
        }
        result
    }

    /// Encode string as JSON escape sequences.
    fn encode_json_escape(&self, s: &str) -> String {
        let mut result = String::with_capacity(s.len() * 6);
        for c in s.chars() {
            if c.is_ascii() && !c.is_ascii_control() && c != '"' && c != '\\' {
                // Encode even printable ASCII as \uXXXX for detection
                result.push_str(&format!("\\u{:04x}", c as u32));
            } else {
                result.push_str(&format!("\\u{:04x}", c as u32));
            }
        }
        result
    }

    /// Encode string as Unicode escape sequences.
    fn encode_unicode_escape(&self, s: &str) -> String {
        let mut result = String::with_capacity(s.len() * 8);
        for c in s.chars() {
            result.push_str(&format!("\\u{{{:04x}}}", c as u32));
        }
        result
    }

    /// Encode string as ROT13.
    fn encode_rot13(&self, s: &str) -> String {
        s.chars()
            .map(|c| match c {
                'a'..='m' | 'A'..='M' => char::from_u32(c as u32 + 13).unwrap_or(c),
                'n'..='z' | 'N'..='Z' => char::from_u32(c as u32 - 13).unwrap_or(c),
                _ => c,
            })
            .collect()
    }
}

impl Default for EncodedGenerator {
    fn default() -> Self {
        Self::new()
    }
}

/// Pre-computed encoded variants for a secret.
pub struct SecretVariants {
    /// Name of the secret.
    pub secret_name: String,
    /// All encoded variants.
    pub variants: Vec<EncodedVariant>,
}

impl SecretVariants {
    /// Create new secret variants from raw secret bytes.
    pub fn new(secret_name: &str, secret: &[u8]) -> Self {
        let generator = EncodedGenerator::new();
        Self {
            secret_name: secret_name.to_string(),
            variants: generator.generate_variants(secret),
        }
    }

    /// Create with a custom generator.
    pub fn with_generator(secret_name: &str, secret: &[u8], generator: &EncodedGenerator) -> Self {
        Self {
            secret_name: secret_name.to_string(),
            variants: generator.generate_variants(secret),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plain_variant_always_present() {
        let generator = EncodedGenerator::new();
        let variants = generator.generate_variants(b"secret");

        assert!(variants.iter().any(|v| v.encoding == EncodedVariantType::Plain));
        assert_eq!(
            variants.iter().find(|v| v.encoding == EncodedVariantType::Plain).unwrap().bytes,
            b"secret"
        );
    }

    #[test]
    fn test_base64_variants() {
        let generator = EncodedGenerator::new();
        let secret = b"sk_live_abc123";
        let variants = generator.generate_variants(secret);

        // Check base64 standard
        let b64_variant = variants
            .iter()
            .find(|v| v.encoding == EncodedVariantType::Base64Standard)
            .expect("Base64 standard variant should exist");

        let expected = general_purpose::STANDARD.encode(secret);
        assert_eq!(b64_variant.bytes, expected.as_bytes());
    }

    #[test]
    fn test_url_encoding_variants() {
        let generator = EncodedGenerator::new();
        let secret = b"secret&key=value";
        let variants = generator.generate_variants(secret);

        let url_variant = variants
            .iter()
            .find(|v| v.encoding == EncodedVariantType::UrlEncoded)
            .expect("URL encoded variant should exist");

        // Should contain percent-encoded characters
        let url_str = String::from_utf8(url_variant.bytes.clone()).unwrap();
        assert!(url_str.contains("%26")); // & encoded
        assert!(url_str.contains("%3D")); // = encoded
    }

    #[test]
    fn test_hex_variants() {
        let generator = EncodedGenerator::new();
        let secret = b"test1234";
        let variants = generator.generate_variants(secret);

        let hex_lower = variants
            .iter()
            .find(|v| v.encoding == EncodedVariantType::HexLower)
            .expect("Hex lower variant should exist");

        let hex_upper = variants
            .iter()
            .find(|v| v.encoding == EncodedVariantType::HexUpper)
            .expect("Hex upper variant should exist");

        assert_eq!(String::from_utf8(hex_lower.bytes.clone()).unwrap(), "7465737431323334");
        assert_eq!(String::from_utf8(hex_upper.bytes.clone()).unwrap(), "7465737431323334".to_uppercase());
    }

    #[test]
    fn test_html_entity_variants() {
        let generator = EncodedGenerator::new();
        let secret = b"ABC123";
        let variants = generator.generate_variants(secret);

        let html_decimal = variants
            .iter()
            .find(|v| v.encoding == EncodedVariantType::HtmlDecimal)
            .expect("HTML decimal variant should exist");

        let html_str = String::from_utf8(html_decimal.bytes.clone()).unwrap();
        assert!(html_str.contains("&#65;")); // 'A'
        assert!(html_str.contains("&#66;")); // 'B'
        assert!(html_str.contains("&#67;")); // 'C'
    }

    #[test]
    fn test_reversed_variant() {
        let generator = EncodedGenerator::new();
        let secret = b"secret12";
        let variants = generator.generate_variants(secret);

        let reversed = variants
            .iter()
            .find(|v| v.encoding == EncodedVariantType::Reversed)
            .expect("Reversed variant should exist");

        assert_eq!(reversed.bytes, b"21terces");
    }

    #[test]
    fn test_rot13_variant() {
        let generator = EncodedGenerator::new();
        let secret = b"ABCabc123";
        let variants = generator.generate_variants(secret);

        let rot13 = variants
            .iter()
            .find(|v| v.encoding == EncodedVariantType::Rot13)
            .expect("ROT13 variant should exist");

        assert_eq!(String::from_utf8(rot13.bytes.clone()).unwrap(), "NOPnop123");
    }

    #[test]
    fn test_short_secret_only_plain() {
        let generator = EncodedGenerator::new().with_min_length(8);
        let secret = b"abc"; // Too short
        let variants = generator.generate_variants(secret);

        assert_eq!(variants.len(), 1);
        assert_eq!(variants[0].encoding, EncodedVariantType::Plain);
    }

    #[test]
    fn test_variant_count() {
        let generator = EncodedGenerator::new();
        let secret = b"sk_live_abc123XYZ";
        let variants = generator.generate_variants(secret);

        // Should have at least: plain, base64 (4 variants), url (2), hex (2),
        // html (2), json, unicode, reversed, rot13 = 15+ variants
        assert!(variants.len() >= 12, "Expected at least 12 variants, got {}", variants.len());
    }

    #[test]
    fn test_secret_variants_struct() {
        let sv = SecretVariants::new("API_KEY", b"secret_value123");

        assert_eq!(sv.secret_name, "API_KEY");
        assert!(!sv.variants.is_empty());
        assert!(sv.variants.iter().any(|v| v.encoding == EncodedVariantType::Plain));
    }
}
