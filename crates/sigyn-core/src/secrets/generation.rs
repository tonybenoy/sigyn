use rand::Rng;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GenerationTemplate {
    Password {
        length: usize,
        charset: PasswordCharset,
    },
    Uuid,
    Hex {
        length: usize,
    },
    Base64 {
        length: usize,
    },
    Alphanumeric {
        length: usize,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordCharset {
    pub uppercase: bool,
    pub lowercase: bool,
    pub digits: bool,
    pub symbols: bool,
    pub custom: Option<String>,
}

impl Default for PasswordCharset {
    fn default() -> Self {
        Self {
            uppercase: true,
            lowercase: true,
            digits: true,
            symbols: true,
            custom: None,
        }
    }
}

impl GenerationTemplate {
    pub fn generate(&self) -> String {
        let mut rng = rand::rngs::OsRng;
        match self {
            GenerationTemplate::Password { length, charset } => {
                let chars = charset.chars();
                (0..*length)
                    .map(|_| {
                        let idx = rng.gen_range(0..chars.len());
                        chars[idx] as char
                    })
                    .collect()
            }
            GenerationTemplate::Uuid => uuid::Uuid::new_v4().to_string(),
            GenerationTemplate::Hex { length } => {
                let bytes: Vec<u8> = (0..(*length).div_ceil(2)).map(|_| rng.gen()).collect();
                let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
                hex[..*length].to_string()
            }
            GenerationTemplate::Base64 { length } => {
                use base64::Engine;
                let byte_len = (*length * 3).div_ceil(4);
                let bytes: Vec<u8> = (0..byte_len).map(|_| rng.gen()).collect();
                let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes);
                encoded[..*length].to_string()
            }
            GenerationTemplate::Alphanumeric { length } => {
                const CHARS: &[u8] =
                    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
                (0..*length)
                    .map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char)
                    .collect()
            }
        }
    }
}

impl PasswordCharset {
    fn chars(&self) -> Vec<u8> {
        let mut chars = Vec::new();
        if self.uppercase {
            chars.extend(b'A'..=b'Z');
        }
        if self.lowercase {
            chars.extend(b'a'..=b'z');
        }
        if self.digits {
            chars.extend(b'0'..=b'9');
        }
        if self.symbols {
            chars.extend(b"!@#$%^&*()-_=+[]{}|;:',.<>?/".iter());
        }
        if let Some(custom) = &self.custom {
            chars.extend(custom.bytes());
        }
        if chars.is_empty() {
            chars.extend(b'a'..=b'z');
        }
        chars
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_generation() {
        let tmpl = GenerationTemplate::Password {
            length: 32,
            charset: PasswordCharset::default(),
        };
        let pwd = tmpl.generate();
        assert_eq!(pwd.len(), 32);
    }

    #[test]
    fn test_uuid_generation() {
        let tmpl = GenerationTemplate::Uuid;
        let id = tmpl.generate();
        assert!(uuid::Uuid::parse_str(&id).is_ok());
    }

    #[test]
    fn test_hex_generation() {
        let tmpl = GenerationTemplate::Hex { length: 16 };
        let hex = tmpl.generate();
        assert_eq!(hex.len(), 16);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
