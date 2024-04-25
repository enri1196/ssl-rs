use std::fmt::Display;

use crate::ssl::*;

use super::ToExt;

#[derive(Debug, Clone, Copy, Default)]
#[repr(u32)]
pub enum KeyUsageValue {
    DigitalSignature = KU_DIGITAL_SIGNATURE,
    NonRepudiation = KU_NON_REPUDIATION,
    KeyEncipherment = KU_KEY_ENCIPHERMENT,
    DataEncipherment = KU_DATA_ENCIPHERMENT,
    KeyAgreement = KU_KEY_AGREEMENT,
    KeyCertSign = KU_KEY_CERT_SIGN,
    CrlSign = KU_CRL_SIGN,
    EncipherOnly = KU_ENCIPHER_ONLY,
    DecipherOnly = KU_DECIPHER_ONLY,
    #[default]
    Absent = UINT32_MAX,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct KeyUsage(u32);

impl KeyUsage {
    pub fn from_raw(value: u32) -> Option<KeyUsage> {
        use KeyUsageValue::*;
        // Define constants for valid key usage flags
        const VALID_FLAGS: u32 = DigitalSignature as u32
            | NonRepudiation as u32
            | KeyEncipherment as u32
            | DataEncipherment as u32
            | KeyAgreement as u32
            | KeyCertSign as u32
            | CrlSign as u32
            | EncipherOnly as u32
            | DecipherOnly as u32;

        // Check if the value contains any invalid flags
        if value & !VALID_FLAGS == 0 {
            Some(KeyUsage(value))
        } else {
            None
        }
    }

    pub fn add(mut self, val: KeyUsageValue) -> Self {
        self.0 |= val as u32;
        self
    }
}

impl From<&[KeyUsageValue]> for KeyUsage {
    fn from(value: &[KeyUsageValue]) -> Self {
        let mut ku = KeyUsage::default();
        for val in value {
          ku.0 |= *val as u32;
        }
        return ku;
    }
}

impl ToExt for KeyUsage {
    fn to_ext(&self) -> crate::x509::X509Ext {
        todo!()
    }
}

impl Display for KeyUsage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use KeyUsageValue::*;
        let mut kus = String::new();

        if self.0 == Absent as u32 {
            kus.push_str("ABSENT");
        } else {
            if self.0 & DigitalSignature as u32 != 0 {
                kus.push_str("digitalSignature,");
            }
            if self.0 & NonRepudiation as u32 != 0 {
                kus.push_str("nonRepudiation,");
            }
            if self.0 & KeyEncipherment as u32 != 0 {
                kus.push_str("keyEncipherment,");
            }
            if self.0 & DataEncipherment as u32 != 0 {
                kus.push_str("dataEncipherment,");
            }
            if self.0 & KeyAgreement as u32 != 0 {
                kus.push_str("keyAgreement,");
            }
            if self.0 & KeyCertSign as u32 != 0 {
                kus.push_str("keyCertSign,");
            }
            if self.0 & CrlSign as u32 != 0 {
                kus.push_str("cRLSign,");
            }
            if self.0 & EncipherOnly as u32 != 0 {
                kus.push_str("encipherOnly,");
            }
            if self.0 & DecipherOnly as u32 != 0 {
                kus.push_str("decipherOnly,");
            }
            if !kus.is_empty() {
                kus.pop(); // Remove the trailing comma
            }
        }

        write!(f, "{kus}")
    }
}