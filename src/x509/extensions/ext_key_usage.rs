use std::fmt::Display;

use crate::ssl::*;

#[derive(Debug, Clone, Copy, Default)]
#[repr(u32)]
pub enum ExtKeyUsageValue {
    SslServer = XKU_SSL_SERVER,
    SslClient = XKU_SSL_CLIENT,
    Smime = XKU_SMIME,
    CodeSign = XKU_CODE_SIGN,
    OcspSign = XKU_OCSP_SIGN,
    Timestamp = XKU_TIMESTAMP,
    DVCS = XKU_DVCS,
    Anyeku = XKU_ANYEKU,
    #[default]
    Absent = UINT32_MAX,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ExtendedKeyUsage(u32);

impl ExtendedKeyUsage {
    pub fn from_raw(value: u32) -> Option<ExtendedKeyUsage> {
        use ExtKeyUsageValue::*;
        // Define constants for valid key usage flags
        const VALID_FLAGS: u32 = SslServer as u32
            | SslClient as u32
            | Smime as u32
            | CodeSign as u32
            | OcspSign as u32
            | Timestamp as u32
            | DVCS as u32
            | Anyeku as u32;

        // Check if the value contains any invalid flags
        if value & !VALID_FLAGS == 0 {
            Some(ExtendedKeyUsage(value))
        } else {
            None
        }
    }

    pub fn add(mut self, val: ExtKeyUsageValue) -> Self {
        self.0 |= val as u32;
        self
    }
}

impl From<&[ExtKeyUsageValue]> for ExtendedKeyUsage {
    fn from(value: &[ExtKeyUsageValue]) -> Self {
        let mut ku = ExtendedKeyUsage::default();
        for val in value {
            ku.0 |= *val as u32;
        }
        return ku;
    }
}

impl Display for ExtendedKeyUsage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use ExtKeyUsageValue::*;
        let mut ekus = String::new();

        if self.0 == Absent as u32 {
            ekus.push_str("ABSENT");
        } else {
            if self.0 & SslServer as u32 != 0 {
                ekus.push_str("serverAuth,")
            }
            if self.0 & SslClient as u32 != 0 {
                ekus.push_str("clientAuth,")
            }
            if self.0 & Smime as u32 != 0 {
                ekus.push_str("emailProtection,")
            }
            if self.0 & CodeSign as u32 != 0 {
                ekus.push_str("codeSigning,")
            }
            if self.0 & OcspSign as u32 != 0 {
                ekus.push_str("OCSPSigning,")
            }
            if self.0 & Timestamp as u32 != 0 {
                ekus.push_str("timeStamping,")
            }
            if self.0 & DVCS as u32 != 0 {
                ekus.push_str("DVCS,")
            }
            if self.0 & Anyeku as u32 != 0 {
                ekus.push_str("ANYEKU,")
            }
            if !ekus.is_empty() {
                ekus.pop();
            }
        }

        write!(f, "{ekus}")
    }
}
