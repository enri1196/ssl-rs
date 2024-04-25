use std::fmt::Display;

use foreign_types::ForeignType;

use crate::{ssl::*, x509::X509Ext};

use super::{ToExt, X509ExtNid};

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
pub struct ExtKeyUsage(u32);

impl ExtKeyUsage {
    pub fn from_raw(value: u32) -> Option<Self> {
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
            Some(Self(value))
        } else {
            None
        }
    }

    pub fn add(mut self, val: ExtKeyUsageValue) -> Self {
        self.0 |= val as u32;
        self
    }
}

impl From<&[ExtKeyUsageValue]> for ExtKeyUsage {
    fn from(value: &[ExtKeyUsageValue]) -> Self {
        let mut ku = ExtKeyUsage::default();
        for val in value {
            ku.0 |= *val as u32;
        }
        return ku;
    }
}

impl ToExt for ExtKeyUsage {
    fn to_ext(&self) -> crate::x509::X509Ext {
        unsafe {
            let ctx = std::ptr::null_mut();
            X509V3_set_ctx(
                ctx,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                0,
            );

            X509Ext::from_ptr(X509V3_EXT_conf_nid(
                std::ptr::null_mut(),
                ctx,
                X509ExtNid::EXT_KEY_USAGE.nid(),
                self.to_string().as_ptr(),
            ))
        }
    }
}

impl Display for ExtKeyUsage {
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
