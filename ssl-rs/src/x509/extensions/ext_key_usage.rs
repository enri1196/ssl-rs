use std::{
    ffi::CString,
    fmt::Display,
    ops::{BitOr, BitOrAssign},
};

use foreign_types::ForeignType;

use crate::{error::ErrorStack, ssl::*, x509::X509Ext};

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
    Absent = u32::MAX,
}

impl BitOr<ExtKeyUsageValue> for ExtKeyUsageValue {
    type Output = u32;

    fn bitor(self, rhs: ExtKeyUsageValue) -> Self::Output {
        self as u32 | rhs as u32
    }
}

impl BitOr<ExtKeyUsageValue> for u32 {
    type Output = u32;

    fn bitor(self, rhs: ExtKeyUsageValue) -> Self::Output {
        self | rhs as u32
    }
}

impl BitOrAssign<ExtKeyUsageValue> for u32 {
    fn bitor_assign(&mut self, rhs: ExtKeyUsageValue) {
        *self |= rhs as u32
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ExtKeyUsage(u32);

impl ExtKeyUsage {
    pub fn from_raw(value: u32) -> Option<Self> {
        use ExtKeyUsageValue::*;
        let valid_flags: u32 =
            SslServer | SslClient | Smime | CodeSign | OcspSign | Timestamp | DVCS | Anyeku;

        if value & !valid_flags == 0 {
            Some(Self(value))
        } else {
            None
        }
    }

    pub fn append(mut self, val: ExtKeyUsageValue) -> Self {
        self.0 |= val;
        self
    }
}

impl From<&[ExtKeyUsageValue]> for ExtKeyUsage {
    fn from(value: &[ExtKeyUsageValue]) -> Self {
        let mut ku = ExtKeyUsage::default();
        for val in value {
            ku.0 |= *val as u32;
        }
        ku
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

impl ToExt for ExtKeyUsage {
    fn to_ext(&self) -> Result<X509Ext, ErrorStack> {
        unsafe {
            let mut ctx = std::mem::zeroed::<v3_ext_ctx>();
            X509V3_set_ctx(
                &mut ctx,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                0,
            );

            let value = CString::new(self.to_string()).expect("Cstring Nul error");
            let ptr = crate::check_ptr(X509V3_EXT_conf_nid(
                std::ptr::null_mut(),
                &mut ctx,
                X509ExtNid::EXT_KEY_USAGE.nid(),
                value.as_ptr(),
            ))?;
            Ok(X509Ext::from_ptr(ptr))
        }
    }
}

#[cfg(test)]
mod test {
    use crate::x509::extensions::ToExt;

    use super::{ExtKeyUsage, ExtKeyUsageValue::*};

    #[test]
    pub fn key_usage_test() {
        let ku = ExtKeyUsage::from_raw(SslClient | CodeSign);
        let ku_ext = ku.unwrap().to_ext().unwrap();
        println!("OID: {}", ku_ext.get_oid());
        println!("DATA: {}", ku.unwrap().to_string());
        assert_eq!("2.5.29.37", ku_ext.get_oid());
    }
}
