use std::{ffi::CString, fmt::Display};

use foreign_types::ForeignType;

use crate::{error::ErrorStack, ssl::*, x509::X509Ext};

use super::{ToExt, X509ExtNid};

#[derive(Default, Debug, Clone)]
pub struct SubjectKeyIdentifier {
    critical: bool,
    key_id: String,
}

impl SubjectKeyIdentifier {
    /// Creates a new `SubjectKeyIdentifier` instance.
    ///
    /// # Arguments
    ///
    /// * `critical` - Indicates whether the extension is critical.
    pub fn new(critical: bool) -> Self {
        Self {
            critical,
            key_id: String::new(),
        }
    }

    /// Sets the key identifier manually.
    pub fn set_key_id(&mut self, key_id: impl Into<String>) -> &mut Self {
        self.key_id = key_id.into();
        self
    }
}

impl Display for SubjectKeyIdentifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut value = String::with_capacity(70);

        if self.critical {
            value.push_str("critical,");
        }
        value.push_str(&self.key_id);

        write!(f, "{}", value)
    }
}

impl ToExt for SubjectKeyIdentifier {
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
                X509ExtNid::SUBJECT_KEY_IDENTIFIER.nid(),
                value.as_ptr(),
            ))?;
            Ok(X509Ext::from_ptr(ptr))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SubjectKeyIdentifier;
    use crate::x509::extensions::ToExt;

    #[test]
    pub fn test_subject_key_identifier() {
        let mut ski = SubjectKeyIdentifier::new(true);
        ski.set_key_id("D8:D7:3F:99:CC:D7:20:AF:62:31:E2:EA:2C:8C:28:8C:B8:2F:0B:96");

        let ski_ext = ski.to_ext().unwrap();

        println!("OID: {}", ski_ext.get_oid());
        println!("DATA: {}", ski.to_string());

        assert_eq!("2.5.29.14", ski_ext.get_oid());
    }
}
