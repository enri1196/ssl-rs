use std::{ffi::CString, fmt::Display};

use foreign_types::ForeignType;

use crate::{asn1::GeneralName, ssl::*, x509::X509Ext};

use super::{ToExt, X509ExtNid};

#[derive(Default, Debug, Clone)]
pub struct GeneralNames(Vec<GeneralName>);

impl GeneralNames {
    pub fn iter(&self) -> std::slice::Iter<'_, GeneralName> {
        self.0.iter()
    }
}

#[derive(Default, Debug, Clone)]
pub struct AuthorityKeyIdentifier {
    critical: bool,
    keyid: Option<bool>,
    issuer: Option<bool>,
}

impl AuthorityKeyIdentifier {
    /// Creates a new `AuthorityKeyIdentifier` instance.
    ///
    /// # Arguments
    ///
    /// * `critical` - Indicates whether the extension is critical.
    pub fn new(critical: bool) -> Self {
        Self {
            critical,
            keyid: None,
            issuer: None,
        }
    }

    /// Sets the Key Identifier to true
    pub fn set_keyid(&mut self, always: Option<bool>) -> &mut Self {
        self.keyid = always;
        self
    }

    /// Sets Authority Certificate Issuer to true
    ///
    /// This can be the issuer's distinguished name or other identifier.
    pub fn set_issuer(&mut self, always: Option<bool>) -> &mut Self {
        self.issuer = always;
        self
    }
}

impl Display for AuthorityKeyIdentifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut parts: Vec<&str> = Vec::new();

        if self.critical {
            parts.push("critical");
        }

        match self.keyid {
            Some(true) => parts.push("keyid:always"),
            Some(false) => parts.push("keyid"),
            None => {}
        }
        match self.issuer {
            Some(true) => parts.push("issuer:always"),
            Some(false) => parts.push("issuer"),
            None => {}
        }

        let value = parts.join(",");

        write!(f, "{}", value)
    }
}

impl ToExt for AuthorityKeyIdentifier {
    fn to_ext(&self) -> X509Ext {
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

            let value = CString::new(self.to_string()).expect("Cstring Nul error");
            let ext = X509V3_EXT_conf_nid(
                std::ptr::null_mut(),
                ctx,
                X509ExtNid::AUTHORITY_KEY_IDENTIFIER.nid(),
                value.as_ptr(),
            );

            X509Ext::from_ptr(ext)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::AuthorityKeyIdentifier;
    use crate::x509::extensions::ToExt;

    #[test]
    pub fn test_authority_key_identifier() {
        let mut aki = AuthorityKeyIdentifier::new(true);
        aki.set_keyid(Some(true)).set_issuer(Some(false));

        let aki_ext = aki.to_ext();

        println!("DATA: {}", aki.to_string());
        println!("OID: {}", aki_ext.get_oid());

        assert_eq!("2.5.29.35", aki_ext.get_oid());
    }
}
