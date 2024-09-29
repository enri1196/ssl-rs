use std::{ffi::CString, fmt::Display};

use foreign_types::ForeignType;

use crate::{ssl::*, x509::X509Ext};

use super::{ToExt, X509ExtNid};

#[derive(Default, Debug, Clone)]
pub struct AuthorityKeyIdentifier {
    critical: bool,
    keyid: Option<String>,
    authority_cert_issuer: Vec<String>, // Typically, issuer's name or other identifiers
    authority_cert_serial: Option<String>, // Serial number of the issuer's certificate
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
            authority_cert_issuer: Vec::new(),
            authority_cert_serial: None,
        }
    }

    /// Sets the Key Identifier.
    pub fn set_keyid(&mut self, keyid: impl Into<String>) -> &mut Self {
        self.keyid = Some(keyid.into());
        self
    }

    /// Adds an Authority Certificate Issuer.
    ///
    /// This can be the issuer's distinguished name or other identifier.
    pub fn add_authority_cert_issuer(&mut self, issuer: impl Into<String>) -> &mut Self {
        self.authority_cert_issuer.push(issuer.into());
        self
    }

    /// Sets the Authority Certificate Serial Number.
    pub fn set_authority_cert_serial(&mut self, serial: impl Into<String>) -> &mut Self {
        self.authority_cert_serial = Some(serial.into());
        self
    }
}

impl Display for AuthorityKeyIdentifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut parts = Vec::new();

        if self.critical {
            parts.push("critical".to_string());
        }

        if let Some(ref keyid) = self.keyid {
            parts.push(format!("keyid:{}", keyid));
        }

        if !self.authority_cert_issuer.is_empty() {
            let issuers = self
                .authority_cert_issuer
                .iter()
                .map(|issuer| format!("issuer:{}", issuer))
                .collect::<Vec<String>>()
                .join(",");
            parts.push(issuers);
        }

        if let Some(ref serial) = self.authority_cert_serial {
            parts.push(format!("serial:{}", serial));
        }

        let value = parts.join(",");

        write!(f, "{value}")
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

            let value = CString::new(self.to_string())
                .expect("Cstring Nul error");
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
        aki.set_keyid("AB:CD:EF:12:34:56:78:90")
            .add_authority_cert_issuer("CN=Issuer Example,O=Example Org,C=US")
            .set_authority_cert_serial("01:23:45:67:89:AB:CD:EF");

        let aki_ext = aki.to_ext();

        println!("OID: {}", aki_ext.get_oid());
        println!("DATA: {}", aki.to_string());

        assert_eq!("2.5.29.35", aki_ext.get_oid());
    }
}
