use std::{ffi::CString, fmt::Display};

use foreign_types::ForeignType;

use crate::{ssl::*, x509::X509Ext};

use super::{ToExt, X509ExtNid};

#[derive(Default, Debug, Clone)]
pub struct IssuerAlternativeName {
    critical: bool,
    dns_names: Vec<String>,
    ip_addresses: Vec<String>,
    email_addresses: Vec<String>,
    uris: Vec<String>,
}

impl IssuerAlternativeName {
    /// Creates a new `IssuerAlternativeName` instance.
    ///
    /// # Arguments
    ///
    /// * `critical` - Indicates whether the extension is critical.
    pub fn new(critical: bool) -> Self {
        Self {
            critical,
            dns_names: Vec::new(),
            ip_addresses: Vec::new(),
            email_addresses: Vec::new(),
            uris: Vec::new(),
        }
    }

    /// Adds a DNS name to the IAN extension.
    pub fn add_dns_name(&mut self, dns: impl Into<String>) -> &mut Self {
        self.dns_names.push(dns.into());
        self
    }

    /// Adds an IP address to the IAN extension.
    pub fn add_ip_address(&mut self, ip: impl Into<String>) -> &mut Self {
        self.ip_addresses.push(ip.into());
        self
    }

    /// Adds an email address to the IAN extension.
    pub fn add_email_address(&mut self, email: impl Into<String>) -> &mut Self {
        self.email_addresses.push(email.into());
        self
    }

    /// Adds a URI to the IAN extension.
    pub fn add_uri(&mut self, uri: impl Into<String>) -> &mut Self {
        self.uris.push(uri.into());
        self
    }

    // Add more methods for other IAN types as needed
}

impl Display for IssuerAlternativeName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut value = String::new();

        if self.critical {
            value.push_str("critical,");
        }

        let mut ian_entries = Vec::new();

        for dns in &self.dns_names {
            ian_entries.push(format!("DNS:{}", dns));
        }

        for ip in &self.ip_addresses {
            ian_entries.push(format!("IP:{}", ip));
        }

        for email in &self.email_addresses {
            ian_entries.push(format!("email:{}", email));
        }

        for uri in &self.uris {
            ian_entries.push(format!("URI:{}", uri));
        }

        // Join all IAN entries with commas
        value.push_str(&ian_entries.join(","));

        write!(f, "{}", value)
    }
}

impl ToExt for IssuerAlternativeName {
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
                X509ExtNid::ISSUER_ALT_NAME.nid(),
                value.as_ptr(),
            );

            X509Ext::from_ptr(ext)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::IssuerAlternativeName;
    use crate::x509::extensions::ToExt;

    #[test]
    pub fn test_issuer_alternative_name() {
        let mut ian = IssuerAlternativeName::new(true);
        ian.add_dns_name("issuer.example.com")
            .add_dns_name("ca.issuer.example.com")
            .add_ip_address("10.0.0.1")
            .add_email_address("ca-issuer@example.com")
            .add_uri("https://issuer.example.com");

        let ian_ext = ian.to_ext();

        println!("OID: {}", ian_ext.get_oid());
        println!("DATA: {}", ian.to_string());

        assert_eq!("2.5.29.18", ian_ext.get_oid());
    }
}
