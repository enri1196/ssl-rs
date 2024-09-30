use std::fmt::{Debug, Display};

use foreign_types::{foreign_type, ForeignType, ForeignTypeRef};

use crate::{bio::SslBio, ssl::*, x509::X509NameRef};

use super::Asn1StringRef;

#[derive(Debug, Clone, Copy)]
#[repr(u32)]
pub enum GenNameType {
    Othername = GEN_OTHERNAME,
    Email = GEN_EMAIL,
    Dns = GEN_DNS,
    X400 = GEN_X400,
    Dirname = GEN_DIRNAME,
    Ediparty = GEN_EDIPARTY,
    Uri = GEN_URI,
    Ipadd = GEN_IPADD,
    Rid = GEN_RID,
}

foreign_type! {
    pub unsafe type GeneralName: Sync + Send {
        type CType = GENERAL_NAME;
        fn drop = GENERAL_NAME_free;
        fn clone = GENERAL_NAME_dup;
    }
}

impl GeneralName {
    pub fn new() -> Self {
        unsafe { Self::from_ptr(GENERAL_NAME_new()) }
    }

    /// Creates a new `GeneralName` of type DirectoryName.
    pub fn new_directory_name(dir_name: &X509NameRef) -> Self {
        unsafe {
            let gn = GeneralName::default();
            (*gn.as_ptr()).type_ = GenNameType::Dirname as i32;
            (*gn.as_ptr()).d.directoryName = X509_NAME_dup(dir_name.as_ptr());
            gn
        }
    }

    /// Creates a new `GeneralName` of type DNSName.
    pub fn new_dns_name(dns: &Asn1StringRef) -> Self {
        unsafe {
            let gn = GeneralName::default();
            (*gn.as_ptr()).type_ = GenNameType::Dns as i32;
            (*gn.as_ptr()).d.dNSName = ASN1_STRING_dup(dns.as_ptr());
            gn
        }
    }

    /// Creates a new `GeneralName` of type IPAddress.
    pub fn new_ip_address(ip: &Asn1StringRef) -> Self {
        unsafe {
            let gn = GeneralName::default();
            (*gn.as_ptr()).type_ = GenNameType::Ipadd as i32;
            (*gn.as_ptr()).d.iPAddress = ASN1_STRING_dup(ip.as_ptr());
            gn
        }
    }
}

impl Default for GeneralName {
    fn default() -> Self {
        Self::new()
    }
}

impl Display for GeneralName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        unsafe {
            let bio = SslBio::memory();
            crate::check_code(GENERAL_NAME_print(bio.as_ptr(), self.as_ptr()))
                .map_err(|_| std::fmt::Error)?;
            write!(
                f,
                "{}",
                std::str::from_utf8_unchecked(bio.get_data().unwrap())
            )
        }
    }
}

impl Debug for GeneralName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

#[cfg(test)]
mod test {
    use crate::x509::{X509Entry, X509NameBuilder};

    use super::*;

    #[test]
    pub fn gen_name_string() {
        let dir_name = X509NameBuilder::new()
            .add_entry(X509Entry::CN, "issuer example")
            .add_entry(X509Entry::O, "My Org")
            .add_entry(X509Entry::C, "US")
            .build();
        let general_name = GeneralName::new_directory_name(&dir_name);

        println!("{}", general_name);
    }
}
