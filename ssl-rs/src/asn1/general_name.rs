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

    /// Creates a new `GeneralName` of type OtherName.
    // pub fn new_other_name(other_name: &OTHERNAME) -> Self {
    //     unsafe {
    //         let gn = GeneralName::default();
    //         (*gn.as_ptr()).type_ = GenNameType::Othername as i32;
    //         (*gn.as_ptr()).d.otherName = OTHERNAME_dup(other_name);
    //         gn
    //     }
    // }

    /// Creates a new `GeneralName` of type RFC822Name (Email).
    pub fn new_email(email: &Asn1StringRef) -> Self {
        unsafe {
            let gn = GeneralName::default();
            (*gn.as_ptr()).type_ = GenNameType::Email as i32;
            (*gn.as_ptr()).d.rfc822Name = ASN1_STRING_dup(email.as_ptr());
            gn
        }
    }

    /// Creates a new `GeneralName` of type X400Address.
    pub fn new_x400_address(x400: &Asn1StringRef) -> Self {
        unsafe {
            let gn = GeneralName::default();
            (*gn.as_ptr()).type_ = GenNameType::X400 as i32;
            (*gn.as_ptr()).d.x400Address = ASN1_STRING_dup(x400.as_ptr());
            gn
        }
    }

    /// Creates a new `GeneralName` of type EDIPartyName.
    pub fn new_edi_party_name(edi_party: *mut EDIPARTYNAME) -> Self {
        unsafe {
            let gn = GeneralName::default();
            (*gn.as_ptr()).type_ = GenNameType::Ediparty as i32;
            (*gn.as_ptr()).d.ediPartyName = edi_party;
            gn
        }
    }

    /// Creates a new `GeneralName` of type UniformResourceIdentifier (URI).
    pub fn new_uri(uri: &Asn1StringRef) -> Self {
        unsafe {
            let gn = GeneralName::default();
            (*gn.as_ptr()).type_ = GenNameType::Uri as i32;
            (*gn.as_ptr()).d.uniformResourceIdentifier = ASN1_STRING_dup(uri.as_ptr());
            gn
        }
    }

    /// Creates a new `GeneralName` of type RegisteredID.
    pub fn new_registered_id(rid: *mut ASN1_OBJECT) -> Self {
        unsafe {
            let gn = GeneralName::default();
            (*gn.as_ptr()).type_ = GenNameType::Rid as i32;
            (*gn.as_ptr()).d.registeredID = rid;
            gn
        }
    }

    /// Creates a new `GeneralName` of type Other (ASN1_TYPE).
    pub fn new_other(other: *mut ASN1_TYPE) -> Self {
        unsafe {
            let gn = GeneralName::default();
            (*gn.as_ptr()).type_ = GenNameType::Othername as i32;
            (*gn.as_ptr()).d.other = other;
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
    use crate::{
        asn1::Asn1String,
        x509::{X509Entry, X509NameBuilder},
    };

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

    #[test]
    pub fn gen_name_dns() {
        let dns = Asn1String::from("example.com");
        let general_name = GeneralName::new_dns_name(&dns);
        println!("{}", general_name);
    }

    // #[test]
    // pub fn gen_name_ip() {
    //     let ip = Asn1StringRef::from_octets(&[192, 168, 1, 1]).unwrap();
    //     let general_name = GeneralName::new_ip_address(&ip);
    //     println!("{}", general_name);
    // }

    #[test]
    pub fn gen_name_email() {
        let email = Asn1String::from("user@example.com");
        let general_name = GeneralName::new_email(&email);
        println!("{}", general_name);
    }

    #[test]
    pub fn gen_name_uri() {
        let uri = Asn1String::from("https://example.com");
        let general_name = GeneralName::new_uri(&uri);
        println!("{}", general_name);
    }
}
