use foreign_types::{foreign_type, ForeignType, ForeignTypeRef};

use crate::{
    asn1::{Asn1IntegerRef, Asn1TimeRef},
    bio::SslBio,
    error::ErrorStack,
    evp::{digest::DigestAlgorithm, EvpPkeyRef, Private, Public},
    ssl::*,
};

use super::{
    extensions::{ExtKeyUsage, KeyUsage, ToExt},
    X509NameRef,
};

foreign_type! {
    pub unsafe type X509Cert: Sync + Send {
        type CType = X509;
        fn drop = X509_free;
        fn clone = X509_dup;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(i64)]
pub enum X509Version {
    V1,
    V2,
    V3
}

impl X509CertRef {
    pub fn serial(&self) -> &Asn1IntegerRef {
        unsafe { Asn1IntegerRef::from_ptr(X509_get0_serialNumber(self.as_ptr()) as *mut _) }
    }

    pub fn subject(&self) -> &X509NameRef {
        unsafe { X509NameRef::from_ptr(X509_get_subject_name(self.as_ptr())) }
    }

    pub fn issuer(&self) -> &X509NameRef {
        unsafe { X509NameRef::from_ptr(X509_get_issuer_name(self.as_ptr())) }
    }

    pub fn not_before(&self) -> &Asn1TimeRef {
        unsafe { Asn1TimeRef::from_ptr(X509_get0_notBefore(self.as_ptr()) as *mut _) }
    }

    pub fn not_after(&self) -> &Asn1TimeRef {
        unsafe { Asn1TimeRef::from_ptr(X509_get0_notAfter(self.as_ptr()) as *mut _) }
    }

    pub fn pub_key(&self) -> &EvpPkeyRef<Public> {
        unsafe { EvpPkeyRef::<Public>::from_ptr(X509_get0_pubkey(self.as_ptr())) }
    }

    pub fn ext_len(&self) -> i32 {
        unsafe { X509_get_ext_count(self.as_ptr()) }
    }

    pub fn get_key_usage(&self) -> Option<KeyUsage> {
        unsafe { KeyUsage::from_raw(X509_get_key_usage(self.as_ptr())) }
    }

    pub fn get_ext_key_usage(&self) -> Option<ExtKeyUsage> {
        unsafe { ExtKeyUsage::from_raw(X509_get_extended_key_usage(self.as_ptr())) }
    }
}

impl TryFrom<&[u8]> for X509Cert {
    type Error = ErrorStack;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        unsafe {
            let bio = SslBio::from(value);
            let x509 = crate::check_ptr(PEM_read_bio_X509(
                bio.as_ptr(),
                std::ptr::null_mut(),
                None,
                std::ptr::null_mut(),
            ))?;
            Ok(X509Cert::from_ptr(x509))
        }
    }
}

pub struct X509CertBuilder {
    x509: X509Cert,
}

impl X509CertBuilder {
    pub fn new() -> Self {
        unsafe {
            Self {
                x509: X509Cert::from_ptr(X509_new()),
            }
        }
    }

    pub fn set_version(self, version: X509Version) -> Self {
        unsafe {
            crate::check_code(X509_set_version(self.x509.as_ptr(), version as i64))
                .expect("Error on set_version");
            self
        }
    }

    pub fn set_serial_number(self, serial: &Asn1IntegerRef) -> Self {
        unsafe {
            crate::check_code(X509_set_serialNumber(self.x509.as_ptr(), serial.as_ptr()))
                .expect("Error on set_serial_number");
            self
        }
    }

    pub fn set_issuer_name(self, name: &X509NameRef) -> Self {
        unsafe {
            crate::check_code(X509_set_issuer_name(self.x509.as_ptr(), name.as_ptr()))
                .expect("Error on set_issuer_name");
            self
        }
    }

    pub fn set_subject_name(self, name: &X509NameRef) -> Self {
        unsafe {
            crate::check_code(X509_set_subject_name(self.x509.as_ptr(), name.as_ptr()))
                .expect("Error on set_subject_name");
            self
        }
    }

    pub fn set_not_before(self, not_before: &Asn1TimeRef) -> Self {
        unsafe {
            crate::check_code(X509_set1_notBefore(self.x509.as_ptr(), not_before.as_ptr()))
                .expect("Error on set_not_before");
            self
        }
    }

    pub fn set_not_after(self, not_after: &Asn1TimeRef) -> Self {
        unsafe {
            crate::check_code(X509_set1_notAfter(self.x509.as_ptr(), not_after.as_ptr()))
                .expect("Error on set_not_after");
            self
        }
    }

    pub fn set_pubkey(self, pkey: &EvpPkeyRef<Public>) -> Self {
        unsafe {
            crate::check_code(X509_set_pubkey(self.x509.as_ptr(), pkey.as_ptr()))
                .expect("Error on set_pubkey");
            self
        }
    }

    pub fn add_extension(self, extension: impl ToExt) -> Self {
        unsafe {
            let ext = extension.to_ext();
            crate::check_code(X509_add_ext(self.x509.as_ptr(), ext.as_ptr(), -1))
                .expect("Error on add_extension");
            self
        }
    }

    pub fn sign(self, pkey: &EvpPkeyRef<Private>, md: DigestAlgorithm) -> X509Cert {
        unsafe {
            crate::check_code(X509_sign(self.x509.as_ptr(), pkey.as_ptr(), md.to_md()))
                .expect("Error on sign");
            self.x509
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{
        asn1::{Asn1Integer, Asn1Time},
        error::ErrorStack,
        evp::{
            digest::DigestAlgorithm,
            rsa::{RsaKey, RsaSize},
            EvpPkey, Private,
        },
        x509::{X509CertBuilder, X509Entry, X509NameBuilder, X509Version},
    };

    use super::X509Cert;

    #[test]
    pub fn test_cert() {
        let cert = include_bytes!("../../../google.cer");
        let x509 = X509Cert::try_from(cert.as_ref()).unwrap();
        let serial = x509.serial();
        let subject = x509.subject();
        let issuer = x509.issuer();
        let not_before = x509.not_before();
        let not_after = x509.not_after();
        let pub_key = x509.pub_key();
        let ku = x509.get_key_usage().map(|v| v.to_string());
        let eku = x509.get_ext_key_usage().map(|v| v.to_string());
        println!("SERIAL: {serial}");
        println!("subject: {subject}");
        println!("issuer: {issuer}");
        println!("not_before: {not_before}");
        println!("not_after: {not_after}");
        println!(
            "not_after: {}",
            not_after.to_date_time().unwrap().to_rfc3339()
        );
        println!("pub_key: {pub_key}");
        println!("Key Usage: {ku:?}");
        println!("Ext Key Usage: {eku:?}");
    }

    #[test]
    pub fn test_cert_builder() -> Result<(), ErrorStack> {
        // Create a serial number
        let serial_number = Asn1Integer::from(1_u64);

        // Build the subject and issuer name
        let name = X509NameBuilder::new()
            .add_entry(X509Entry::CN, "Test CA")
            .build();

        // Create not before and not after times
        let not_before = Asn1Time::now()?;
        let not_after = Asn1Time::from_days(365)?;

        // Generate a key pair
        let pkey: EvpPkey<Private> = RsaKey::new_rsa(RsaSize::Rs2048)?.into();
        let ppkey = pkey.get_public()?;

        // Build the certificate
        let x509 = X509CertBuilder::new()
            .set_version(X509Version::V3)
            .set_serial_number(&serial_number)
            .set_issuer_name(&name)
            .set_subject_name(&name)
            .set_not_before(&not_before)
            .set_not_after(&not_after)
            .set_pubkey(&ppkey)
            .sign(&pkey, DigestAlgorithm::SHA256);

        let serial = x509.serial();
        let subject = x509.subject();
        let issuer = x509.issuer();
        let not_before = x509.not_before();
        let not_after = x509.not_after();
        let pub_key = x509.pub_key();

        println!("SERIAL: {serial}");
        println!("subject: {subject}");
        println!("issuer: {issuer}");
        println!("not_before: {not_before}");
        println!("not_after: {not_after}");
        println!(
            "not_after: {}",
            not_after.to_date_time().unwrap().to_rfc3339()
        );
        println!("pub_key: {pub_key}");

        // Print the certificate or perform assertions
        // println!("Certificate: {}", x509);

        Ok(())
    }
}
