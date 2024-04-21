use foreign_types::{foreign_type, ForeignType, ForeignTypeRef};

use crate::{asn1::{Asn1IntegerRef, Asn1TimeRef}, bio::SslBio, error::ErrorStack, evp::{EvpPkeyRef, Public}, ssl::*};

use super::X509NameRef;

foreign_type! {
    pub unsafe type X509Cert: Sync + Send {
        type CType = X509;
        fn drop = X509_free;
        fn clone = X509_dup;
    }
}

impl X509CertRef {
    pub fn serial(&self) -> &Asn1IntegerRef {
        unsafe {
            Asn1IntegerRef::from_ptr(X509_get0_serialNumber(self.as_ptr()) as *mut _)
        }
    }

    pub fn subject(&self) -> &X509NameRef {
        unsafe {
            X509NameRef::from_ptr(X509_get_subject_name(self.as_ptr()))
        }
    }

    pub fn issuer(&self) -> &X509NameRef {
        unsafe {
            X509NameRef::from_ptr(X509_get_issuer_name(self.as_ptr()))
        }
    }

    pub fn not_before(&self) -> &Asn1TimeRef {
        unsafe {
            Asn1TimeRef::from_ptr(X509_get0_notBefore(self.as_ptr()) as *mut _)
        }
    }

    pub fn not_after(&self) -> &Asn1TimeRef {
        unsafe {
            Asn1TimeRef::from_ptr(X509_get0_notAfter(self.as_ptr()) as *mut _)
        }
    }

    pub fn pub_key(&self) -> &EvpPkeyRef<Public> {
        unsafe {
            EvpPkeyRef::<Public>::from_ptr(X509_get0_pubkey(self.as_ptr()))
        }
    }
}

impl TryFrom<&[u8]> for X509Cert {
    type Error = ErrorStack;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        unsafe {
            let bio = SslBio::from(value.as_ref());
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

#[cfg(test)]
mod test {
    use super::X509Cert;

    #[test]
    pub fn test_cert() {
        let cert = include_bytes!("../../google.cer");
        let x509 = X509Cert::try_from(cert.as_ref()).unwrap();
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
        println!("pub_key: {pub_key}");
    }
}
