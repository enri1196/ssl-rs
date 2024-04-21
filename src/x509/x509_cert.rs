use foreign_types::{foreign_type, ForeignType, ForeignTypeRef};

use crate::{asn1::IntegerRef, bio::SslBio, error::ErrorStack, evp::{EvpPkeyRef, Public}, ssl::*};

foreign_type! {
    pub unsafe type X509Cert: Sync + Send {
        type CType = X509;
        fn drop = X509_free;
        fn clone = X509_dup;
    }
}

impl X509CertRef {
    pub fn serial(&self) -> &IntegerRef {
        unsafe {
            IntegerRef::from_ptr(X509_get0_serialNumber(self.as_ptr()) as *mut _)
        }
    }

    pub fn pub_key(&self) -> &EvpPkeyRef<Public> {
        unsafe {
            EvpPkeyRef::<Public>::from_ptr(X509_get0_pubkey(self.as_ptr()))
        }
    }
}

impl TryFrom<Vec<u8>> for X509Cert {
    type Error = ErrorStack;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        unsafe {
            let value = value;
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
        let x509 = X509Cert::try_from(cert.to_vec()).unwrap();
        let serial = x509.serial();
        let pub_key = x509.pub_key();
        println!("SERIAL: {serial}");
        println!("pub_key: {}", pub_key.size());
    }
}
