use foreign_types::{foreign_type, ForeignType};

use crate::ssl::*;

use super::X509Cert;

foreign_type! {
    pub unsafe type X509Store: Sync + Send {
        type CType = X509_STORE;
        fn drop = X509_STORE_free;
    }
}

impl X509Store {
    pub fn add_cert(&self, cert: X509Cert) {
        unsafe {
            X509_STORE_add_cert(self.as_ptr(), cert.as_ptr());
        }
    }

    // TODO: Impl CRL type and add it here
    pub fn add_crl(&self) {
        unsafe {
            X509_STORE_add_crl(self.as_ptr(), std::ptr::null_mut());
        }
    }
}

impl Default for X509Store {
    fn default() -> Self {
        unsafe{Self::from_ptr(X509_STORE_new())}
    }
}
