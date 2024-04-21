use std::fmt::Display;

use foreign_types::{foreign_type, ForeignType, ForeignTypeRef};

use crate::{bio::SslBio, ssl::*};

foreign_type! {
    pub unsafe type X509Name: Sync + Send {
        type CType = X509_NAME;
        fn drop = X509_NAME_free;
        fn clone = X509_NAME_dup;
    }
}

impl X509NameRef {}

impl Display for X509NameRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        unsafe {
            let bio = SslBio::memory();
            X509_NAME_print_ex(bio.as_ptr(), self.as_ptr(), 0, XN_FLAG_RFC2253 as u64);
            write!(f, "{}", std::str::from_utf8(bio.get_data()).unwrap())
        }
    }
}
