use foreign_types::{foreign_type, ForeignType};

use crate::ssl::*;

foreign_type! {
    pub unsafe type SslBio: Sync + Send {
        type CType = BIO;
        fn drop = BIO_free;
        fn clone = BIO_dup_chain;
    }
}

impl SslBio {
    pub fn memory() -> Self {
        unsafe { Self::from_ptr(BIO_new(BIO_s_mem())) }
    }
}

impl From<&[u8]> for SslBio {
    fn from(value: &[u8]) -> Self {
        unsafe {
            Self::from_ptr(BIO_new_mem_buf(
                value.as_ptr() as *const _,
                value.len() as i32,
            ))
        }
    }
}
