use foreign_types::{foreign_type, ForeignType};

use crate::{error::ErrorStack, ssl::*};

foreign_type! {
    pub unsafe type X509Req: Sync + Send {
        type CType = X509_REQ;
        fn drop = X509_REQ_free;
        fn clone = X509_REQ_dup;
    }
}

impl TryFrom<&[u8]> for X509Req {
    type Error = ErrorStack;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        unsafe {
            let req_ptr = crate::check_ptr(d2i_X509_REQ(
                std::ptr::null_mut(),
                value.as_ptr() as *mut *const _,
                value.len() as i64))?;
            Ok(Self::from_ptr(req_ptr))
        }
    }
}
