use foreign_types::{foreign_type, ForeignType};

use crate::{error::ErrorStack, ssl::*};

foreign_type! {
    pub unsafe type TsReq: Sync + Send {
        type CType = TS_REQ;
        fn drop = TS_REQ_free;
        fn clone = TS_REQ_dup;
    }
}

impl TryFrom<&[u8]> for TsReq {
    type Error = ErrorStack;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        unsafe {
            let ptr = crate::check_ptr(d2i_TS_REQ(
                std::ptr::null_mut(),
                value.as_ptr() as *mut *const _,
                value.len() as i64,
            ))?;
            Ok(Self::from_ptr(ptr))
        }
    }
}
