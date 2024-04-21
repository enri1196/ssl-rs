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

    pub fn get_data(&self) -> &[u8] {
        unsafe fn get_mem_data(b: *mut BIO, pp: *mut *mut std::ffi::c_char) -> std::ffi::c_long {
            BIO_ctrl(b, BIO_CTRL_INFO as i32, 0, pp as *mut std::ffi::c_void)
        }
        unsafe {
            let mut ptr = std::ptr::null_mut();
            let len = get_mem_data(self.as_ptr(), &mut ptr);
            std::slice::from_raw_parts(ptr as *const _ as *const _, len as usize)
        }
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
