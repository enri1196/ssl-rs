use foreign_types::{foreign_type, ForeignTypeRef};

use crate::ssl::*;

foreign_type! {
    pub unsafe type X509Ext: Sync + Send {
        type CType = X509_EXTENSION;
        fn drop = X509_EXTENSION_free;
        fn clone = X509_EXTENSION_dup;
    }
}

impl X509ExtRef {
    pub fn get_oid(&self) -> String {
        unsafe {
            let oid = X509_EXTENSION_get_object(self.as_ptr());
            let mut buf = vec![0u8; 50];
            let len = OBJ_obj2txt(buf.as_mut_ptr() as *mut i8, 50, oid, 1);
            buf.resize(len as usize, 0);
            String::from_utf8_unchecked(buf)
        }
    }
}
