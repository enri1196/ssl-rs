use std::fmt::Display;

use foreign_types::{foreign_type, ForeignType, ForeignTypeRef};

use crate::{bn::BigNum, ssl::*};

foreign_type! {
    pub unsafe type Integer: Sync + Send {
        type CType = ASN1_INTEGER;
        fn drop = ASN1_INTEGER_free;
        fn clone = ASN1_INTEGER_dup;
    }
}

impl Integer {}

impl From<i64> for Integer {
    fn from(value: i64) -> Self {
        unsafe {
            let ptr = ASN1_INTEGER_new();
            ASN1_INTEGER_set_int64(ptr, value);
            Integer::from_ptr(ptr)
        }
    }
}

impl From<u64> for Integer {
    fn from(value: u64) -> Self {
        unsafe {
            let ptr = ASN1_INTEGER_new();
            ASN1_INTEGER_set_uint64(ptr, value);
            Integer::from_ptr(ptr)
        }
    }
}

impl Display for IntegerRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        unsafe {
            let bn_ptr = crate::check_ptr(ASN1_INTEGER_to_BN(self.as_ptr(), std::ptr::null_mut()))
                .map_err(|_| std::fmt::Error::default())?;
            let bn = BigNum::from_ptr(bn_ptr);
            let bn_str = BN_bn2dec(bn.as_ptr());
            let bn_len = strlen(bn_str);
            let bn = String::from_raw_parts(bn_str, bn_len as usize, bn_len as usize);
            write!(f, "{bn}")
        }
    }
}
