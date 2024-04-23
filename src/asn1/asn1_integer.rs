use std::{ffi::CString, fmt::Display};

use foreign_types::{foreign_type, ForeignType, ForeignTypeRef};

use crate::{
    bn::{BigNum, BigNumRef},
    error::ErrorStack,
    ssl::*,
};

foreign_type! {
    pub unsafe type Asn1Integer: Sync + Send {
        type CType = ASN1_INTEGER;
        fn drop = ASN1_INTEGER_free;
        fn clone = ASN1_INTEGER_dup;
    }
}

impl Asn1Integer {}

impl From<i64> for Asn1Integer {
    fn from(value: i64) -> Self {
        unsafe {
            let ptr = ASN1_INTEGER_new();
            ASN1_INTEGER_set_int64(ptr, value);
            Asn1Integer::from_ptr(ptr)
        }
    }
}

impl From<u64> for Asn1Integer {
    fn from(value: u64) -> Self {
        unsafe {
            let ptr = ASN1_INTEGER_new();
            ASN1_INTEGER_set_uint64(ptr, value);
            Asn1Integer::from_ptr(ptr)
        }
    }
}

impl TryFrom<&BigNumRef> for Asn1Integer {
    type Error = ErrorStack;

    fn try_from(value: &BigNumRef) -> Result<Self, Self::Error> {
        unsafe {
            let bn_ptr =
                crate::check_ptr(BN_to_ASN1_INTEGER(value.as_ptr(), std::ptr::null_mut()))?;
            Ok(Self::from_ptr(bn_ptr))
        }
    }
}

impl Display for Asn1IntegerRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        unsafe {
            let bn = BigNum::try_from(self).unwrap();
            let bn = CString::from_raw(BN_bn2dec(bn.as_ptr()))
                .into_string()
                .unwrap();
            write!(f, "{bn}")
        }
    }
}
