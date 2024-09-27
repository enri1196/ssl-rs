use foreign_types::{foreign_type, ForeignType, ForeignTypeRef};

use std::{ffi::CString, fmt::Display};

use crate::{asn1::Asn1IntegerRef, error::ErrorStack, ssl::*};

foreign_type! {
    pub unsafe type BigNum: Sync + Send {
        type CType = BIGNUM;
        fn drop = BN_free;
        fn clone = BN_dup;
    }
}

impl BigNum {
    pub fn new() -> Self {
        unsafe { Self::from_ptr(BN_new()) }
    }

    pub fn secure_new() -> Self {
        unsafe { Self::from_ptr(BN_secure_new()) }
    }
}

impl BigNumRef {
    pub fn is_zero(&self) -> bool {
        unsafe { BN_is_zero(self.as_ptr() as *const _) == 1 }
    }

    pub fn is_one(&self) -> bool {
        unsafe { BN_is_one(self.as_ptr() as *const _) == 1 }
    }

    pub fn is_odd(&self) -> bool {
        unsafe { BN_is_odd(self.as_ptr() as *const _) == 1 }
    }

    pub fn is_negative(&self) -> bool {
        unsafe { BN_is_negative(self.as_ptr() as *const _) == 1 }
    }

    pub fn len(&self) -> usize {
        unsafe { ((BN_num_bits(self.as_ptr()) + 7) / 8) as usize }
    }

    pub fn is_empty(&self) -> bool {
        unsafe { BN_num_bits(self.as_ptr()) == 0 }
    }
}

impl Default for BigNum {
    fn default() -> Self {
        Self::new()
    }
}

impl TryFrom<&[u8]> for BigNum {
    type Error = ErrorStack;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        unsafe {
            let bn = crate::check_ptr(BN_bin2bn(
                value.as_ptr(),
                value.len().try_into().unwrap(),
                std::ptr::null_mut(),
            ))?;
            Ok(Self::from_ptr(bn))
        }
    }
}

impl TryFrom<&Asn1IntegerRef> for BigNum {
    type Error = ErrorStack;

    fn try_from(value: &Asn1IntegerRef) -> Result<Self, Self::Error> {
        unsafe {
            let bn = crate::check_ptr(ASN1_INTEGER_to_BN(value.as_ptr(), std::ptr::null_mut()))?;
            Ok(Self::from_ptr(bn))
        }
    }
}

impl Display for BigNum {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.as_ref().fmt(f)
    }
}

impl Display for &BigNumRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        unsafe {
            let bn = BN_bn2dec(self.as_ptr() as *const _);
            let c_bn = CString::from_raw(bn);
            let s = String::from_utf8(c_bn.into_bytes_with_nul()).map_err(|_| std::fmt::Error)?;
            write!(f, "{s}")
        }
    }
}

impl PartialEq for BigNum {
    fn eq(&self, other: &Self) -> bool {
        self.as_ref().eq(&other.as_ref())
    }
}

impl Eq for BigNum {}

impl PartialEq for &BigNumRef {
    fn eq(&self, other: &Self) -> bool {
        unsafe { BN_cmp(self.as_ptr(), other.as_ptr()) == 0 }
    }
}

impl Eq for &BigNumRef {}

impl PartialOrd for BigNum {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.as_ref().partial_cmp(&other.as_ref())
    }
}

impl PartialOrd for &BigNumRef {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        unsafe {
            match BN_cmp(self.as_ptr(), other.as_ptr()) {
                -1 => Some(std::cmp::Ordering::Less),
                0 => Some(std::cmp::Ordering::Equal),
                1 => Some(std::cmp::Ordering::Greater),
                _ => None,
            }
        }
    }
}
