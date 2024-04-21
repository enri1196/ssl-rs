// internal use only
use ssl_sys as ssl;
// exported modules
pub mod asn1;
pub mod bio;
pub mod bn;
pub mod error;
pub mod evp;
pub mod ossl_param;
pub mod x509;

use std::ffi::{c_int, c_long};

#[inline]
fn check_ptr<T>(r: *mut T) -> Result<*mut T, error::ErrorStack> {
    if r.is_null() {
        Err(error::ErrorStack::get())
    } else {
        Ok(r)
    }
}

#[allow(unused)]
#[inline]
fn check_cptr<T>(r: *const T) -> Result<*const T, error::ErrorStack> {
    if r.is_null() {
        Err(error::ErrorStack::get())
    } else {
        Ok(r)
    }
}

#[allow(unused)]
#[inline]
fn check_code(r: c_int) -> Result<c_int, error::ErrorStack> {
    if r <= 0 {
        Err(error::ErrorStack::get())
    } else {
        Ok(r)
    }
}

#[allow(unused)]
#[inline]
fn check_code_n(r: c_int) -> Result<c_int, error::ErrorStack> {
    if r < 0 {
        Err(error::ErrorStack::get())
    } else {
        Ok(r)
    }
}

#[allow(unused)]
#[inline]
fn check_code_l(r: c_long) -> Result<c_long, error::ErrorStack> {
    if r <= 0 {
        Err(error::ErrorStack::get())
    } else {
        Ok(r)
    }
}
