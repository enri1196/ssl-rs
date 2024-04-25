mod basic_constraints;
mod ext_key_usage;
mod key_usage;

pub use basic_constraints::*;
pub use key_usage::*;
pub use ext_key_usage::*;

use super::X509Ext;
use crate::ssl::*;

pub trait ToExt {
    fn to_ext(&self) -> X509Ext;
}

pub struct X509ExtNid(&'static str, &'static str, i32);

impl X509ExtNid {
    pub fn short_name(&self) -> &str {
        self.0
    }

    pub fn long_name(&self) -> &str {
        self.1
    }

    pub fn nid(&self) -> i32 {
        self.2
    }

    pub const BASIC_CONSTRAINTS: X509ExtNid = X509ExtNid(
        unsafe { std::str::from_utf8_unchecked(SN_basic_constraints) },
        unsafe { std::str::from_utf8_unchecked(LN_basic_constraints) },
        NID_basic_constraints as i32,
    );
}
