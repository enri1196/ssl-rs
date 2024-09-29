mod authority_key_identifier;
mod basic_constraints;
mod ext_key_usage;
mod issuer_alt_name;
mod key_usage;
mod subject_alt_name;
mod subject_key_indentifier;

pub use authority_key_identifier::*;
pub use basic_constraints::*;
pub use ext_key_usage::*;
pub use issuer_alt_name::*;
pub use key_usage::*;
pub use subject_alt_name::*;
pub use subject_key_indentifier::*;

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
        unsafe { std::str::from_utf8_unchecked(SN_basic_constraints.to_bytes()) },
        unsafe { std::str::from_utf8_unchecked(LN_basic_constraints.to_bytes()) },
        NID_basic_constraints as i32,
    );

    pub const KEY_USAGE: X509ExtNid = X509ExtNid(
        unsafe { std::str::from_utf8_unchecked(SN_key_usage.to_bytes()) },
        unsafe { std::str::from_utf8_unchecked(LN_key_usage.to_bytes()) },
        NID_key_usage as i32,
    );

    pub const EXT_KEY_USAGE: X509ExtNid = X509ExtNid(
        unsafe { std::str::from_utf8_unchecked(SN_ext_key_usage.to_bytes()) },
        unsafe { std::str::from_utf8_unchecked(LN_ext_key_usage.to_bytes()) },
        NID_ext_key_usage as i32,
    );

    pub const SUBJECT_ALT_NAME: X509ExtNid = X509ExtNid(
        unsafe { std::str::from_utf8_unchecked(SN_subject_alt_name.to_bytes()) },
        unsafe { std::str::from_utf8_unchecked(LN_subject_alt_name.to_bytes()) },
        NID_subject_alt_name as i32,
    );

    pub const ISSUER_ALT_NAME: X509ExtNid = X509ExtNid(
        unsafe { std::str::from_utf8_unchecked(SN_issuer_alt_name.to_bytes()) },
        unsafe { std::str::from_utf8_unchecked(LN_issuer_alt_name.to_bytes()) },
        NID_issuer_alt_name as i32,
    );

    pub const AUTHORITY_KEY_IDENTIFIER: X509ExtNid = X509ExtNid(
        unsafe { std::str::from_utf8_unchecked(SN_authority_key_identifier.to_bytes()) },
        unsafe { std::str::from_utf8_unchecked(LN_authority_key_identifier.to_bytes()) },
        NID_authority_key_identifier as i32,
    );

    pub const SUBJECT_KEY_IDENTIFIER: X509ExtNid = X509ExtNid(
        unsafe { std::str::from_utf8_unchecked(SN_subject_key_identifier.to_bytes()) },
        unsafe { std::str::from_utf8_unchecked(LN_subject_key_identifier.to_bytes()) },
        NID_subject_key_identifier as i32,
    );

    pub const CERTIFICATE_POLICIES: X509ExtNid = X509ExtNid(
        unsafe { std::str::from_utf8_unchecked(SN_certificate_policies.to_bytes()) },
        unsafe { std::str::from_utf8_unchecked(LN_certificate_policies.to_bytes()) },
        NID_certificate_policies as i32,
    );
}
