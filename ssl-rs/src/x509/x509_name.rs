use std::{ffi::CString, fmt::Display};

use foreign_types::{foreign_type, ForeignType, ForeignTypeRef};

use crate::{bio::SslBio, ssl::*};

use super::{X509Entry, X509NameEntryRef};

foreign_type! {
    pub unsafe type X509Name: Sync + Send {
        type CType = X509_NAME;
        fn drop = X509_NAME_free;
        fn clone = X509_NAME_dup;
    }
}

impl Default for X509Name {
    fn default() -> Self {
        unsafe { Self::from_ptr(X509_NAME_new()) }
    }
}

impl X509NameRef {
    pub fn entries_len(&self) -> usize {
        unsafe { X509_NAME_entry_count(self.as_ptr()) as usize }
    }

    pub fn get_entry(&self) -> Option<&X509NameEntryRef> {
        unsafe {
            crate::check_ptr(X509_NAME_get_entry(self.as_ptr(), 0))
                .map(|ne| X509NameEntryRef::from_ptr(ne))
                .ok()
        }
    }
}

impl Display for X509NameRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        unsafe {
            let bio = SslBio::memory();
            X509_NAME_print_ex(bio.as_ptr(), self.as_ptr(), 0, XN_FLAG_RFC2253 as u64);
            let s = match bio.get_data() {
                Some(data) => std::str::from_utf8_unchecked(data),
                None => return Err(std::fmt::Error),
            };
            write!(f, "{s}")
        }
    }
}

pub struct X509NameBuilder(X509Name);

impl Default for X509NameBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl X509NameBuilder {
    pub fn new() -> Self {
        Self(X509Name::default())
    }

    pub fn add_entry_txt(self, key: &str, value: &str) -> Self {
        unsafe {
            let c_key = CString::new(key.to_string()).unwrap();
            X509_NAME_add_entry_by_txt(
                self.0.as_ptr(),
                c_key.as_ptr(),
                MBSTRING_ASC as i32,
                value.as_ptr(),
                value.len() as i32,
                -1,
                0,
            );
            self
        }
    }

    pub fn add_entry(self, key: X509Entry, value: &str) -> Self {
        unsafe {
            let c_key = CString::new(key.to_string()).unwrap();
            X509_NAME_add_entry_by_txt(
                self.0.as_ptr(),
                c_key.as_ptr(),
                MBSTRING_ASC as i32,
                value.as_ptr(),
                value.len() as i32,
                -1,
                0,
            );
            self
        }
    }

    pub fn build(self) -> X509Name {
        self.0
    }
}
