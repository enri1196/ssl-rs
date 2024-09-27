use std::fmt::Display;

use foreign_types::foreign_type;
use strum::AsRefStr;

use crate::ssl::*;

foreign_type! {
    pub unsafe type X509NameEntry: Sync + Send {
        type CType = X509_NAME_ENTRY;
        fn drop = X509_NAME_ENTRY_free;
        fn clone = X509_NAME_ENTRY_dup;
    }
}

#[derive(Clone, Copy, Debug, AsRefStr)]
pub enum X509Entry {
    C,
    CN,
    DC,
    Email,
    GivenName,
    L,
    O,
    OU,
    SN,
    ST,
    Surname,
    UID,
}

impl Display for X509Entry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_ref())
    }
}
