use foreign_types::foreign_type;

use crate::ssl::*;

foreign_type! {
    pub unsafe type X509NameEntry: Sync + Send {
        type CType = X509_NAME_ENTRY;
        fn drop = X509_NAME_ENTRY_free;
        fn clone = X509_NAME_ENTRY_dup;
    }
}

pub enum X509Entries {
    C,
    CN,
    O,
    OU,
}
