use foreign_types::foreign_type;

use crate::ssl::*;

foreign_type! {
    pub unsafe type X509Ext: Sync + Send {
        type CType = X509_EXTENSION;
        fn drop = X509_EXTENSION_free;
        fn clone = X509_EXTENSION_dup;
    }
}

impl X509ExtRef {}
