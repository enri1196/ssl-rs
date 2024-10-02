use foreign_types::foreign_type;

use crate::ssl::*;

foreign_type! {
    pub unsafe type X509Alg: Sync + Send {
        type CType = X509_ALGOR;
        fn drop = X509_ALGOR_free;
        fn clone = X509_ALGOR_dup;
    }
}
