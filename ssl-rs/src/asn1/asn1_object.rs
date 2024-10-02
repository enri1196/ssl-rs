use foreign_types::foreign_type;

use crate::ssl::*;

foreign_type! {
    pub unsafe type Asn1Object: Sync + Send {
        type CType = ASN1_OBJECT;
        fn drop = ASN1_OBJECT_free;
    }
}
