mod ec;
mod rsa;
mod dsa;
mod dh;

use foreign_types::foreign_type;

use crate::ssl::*;

use super::{KeyAlgorithm, KeyType};

foreign_type! {
    pub unsafe type EvpCtx<KT: KeyType, KA: KeyAlgorithm> {
        type CType = EVP_PKEY_CTX;
        type PhantomData = (KT, KA);
        fn drop = EVP_PKEY_CTX_free;
    }
}

impl<KT: KeyType, KA: KeyAlgorithm> EvpCtx<KT, KA> {}
