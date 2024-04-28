// TODO: Fix key generation for DSA and DH
// mod dh;
// mod dsa;
mod ec;
mod rsa;

use foreign_types::{foreign_type, ForeignType};

use crate::{error::ErrorStack, ssl::*};

use super::{EvpId, EvpPkey, KeyAlgorithm, KeyType, Private};

foreign_type! {
    pub unsafe type EvpCtx<KT: KeyType, KA: KeyAlgorithm> {
        type CType = EVP_PKEY_CTX;
        type PhantomData = (KT, KA);
        fn drop = EVP_PKEY_CTX_free;
    }
}

impl<KT: KeyType, KA: KeyAlgorithm> EvpCtx<KT, KA> {}

impl<KT: KeyType, KA: KeyAlgorithm> From<EvpId> for EvpCtx<KT, KA> {
    fn from(value: EvpId) -> Self {
        unsafe {
            Self::from_ptr(EVP_PKEY_CTX_new_id(
                value.get_raw() as i32,
                std::ptr::null_mut(),
            ))
        }
    }
}

pub trait KeyGen<KA: KeyAlgorithm> {
    fn init_key_gen(self) -> Self;
    fn set_key_algorithm(self, alg: KA) -> Self;
    fn generate(self) -> Result<EvpPkey<Private>, ErrorStack>;
}
