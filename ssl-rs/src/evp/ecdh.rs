use foreign_types::ForeignType;
use ssl_sys::*;

use crate::error::ErrorStack;

use super::{evp_ctx::EvpCtx, EvpPkey, Private, Public};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Ecdh(Vec<u8>);

impl Ecdh {
    pub fn new(first_pkey: &EvpPkey<Private>, second_pkey: &EvpPkey<Public>) -> Result<Self, ErrorStack> {
        unsafe {
            let derive_ctx = EvpCtx::<Private>::try_from(first_pkey)?;
            crate::check_code(EVP_PKEY_derive_init(derive_ctx.as_ptr()))?;
            crate::check_code(EVP_PKEY_derive_set_peer(derive_ctx.as_ptr(), second_pkey.as_ptr()))?;
            let mut secret_len: usize = 0;
            crate::check_code(EVP_PKEY_derive(derive_ctx.as_ptr(), std::ptr::null_mut(), &mut secret_len))?;

            let mut secret = Vec::with_capacity(secret_len);
            crate::check_code(EVP_PKEY_derive(derive_ctx.as_ptr(), secret.as_mut_ptr(), &mut secret_len))?;
            
            Ok(Self(secret))
        }
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn to_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for Ecdh {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

#[cfg(test)]
mod test {
    use crate::evp::{ec::{CurveRawNid, EcKey}, EvpPkey, Private};

    use super::Ecdh;

    #[test]
    pub fn test_ecdh() {
        let alice_key: EvpPkey<Private> = EcKey::new_raw_ec(CurveRawNid::X25519).unwrap().into();
        let bob_key: EvpPkey<Private> = EcKey::new_raw_ec(CurveRawNid::X25519).unwrap().into();

        let alice_secret = Ecdh::new(&alice_key, &bob_key.get_public().unwrap()).unwrap();
        let bob_secret = Ecdh::new(&bob_key, &alice_key.get_public().unwrap()).unwrap();

        assert_eq!(alice_secret.len(), bob_secret.len());
        assert_eq!(alice_secret.to_bytes(), bob_secret.to_bytes());
        assert_eq!(alice_secret, bob_secret);
    }
}