use foreign_types::ForeignType;

use crate::{
    error::ErrorStack,
    evp::{DhKey, EvpPkey, Private},
    ssl::*,
};

use super::{EvpCtx, KeyGen};

impl KeyGen<DhKey> for EvpCtx<Private, DhKey> {
    fn init_key_gen(self) -> Self {
        unsafe {
            EVP_PKEY_paramgen_init(self.as_ptr());
            self
        }
    }

    fn set_key_algorithm(self, alg: DhKey) -> Self {
        unsafe {
            let DhKey(_, bits) = alg;
            EVP_PKEY_CTX_set_dsa_paramgen_bits(self.as_ptr(), bits as i32);
            self
        }
    }

    fn generate(self) -> Result<EvpPkey<Private>, ErrorStack> {
        unsafe {
            let m_key = EvpPkey::<Private>::default();
            crate::check_code(EVP_PKEY_paramgen(
                self.as_ptr(),
                m_key.as_ptr() as *mut *mut _,
            ))?;
            Ok(m_key)
        }
    }
}

#[cfg(test)]
mod test {
    use crate::evp::{DhKey, EvpPkey, Private};

    #[test]
    pub fn test_dh() {
        let key = EvpPkey::<Private>::try_from(DhKey::DH_2048_BITS).unwrap();
        println!("{}", key.to_string());
        println!("{}", key.get_public().unwrap().to_string());
        assert_eq!(116, key.id().get_raw());
        assert_eq!(64, key.size());
    }
}
