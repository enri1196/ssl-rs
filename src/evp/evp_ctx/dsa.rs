use foreign_types::ForeignType;

use crate::{
    error::ErrorStack,
    evp::{DsaKey, EvpPkey, Private},
    ssl::*,
};

use super::{EvpCtx, KeyGen};

impl KeyGen<DsaKey> for EvpCtx<Private, DsaKey> {
    fn generate(self, alg: DsaKey) -> Result<EvpPkey<Private>, ErrorStack> {
        unsafe {
            let DsaKey(_, bits) = alg;
            EVP_PKEY_paramgen_init(self.as_ptr());
            EVP_PKEY_CTX_set_dsa_paramgen_bits(self.as_ptr(), bits as i32);
            let param_key = EvpPkey::<Private>::default();
            crate::check_code(EVP_PKEY_paramgen(
                self.as_ptr(),
                param_key.as_ptr() as *mut *mut _,
            ))?;
            let m_key = EvpPkey::<Private>::default();
            let ctx = EvpCtx::<Private, DsaKey>::from(param_key);
            EVP_PKEY_keygen_init(ctx.as_ptr());
            crate::check_code(EVP_PKEY_keygen(
                ctx.as_ptr(),
                &mut m_key.as_ptr() as *mut *mut _,
            ))?;
            Ok(m_key)
        }
    }
}

#[cfg(test)]
mod test {
    use crate::evp::{DsaKey, EvpPkey, Private};

    #[test]
    pub fn test_dsa() {
        let key = EvpPkey::<Private>::try_from(DsaKey::DSA_2048_BITS).unwrap();
        // println!("{}", key.to_string());
        // println!("{}", key.get_public().unwrap().to_string());
        // assert_eq!(116, key.id().get_raw());
        assert_eq!(64, key.size());
    }
}
