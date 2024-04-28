use foreign_types::ForeignType;

use crate::{
    error::ErrorStack,
    evp::{DhKey, EvpPkey, Private},
    ssl::*,
};

use super::{EvpCtx, KeyGen};

impl KeyGen<Private, DhKey> for EvpCtx<Private, DhKey> {
    fn generate(value: DhKey) -> Result<EvpPkey<Private>, ErrorStack> {
        unsafe {
            let DhKey(id, bits) = value;
            let m_key = EvpPkey::<Private>::default();
            let ctx = Self::from(id);
            crate::check_code(EVP_PKEY_paramgen_init(ctx.as_ptr()))?;
            crate::check_code(EVP_PKEY_CTX_set_dh_paramgen_prime_len(
                ctx.as_ptr(),
                bits as i32,
            ))?;
            crate::check_code(EVP_PKEY_paramgen(
                ctx.as_ptr(),
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
