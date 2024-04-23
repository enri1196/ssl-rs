use foreign_types::ForeignType;

use crate::{
    error::ErrorStack,
    evp::{DsaKey, EvpPkey, Private},
    ssl::*,
};

use super::EvpCtx;

impl EvpCtx<Private, DsaKey> {
    pub fn generate(value: DsaKey) -> Result<EvpPkey<Private>, ErrorStack> {
        unsafe {
            let DsaKey(id, bits) = value;
            let ctx = Self::from_ptr(EVP_PKEY_CTX_new_id(
                id.get_raw() as i32,
                std::ptr::null_mut(),
            ));
            let m_key = EvpPkey::<Private>::default();
            crate::check_code(EVP_PKEY_paramgen_init(ctx.as_ptr()))?;
            crate::check_code(EVP_PKEY_CTX_set_dsa_paramgen_bits(
                ctx.as_ptr(),
                bits as i32,
            ))?;
            crate::check_code(EVP_PKEY_paramgen(
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
        println!("{}", key.to_string());
        println!("{}", key.get_public().unwrap().to_string());
        assert_eq!(116, key.id().get_raw());
        assert_eq!(64, key.size());
    }
}
