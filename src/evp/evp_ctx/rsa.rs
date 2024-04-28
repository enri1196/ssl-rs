use foreign_types::ForeignType;

use crate::{
    error::ErrorStack,
    evp::{EvpPkey, Private, RsaKey},
    ssl::*,
};

use super::{EvpCtx, KeyGen};

impl KeyGen<Private, RsaKey> for EvpCtx<Private, RsaKey> {
    fn generate(value: RsaKey) -> Result<EvpPkey<Private>, ErrorStack> {
        unsafe {
            let RsaKey(id, bits) = value;
            let m_key = EvpPkey::<Private>::default();
            let ctx = Self::from(id);
            crate::check_code(EVP_PKEY_keygen_init(ctx.as_ptr()))?;
            crate::check_code(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.as_ptr(), bits as i32))?;
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
    use crate::evp::{EvpPkey, Private, RsaKey};

    #[test]
    pub fn test_rsa() {
        let key = EvpPkey::<Private>::try_from(RsaKey::RSA_2048_BITS).unwrap();
        println!("{}", key.to_string());
        println!("{}", key.get_public().unwrap().to_string());
        assert_eq!(6, key.id().get_raw());
        assert_eq!(256, key.size());
    }

    #[test]
    pub fn test_rsa_pss() {
        let key = EvpPkey::<Private>::try_from(RsaKey::RSA_PSS_2048_BITS).unwrap();
        println!("{}", key.to_string());
        println!("{}", key.get_public().unwrap().to_string());
        assert_eq!(912, key.id().get_raw());
        assert_eq!(256, key.size());
    }
}
