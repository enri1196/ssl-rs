use foreign_types::ForeignType;

use crate::{
    error::ErrorStack,
    evp::{EcKey, EvpPkey, Private},
    ssl::*,
};

use super::EvpCtx;

impl EvpCtx<Private, EcKey> {
    pub fn generate(value: EcKey) -> Result<EvpPkey<Private>, ErrorStack> {
        unsafe {
            let EcKey(id, nid) = value;
            let ctx = Self::from_ptr(EVP_PKEY_CTX_new_id(
                id.get_raw() as i32,
                std::ptr::null_mut(),
            ));
            let m_key = EvpPkey::default();
            crate::check_code(EVP_PKEY_keygen_init(ctx.as_ptr()))?;
            crate::check_code(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(
                ctx.as_ptr(),
                nid as i32,
            ))?;
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
    use crate::evp::{evp_ctx::EvpCtx, EcKey, Private};

    #[test]
    pub fn test_ec() {
        let key = EvpCtx::<Private, EcKey>::generate(EcKey::SECP_256K1).unwrap();
        println!("{}", key.to_string());
        assert_eq!(408, key.id().get_raw());
        assert_eq!(72, key.size());
    }
}
