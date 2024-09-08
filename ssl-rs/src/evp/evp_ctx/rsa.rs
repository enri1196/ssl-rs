use foreign_types::{ForeignType, ForeignTypeRef};

use crate::{
    error::ErrorStack, evp::{EvpPkey, Private, RsaKey}, ossl_param::OsslParamRef, ssl::*
};

use super::{EvpCtx, KeyGen, ParamsKeyGen};

impl KeyGen<RsaKey> for EvpCtx<Private, RsaKey> {
    fn generate(self, alg: RsaKey) -> Result<EvpPkey<Private>, ErrorStack> {
        unsafe {
            let RsaKey(_, bits) = alg;
            let m_key = EvpPkey::<Private>::default();
            EVP_PKEY_keygen_init(self.as_ptr());
            EVP_PKEY_CTX_set_rsa_keygen_bits(self.as_ptr(), bits as i32);

            crate::check_code(EVP_PKEY_keygen(
                self.as_ptr(),
                &mut m_key.as_ptr() as *mut *mut _,
            ))?;
            Ok(m_key)
        }
    }
}

impl ParamsKeyGen<RsaKey> for EvpCtx<Private, RsaKey> {
    fn generate_with_params(self, params: &OsslParamRef) -> Result<EvpPkey<Private>, ErrorStack> {
        unsafe {
            let ctx_key = EvpPkey::<Private>::default();
            EVP_PKEY_paramgen_init(self.as_ptr());
            EVP_PKEY_CTX_set_params(self.as_ptr(), params.as_ptr() as *const _);
            crate::check_code(EVP_PKEY_generate(
                self.as_ptr(),
                &mut ctx_key.as_ptr() as *mut *mut _
            ))?;
            let m_key = EvpPkey::<Private>::default();
            let new_ctx = EvpCtx::<Private, RsaKey>::from(ctx_key);
            EVP_PKEY_keygen_init(new_ctx.as_ptr());
            crate::check_code(EVP_PKEY_keygen(
                new_ctx.as_ptr(),
                &mut m_key.as_ptr() as *mut *mut _,
            ))?;
            Ok(m_key)
        }
    }
}
