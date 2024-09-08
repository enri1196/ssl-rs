mod evp_ctx;
mod evp_props;

use std::fmt::Display;

use crate::{bio::SslBio, error::ErrorStack, ssl::*};

use evp_ctx::ParamsKeyGen;
pub use evp_props::*;
use foreign_types::{foreign_type, ForeignType, ForeignTypeRef};
use num::FromPrimitive;

use self::evp_ctx::{EvpCtx, KeyGen};

foreign_type! {
    pub unsafe type EvpPkey<KT: KeyType> : Send + Sync {
        type CType = EVP_PKEY;
        type PhantomData = KT;
        fn drop = EVP_PKEY_free;
        fn clone = EVP_PKEY_dup;
    }
}

impl<KT: KeyType> EvpPkeyRef<KT> {
    pub fn id(&self) -> EvpId {
        unsafe { EvpId::from_u32(EVP_PKEY_get_id(self.as_ptr()) as u32).unwrap_unchecked() }
    }

    pub fn size(&self) -> i32 {
        unsafe { EVP_PKEY_get_size(self.as_ptr()) }
    }
}

impl EvpPkey<Private> {
    pub fn get_public(&self) -> Result<EvpPkey<Public>, ErrorStack> {
        unsafe {
            let bio = SslBio::memory();
            crate::check_code(PEM_write_bio_PUBKEY(bio.as_ptr(), self.as_ptr()))?;
            let pub_key = crate::check_ptr(PEM_read_bio_PUBKEY(
                bio.as_ptr(),
                std::ptr::null_mut(),
                None,
                std::ptr::null_mut(),
            ))?;

            Ok(EvpPkey::<Public>::from_ptr(pub_key))
        }
    }

    pub fn sign(&self, tbs: &[u8]) -> Result<Vec<u8>, ErrorStack> {
        unsafe {
            let ctx = EVP_PKEY_CTX_new_from_pkey(
                std::ptr::null_mut(),
                self.as_ptr(),
                std::ptr::null_mut(),
            );
            crate::check_code(EVP_PKEY_sign_init(ctx))?;
            let mut siglen = 0;
            crate::check_code(EVP_PKEY_sign(
                ctx,
                std::ptr::null_mut(),
                &mut siglen,
                tbs.as_ptr(),
                tbs.len(),
            ))?;
            let mut sig = Vec::with_capacity(siglen);
            crate::check_code(EVP_PKEY_sign(
                ctx,
                sig.as_mut_ptr(),
                &mut siglen,
                tbs.as_ptr(),
                tbs.len(),
            ))?;
            Ok(sig)
        }
    }
}

impl<KT: KeyType> Default for EvpPkey<KT> {
    fn default() -> Self {
        unsafe { Self::from_ptr(EVP_PKEY_new()) }
    }
}

impl TryFrom<RsaKey> for EvpPkey<Private> {
    type Error = ErrorStack;
    fn try_from(value: RsaKey) -> Result<Self, Self::Error> {
        let RsaKey(evp_id, _) = value;
        EvpCtx::from(evp_id).generate(value)
    }
}

impl TryFrom<RsaParams> for EvpPkey<Private> {
    type Error = ErrorStack;
    fn try_from(value: RsaParams) -> Result<Self, Self::Error> {
        let RsaParams(evp_id, params) = value;
        EvpCtx::from(evp_id).generate_with_params(&params)
    }
}

impl TryFrom<EcKey> for EvpPkey<Private> {
    type Error = ErrorStack;
    fn try_from(value: EcKey) -> Result<Self, Self::Error> {
        let EcKey(evp_id, _) = value;
        EvpCtx::from(evp_id).generate(value)
    }
}

impl TryFrom<EcParams> for EvpPkey<Private> {
    type Error = ErrorStack;
    fn try_from(value: EcParams) -> Result<Self, Self::Error> {
        let EcParams(evp_id, params) = value;
        EvpCtx::from(evp_id).generate_with_params(&params)
    }
}

impl TryFrom<EvpPkey<Private>> for EvpPkey<Public> {
    type Error = ErrorStack;
    fn try_from(value: EvpPkey<Private>) -> Result<Self, Self::Error> {
        value.get_public()
    }
}

impl Display for EvpPkeyRef<Private> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        unsafe {
            let bio = SslBio::memory();
            crate::check_code(PEM_write_bio_PrivateKey_ex(
                bio.as_ptr(),
                self.as_ptr() as *const _,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                0,
                None,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            ))
            .unwrap();
            write!(f, "{}", std::str::from_utf8_unchecked(bio.get_data()))
        }
    }
}

impl Display for EvpPkeyRef<Public> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        unsafe {
            let bio = SslBio::memory();
            crate::check_code(PEM_write_bio_PUBKEY_ex(
                bio.as_ptr(),
                self.as_ptr() as *const _,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            ))
            .unwrap();
            write!(f, "{}", std::str::from_utf8_unchecked(bio.get_data()))
        }
    }
}

#[cfg(test)]
mod test {
    use crate::evp::{EvpPkey, Private, RsaKey, EcKey};

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

    #[test]
    pub fn test_ec() {
        let key = EvpPkey::<Private>::try_from(EcKey::SECP_256K1).unwrap();
        println!("{}", key.to_string());
        println!("{}", key.get_public().unwrap().to_string());
        assert_eq!(408, key.id().get_raw());
        assert_eq!(72, key.size());
    }

    #[test]
    pub fn test_ec_x25519() {
        let key = EvpPkey::<Private>::try_from(EcKey::X25519).unwrap();
        println!("{}", key.to_string());
        println!("{}", key.get_public().unwrap().to_string());
        assert_eq!(1034, key.id().get_raw());
        assert_eq!(32, key.size());
    }

    #[test]
    pub fn test_ec_x448() {
        let key = EvpPkey::<Private>::try_from(EcKey::X448).unwrap();
        println!("{}", key.to_string());
        println!("{}", key.get_public().unwrap().to_string());
        assert_eq!(1035, key.id().get_raw());
        assert_eq!(56, key.size());
    }
}
