mod evp_ctx;
// mod ec;
pub mod rsa;

use num_derive::FromPrimitive;
use std::fmt::Display;

use crate::{bio::SslBio, error::ErrorStack, ossl_param::OsslParamRef, ssl::*};

use foreign_types::{foreign_type, ForeignType, ForeignTypeRef};
use num::FromPrimitive;

use self::evp_ctx::EvpCtx;

pub struct Private;
pub struct Public;

pub trait KeyType {}
impl KeyType for Private {}
impl KeyType for Public {}

pub trait KeyAlgorithm {}

#[derive(Clone, Copy, Debug, PartialEq, FromPrimitive)]
#[repr(u32)]
pub enum EvpId {
    RsaId = EVP_PKEY_RSA,
    RsaPssId = EVP_PKEY_RSA_PSS,
    EcId = EVP_PKEY_EC,
    X25519Id = EVP_PKEY_X25519,
    X448Id = EVP_PKEY_X448,
    Ed25519Id = EVP_PKEY_ED25519,
    Ed448Id = EVP_PKEY_ED448,
}

impl EvpId {
    pub fn get_raw(&self) -> u32 {
        *self as u32
    }
}

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
            let ctx = EvpCtx::<Private>::try_from(self)?;
            crate::check_code(EVP_PKEY_sign_init(ctx.as_ptr()))?;
            let mut siglen = 0;
            crate::check_code(EVP_PKEY_sign(
                ctx.as_ptr(),
                std::ptr::null_mut(),
                &mut siglen,
                tbs.as_ptr(),
                tbs.len(),
            ))?;
            let mut sig = Vec::with_capacity(siglen);
            crate::check_code(EVP_PKEY_sign(
                ctx.as_ptr(),
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

impl TryFrom<(EvpCtx<Private>, &OsslParamRef)> for EvpPkey<Private> {
    type Error = ErrorStack;

    fn try_from((ctx, params): (EvpCtx<Private>, &OsslParamRef)) -> Result<Self, Self::Error> {
        unsafe {
            let m_key = EvpPkey::<Private>::default();
            crate::check_code(EVP_PKEY_keygen_init(ctx.as_ptr()))?;
            crate::check_code(EVP_PKEY_CTX_set_params(
                ctx.as_ptr(),
                params.as_ptr() as *const _,
            ))?;
            EVP_PKEY_generate(ctx.as_ptr(), &mut m_key.as_ptr() as *mut *mut _);
            Ok(m_key)
        }
    }
}

// impl TryFrom<RsaKey> for EvpPkey<Private> {
//     type Error = ErrorStack;
//     fn try_from(value: RsaKey) -> Result<Self, Self::Error> {
//         let RsaKey(evp_id, _) = value;
//         EvpCtx::try_from(evp_id)?.generate(value)
//     }
// }

// impl TryFrom<RsaParams> for EvpPkey<Private> {
//     type Error = ErrorStack;
//     fn try_from(value: RsaParams) -> Result<Self, Self::Error> {
//         let RsaParams(evp_id, params) = value;
//         let ctx = EvpCtx::<Private>::try_from(evp_id)?;
//         ParamsKeyGen::<RsaKey>::generate_with_params(ctx, &params)
//     }
// }

// impl TryFrom<EcKey> for EvpPkey<Private> {
//     type Error = ErrorStack;
//     fn try_from(value: EcKey) -> Result<Self, Self::Error> {
//         let EcKey(evp_id, _) = value;
//         EvpCtx::try_from(evp_id)?.generate(value)
//     }
// }

// impl TryFrom<EcParams> for EvpPkey<Private> {
//     type Error = ErrorStack;
//     fn try_from(value: EcParams) -> Result<Self, Self::Error> {
//         let EcParams(evp_id, params) = value;
//         let ctx = EvpCtx::<Private>::try_from(evp_id)?;
//         ParamsKeyGen::<EcKey>::generate_with_params(ctx, &params)
//     }
// }

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
    // use crate::{
    //     evp::{EvpPkey, Private},
    //     ossl_param::OsslParamBld,
    // };

    use crate::evp::rsa::{RsaKey, RsaSize};

    #[test]
    pub fn test_rsa() {
        let key = RsaKey::new_rsa(RsaSize::Rs2048).unwrap();
        println!("{}", key.to_string());
        println!("{}", key.get_public().unwrap().to_string());
        // assert_eq!(6, key.id().get_raw());
        // assert_eq!(256, key.size());
    }

    // #[test]
    // pub fn test_rsa_params() {
    //     let params = OsslParamBld::new().push_u32("bits", 2048).build();
    //     let rsa_params = RsaParams::new_rsa(params);
    //     let key = EvpPkey::<Private>::try_from(rsa_params).unwrap();
    //     println!("{}", key.to_string());
    //     println!("{}", key.get_public().unwrap().to_string());
    //     assert_eq!(6, key.id().get_raw());
    //     assert_eq!(256, key.size());
    // }

    // #[test]
    // pub fn test_rsa_pss() {
    //     let key = EvpPkey::<Private>::try_from(RsaKey::new_rsa_pss(RsaSize::Rs4096)).unwrap();
    //     println!("{}", key.to_string());
    //     println!("{}", key.get_public().unwrap().to_string());
    //     assert_eq!(912, key.id().get_raw());
    //     assert_eq!(256, key.size());
    // }

    // #[test]
    // pub fn test_ec() {
    //     let key = EvpPkey::<Private>::try_from(EcKey::SECP_256K1).unwrap();
    //     println!("{}", key.to_string());
    //     println!("{}", key.get_public().unwrap().to_string());
    //     assert_eq!(408, key.id().get_raw());
    //     assert_eq!(72, key.size());
    // }

    // #[test]
    // pub fn test_ec_x25519() {
    //     let key = EvpPkey::<Private>::try_from(EcKey::X25519).unwrap();
    //     println!("{}", key.to_string());
    //     println!("{}", key.get_public().unwrap().to_string());
    //     assert_eq!(1034, key.id().get_raw());
    //     assert_eq!(32, key.size());
    // }

    // #[test]
    // pub fn test_ec_x448() {
    //     let key = EvpPkey::<Private>::try_from(EcKey::X448).unwrap();
    //     println!("{}", key.to_string());
    //     println!("{}", key.get_public().unwrap().to_string());
    //     assert_eq!(1035, key.id().get_raw());
    //     assert_eq!(56, key.size());
    // }
}
