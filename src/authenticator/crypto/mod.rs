#[allow(unused)]
pub(crate) mod agility;

use crate::authenticator::protocol::hpke_format::HPKEMode;
use agility::*;
use hpke::aead::Aead;
use hpke::kdf::Kdf;
use hpke::{Kem, OpModeR, OpModeS, PskBundle, Serializable};
use rand::{rngs::StdRng, SeedableRng};

const INFO: &[u8] = b"information";
const AAD: &[u8] = b"information aad";

//协议中没有规定psk_id应该在哪里进行协商，这里只用一个进行处理
static PSK_ID: &[u8; 40] = b"preshared key attempt #5, take 2. action";
static PSK_BYTES: [u8; 512] = [0; 512];
pub fn psk(kdf_alg: KdfAlg) -> AgilePskBundle<'static> {
    AgilePskBundle(PskBundle {
        psk: &PSK_BYTES[..kdf_alg.get_digest_len()],
        psk_id: PSK_ID,
    })
}

pub fn gen_key_pair(kem: u16) -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut csprng = StdRng::from_entropy();
    let kem_alg = KemAlg::try_from_u16(kem)?;
    let pair = agile_gen_keypair(kem_alg, &mut csprng);
    Ok((pair.0.privkey_bytes, pair.1.pubkey_bytes))
}

fn trans_keypair(keypair: &(Vec<u8>, Vec<u8>), kem_alg: KemAlg) -> AgileKeypair {
    AgileKeypair(
        AgilePrivateKey {
            kem_alg,
            privkey_bytes: keypair.0.to_owned(),
        },
        AgilePublicKey {
            kem_alg,
            pubkey_bytes: keypair.1.to_owned(),
        },
    )
}

///加密数据
/// Flag为RFC 9180 Algorithm Identifiers规定的标志的16位形式
pub fn encrypt(
    kem_flag: u16,
    kdf_flag: u16,
    aead_flag: u16,
    data: &[u8],
    pki: &[u8],
    mode: &HPKEMode,
    key_pair: &(Vec<u8>, Vec<u8>),
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut csprng = StdRng::from_entropy();
    let (aead_alg, kdf_alg, kem_alg) = match_algorithm(kem_flag, kdf_flag, aead_flag)?;

    let op_mode_ty = match mode {
        HPKEMode::Base => AgileOpModeSTy::Base,
        HPKEMode::Psk => AgileOpModeSTy::Psk(psk(kdf_alg)),
        HPKEMode::Auth => AgileOpModeSTy::Auth(trans_keypair(key_pair, kem_alg)),
        HPKEMode::AuthPsk => {
            AgileOpModeSTy::AuthPsk(trans_keypair(key_pair, kem_alg), psk(kdf_alg))
        }
    };

    let op_mode_s = AgileOpModeS {
        kem_alg,
        op_mode_ty,
    };
    let pki = AgilePublicKey {
        kem_alg,
        pubkey_bytes: pki.to_vec(),
    };
    let (encapped_key, mut aead_ctx1) = agile_setup_sender(
        aead_alg,
        kdf_alg,
        kem_alg,
        &op_mode_s,
        &pki,
        INFO,
        &mut csprng,
    )?;

    let ciphertext = aead_ctx1.seal(data, AAD)?;
    Ok((ciphertext, encapped_key.encapped_key_bytes))
}

/// 解密数据
/// Flag为RFC 9180 Algorithm Identifiers规定的标志的16位形式
pub fn decrypt(
    kem_flag: u16,
    kdf_flag: u16,
    aead_flag: u16,
    ciphertext: &[u8],
    ski: &[u8],
    pki: &[u8],
    encapsulated_key: &[u8],
    mode: &HPKEMode,
    pke: &Option<Vec<u8>>,
) -> Result<Vec<u8>, String> {
    let (aead_alg, kdf_alg, kem_alg) = match_algorithm(kem_flag, kdf_flag, aead_flag)?;
    let op_mode_ty = match mode {
        HPKEMode::Base => AgileOpModeRTy::Base,
        HPKEMode::Psk => AgileOpModeRTy::Psk(psk(kdf_alg)),
        HPKEMode::Auth => AgileOpModeRTy::Auth(AgilePublicKey {
            kem_alg,
            pubkey_bytes: pke.to_owned().unwrap(),
        }),
        HPKEMode::AuthPsk => AgileOpModeRTy::AuthPsk(
            AgilePublicKey {
                kem_alg,
                pubkey_bytes: pke.to_owned().unwrap(),
            },
            psk(kdf_alg),
        ),
    };
    let op_mode_r = AgileOpModeR {
        kem_alg,
        op_mode_ty,
    };
    let encapped_key = AgileEncappedKey {
        kem_alg,
        encapped_key_bytes: encapsulated_key.to_vec(),
    };
    let recip_keypair = AgileKeypair(
        AgilePrivateKey {
            kem_alg,
            privkey_bytes: ski.to_vec(),
        },
        AgilePublicKey {
            kem_alg,
            pubkey_bytes: pki.to_vec(),
        },
    );
    let mut aead_ctx2 = agile_setup_receiver(
        aead_alg,
        kdf_alg,
        kem_alg,
        &op_mode_r,
        &recip_keypair,
        &encapped_key,
        INFO,
    )?;
    Ok(aead_ctx2.open(&ciphertext, AAD)?)
}

fn match_algorithm(kem: u16, kdf: u16, aead: u16) -> Result<(AeadAlg, KdfAlg, KemAlg), String> {
    let aead_alg = AeadAlg::try_from_u16(aead)?;
    let kem_alg = KemAlg::try_from_u16(kem)?;
    let kdf_alg = KdfAlg::try_from_u16(kdf)?;
    Ok((aead_alg, kdf_alg, kem_alg))
}

pub fn _encrypt_str<AeadTrait: Aead, KdfTrait: Kdf, KemTrait: Kem>(
    data: &[u8],
    pki: &KemTrait::PublicKey,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut csprng = StdRng::from_entropy();
    let (encapsulated_key, mut encryption_context) = hpke::setup_sender::<
        AeadTrait,
        KdfTrait,
        KemTrait,
        _,
    >(&OpModeS::Base, pki, INFO, &mut csprng)
    .map_err(|e| e.to_string())?;
    let ciphertext = encryption_context
        .seal(data, AAD)
        .expect("encryption failed!");
    Ok((ciphertext, encapsulated_key.to_bytes().to_vec()))
}

pub fn _decrypt_str<AeadTrait: Aead, KdfTrait: Kdf, KemTrait: Kem>(
    ciphertext: &[u8],
    ski: &KemTrait::PrivateKey,
    encapsulated_key: &KemTrait::EncappedKey,
) -> Result<Vec<u8>, String> {
    let mut decryption_context = hpke::setup_receiver::<AeadTrait, KdfTrait, KemTrait>(
        &OpModeR::Base,
        ski,
        encapsulated_key,
        INFO,
    )
    .expect("failed to set up receiver!");

    let plaintext = decryption_context
        .open(ciphertext, AAD)
        .expect("invalid ciphertext!");
    Ok(plaintext)
}
