#[allow(unused)]
mod agility;

use agility::*;
use hpke::aead::Aead;
use hpke::kdf::Kdf;
use hpke::{Kem, OpModeR, OpModeS, Serializable};
use rand::{rngs::StdRng, SeedableRng};

const INFO: &[u8] = b"information";
const AAD: &[u8] = b"information aad";

pub fn gen_key_pair(kem: u16) -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut csprng = StdRng::from_entropy();
    let kem_alg = KemAlg::try_from_u16(kem)?;
    let pair = agile_gen_keypair(kem_alg, &mut csprng);
    Ok((pair.0.privkey_bytes, pair.1.pubkey_bytes))
}

///加密数据
/// Flag为RFC 9180 Algorithm Identifiers规定的标志的16位形式
pub fn encrypt(
    kem_flag: u16,
    kdf_flag: u16,
    aead_flag: u16,
    data: &[u8],
    pki: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut csprng = StdRng::from_entropy();
    let (aead_alg, kdf_alg, kem_alg) = match_algorithm(kem_flag, kdf_flag, aead_flag)?;
    let op_mode_s = AgileOpModeS {
        kem_alg,
        op_mode_ty: AgileOpModeSTy::Base,
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
) -> Result<Vec<u8>, String> {
    let (aead_alg, kdf_alg, kem_alg) = match_algorithm(kem_flag, kdf_flag, aead_flag)?;
    let op_mode_r = AgileOpModeR {
        kem_alg,
        op_mode_ty: AgileOpModeRTy::Base,
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
