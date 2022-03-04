use alloc::vec::Vec;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

use crate::errors::{Error, Result};
use crate::hash::Hash;
use crate::key::{self, PrivateKey, PublicKey};

/// Decrypts a plaintext using RSA and the padding scheme from PKCS#1 v1.5.
// If an `rng` is passed, it uses RSA blinding to avoid timing side-channel attacks.
//
// Note that whether this function returns an error or not discloses secret
// information. If an attacker can cause this function to run repeatedly and
// learn whether each instance returned an error then they can decrypt and
// forge signatures as if they had the private key. See
// `decrypt_session_key` for a way of solving this problem.
#[inline]
pub fn decrypt<R, SK: PrivateKey>(
    rng: Option<&mut R>,
    priv_key: &SK,
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    key::check_public(priv_key)?;

    let (valid, out, index) = decrypt_inner(rng, priv_key, ciphertext)?;
    if valid == 0 {
        return Err(Error::Decryption);
    }

    Ok(out[index as usize..].to_vec())
}

/// Verifies an RSA PKCS#1 v1.5 signature.
#[inline]
pub fn verify<PK: PublicKey>(
    pub_key: &PK,
    hash: Option<&Hash>,
    hashed: &[u8],
    sig: &[u8],
) -> Result<()> {
    let (hash_len, prefix) = hash_info(hash, hashed.len())?;

    let t_len = prefix.len() + hash_len;
    let k = pub_key.size();
    if k < t_len + 11 {
        return Err(Error::Verification);
    }

    let em = pub_key.raw_encryption_primitive(sig, pub_key.size())?;

    // EM = 0x00 || 0x01 || PS || 0x00 || T
    let mut ok = em[0].ct_eq(&0u8);
    ok &= em[1].ct_eq(&1u8);
    ok &= em[k - hash_len..k].ct_eq(hashed);
    ok &= em[k - t_len..k - hash_len].ct_eq(&prefix);
    ok &= em[k - t_len - 1].ct_eq(&0u8);

    for el in em.iter().skip(2).take(k - t_len - 3) {
        ok &= el.ct_eq(&0xff)
    }

    if ok.unwrap_u8() != 1 {
        return Err(Error::Verification);
    }

    Ok(())
}

#[inline]
fn hash_info(hash: Option<&Hash>, digest_len: usize) -> Result<(usize, &'static [u8])> {
    match hash {
        Some(hash) => {
            let hash_len = hash.size();
            if digest_len != hash_len {
                return Err(Error::InputNotHashed);
            }

            Ok((hash_len, hash.asn1_prefix()))
        }
        // this means the data is signed directly
        None => Ok((digest_len, &[])),
    }
}

/// Decrypts ciphertext using `priv_key` and blinds the operation if
/// `rng` is given. It returns one or zero in valid that indicates whether the
/// plaintext was correctly structured. In either case, the plaintext is
/// returned in em so that it may be read independently of whether it was valid
/// in order to maintain constant memory access patterns. If the plaintext was
/// valid then index contains the index of the original message in em.
#[inline]
fn decrypt_inner<R, SK: PrivateKey>(
    rng: Option<&mut R>,
    priv_key: &SK,
    ciphertext: &[u8],
) -> Result<(u8, Vec<u8>, u32)> {
    let k = priv_key.size();
    if k < 11 {
        return Err(Error::Decryption);
    }

    let em = priv_key.raw_decryption_primitive(rng, ciphertext, priv_key.size())?;

    let first_byte_is_zero = em[0].ct_eq(&0u8);
    let second_byte_is_two = em[1].ct_eq(&2u8);

    // The remainder of the plaintext must be a string of non-zero random
    // octets, followed by a 0, followed by the message.
    //   looking_for_index: 1 iff we are still looking for the zero.
    //   index: the offset of the first zero byte.
    let mut looking_for_index = 1u8;
    let mut index = 0u32;

    for (i, el) in em.iter().enumerate().skip(2) {
        let equals0 = el.ct_eq(&0u8);
        index.conditional_assign(&(i as u32), Choice::from(looking_for_index) & equals0);
        looking_for_index.conditional_assign(&0u8, equals0);
    }

    // The PS padding must be at least 8 bytes long, and it starts two
    // bytes into em.
    // TODO: WARNING: THIS MUST BE CONSTANT TIME CHECK:
    // Ref: https://github.com/dalek-cryptography/subtle/issues/20
    // This is currently copy & paste from the constant time impl in
    // go, but very likely not sufficient.
    let valid_ps = Choice::from((((2i32 + 8i32 - index as i32 - 1i32) >> 31) & 1) as u8);
    let valid =
        first_byte_is_zero & second_byte_is_two & Choice::from(!looking_for_index & 1) & valid_ps;
    index = u32::conditional_select(&0, &(index + 1), valid);

    Ok((valid.unwrap_u8(), em, index))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64;
    use hex;
    use num_bigint::BigUint;
    use num_traits::FromPrimitive;
    use num_traits::Num;
    use sha1::{Digest, Sha1};
    use std::time::SystemTime;

    use crate::{Hash, PaddingScheme, PublicKey, PublicKeyParts, RsaPrivateKey, RsaPublicKey};

    fn get_private_key() -> RsaPrivateKey {
        // In order to generate new test vectors you'll need the PEM form of this key:
        // -----BEGIN RSA PRIVATE KEY-----
        // MIIBOgIBAAJBALKZD0nEffqM1ACuak0bijtqE2QrI/KLADv7l3kK3ppMyCuLKoF0
        // fd7Ai2KW5ToIwzFofvJcS/STa6HA5gQenRUCAwEAAQJBAIq9amn00aS0h/CrjXqu
        // /ThglAXJmZhOMPVn4eiu7/ROixi9sex436MaVeMqSNf7Ex9a8fRNfWss7Sqd9eWu
        // RTUCIQDasvGASLqmjeffBNLTXV2A5g4t+kLVCpsEIZAycV5GswIhANEPLmax0ME/
        // EO+ZJ79TJKN5yiGBRsv5yvx5UiHxajEXAiAhAol5N4EUyq6I9w1rYdhPMGpLfk7A
        // IU2snfRJ6Nq2CQIgFrPsWRCkV+gOYcajD17rEqmuLrdIRexpg8N1DOSXoJ8CIGlS
        // tAboUGBxTDq3ZroNism3DaMIbKPyYrAqhKov1h5V
        // -----END RSA PRIVATE KEY-----

        RsaPrivateKey::from_components(
            BigUint::from_str_radix("9353930466774385905609975137998169297361893554149986716853295022578535724979677252958524466350471210367835187480748268864277464700638583474144061408845077", 10).unwrap(),
            BigUint::from_u64(65537).unwrap(),
            BigUint::from_str_radix("7266398431328116344057699379749222532279343923819063639497049039389899328538543087657733766554155839834519529439851673014800261285757759040931985506583861", 10).unwrap(),
            vec![
                BigUint::from_str_radix("98920366548084643601728869055592650835572950932266967461790948584315647051443",10).unwrap(),
                BigUint::from_str_radix("94560208308847015747498523884063394671606671904944666360068158221458669711639", 10).unwrap()
            ],
        )
    }

    #[test]
    fn test_decrypt_pkcs1v15() {
        let priv_key = get_private_key();

        let tests = [[
	    "gIcUIoVkD6ATMBk/u/nlCZCCWRKdkfjCgFdo35VpRXLduiKXhNz1XupLLzTXAybEq15juc+EgY5o0DHv/nt3yg==",
	    "x",
	], [
	    "Y7TOCSqofGhkRb+jaVRLzK8xw2cSo1IVES19utzv6hwvx+M8kFsoWQm5DzBeJCZTCVDPkTpavUuEbgp8hnUGDw==",
	    "testing.",
	], [
	    "arReP9DJtEVyV2Dg3dDp4c/PSk1O6lxkoJ8HcFupoRorBZG+7+1fDAwT1olNddFnQMjmkb8vxwmNMoTAT/BFjQ==",
	    "testing.\n",
	], [
	"WtaBXIoGC54+vH0NH0CHHE+dRDOsMc/6BrfFu2lEqcKL9+uDuWaf+Xj9mrbQCjjZcpQuX733zyok/jsnqe/Ftw==",
		"01234567890123456789012345678901234567890123456789012",
	]];

        for test in &tests {
            let out = priv_key
                .decrypt(
                    PaddingScheme::new_pkcs1v15_encrypt(),
                    &base64::decode(test[0]).unwrap(),
                )
                .unwrap();
            assert_eq!(out, test[1].as_bytes());
        }
    }

    #[test]
    fn test_verify_pkcs1v15() {
        let priv_key = get_private_key();

        let tests = [[
            "Test.\n", "a4f3fa6ea93bcdd0c57be020c1193ecbfd6f200a3d95c409769b029578fa0e336ad9a347600e40d3ae823b8c7e6bad88cc07c1d54c3a1523cbbb6d58efc362ae"
	]];
        let pub_key: RsaPublicKey = priv_key.into();

        for test in &tests {
            let digest = Sha1::digest(test[0].as_bytes()).to_vec();
            let sig = hex::decode(test[1]).unwrap();

            pub_key
                .verify(
                    PaddingScheme::new_pkcs1v15_sign(Some(Hash::SHA1)),
                    &digest,
                    &sig,
                )
                .expect("failed to verify");
        }
    }

    #[test]
    fn test_unpadded_signature() {
        let msg = b"Thu Dec 19 18:06:16 EST 2013\n";
        let expected_sig = base64::decode("pX4DR8azytjdQ1rtUiC040FjkepuQut5q2ZFX1pTjBrOVKNjgsCDyiJDGZTCNoh9qpXYbhl7iEym30BWWwuiZg==").unwrap();
        let priv_key = get_private_key();

        let sig = priv_key
            .sign(PaddingScheme::new_pkcs1v15_sign(None), msg)
            .unwrap();
        assert_eq!(expected_sig, sig);

        let pub_key: RsaPublicKey = priv_key.into();
        pub_key
            .verify(PaddingScheme::new_pkcs1v15_sign(None), msg, &sig)
            .expect("failed to verify");
    }
}
