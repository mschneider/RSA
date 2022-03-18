//! pem encoding tests

#![cfg(feature = "alloc")]

use hex_literal::hex;
use rand::rngs::OsRng;
use rsa::{
    pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey},
    pkcs8::{DecodePublicKey, EncodePublicKey},
    PaddingScheme, PublicKey, PublicKeyParts, RsaPrivateKey, RsaPublicKey,
};
use std::fs;

/// RSA-128 asn1 private key encoded as PEM
#[cfg(feature = "pem")]
const RSA_128_PRIV_PEM: &str = include_str!("examples/pem/rsa128-priv.pem");

/// RSA-192 asn1 private key encoded as PEM
#[cfg(feature = "pem")]
const RSA_192_PRIV_PEM: &str = include_str!("examples/pem/rsa192-priv.pem");

/// RSA-256 asn1 private key encoded as PEM
#[cfg(feature = "pem")]
const RSA_256_PRIV_PEM: &str = include_str!("examples/pem/rsa256-priv.pem");

/// RSA-512 asn1 private key encoded as PEM
#[cfg(feature = "pem")]
const RSA_512_PRIV_PEM: &str = include_str!("examples/pem/rsa512-priv.pem");

/// RSA-768 asn1 private key encoded as PEM
#[cfg(feature = "pem")]
const RSA_768_PRIV_PEM: &str = include_str!("examples/pem/rsa768-priv.pem");

/// RSA-1024 asn1 private key encoded as PEM
#[cfg(feature = "pem")]
const RSA_1024_PRIV_PEM: &str = include_str!("examples/pem/rsa1024-priv.pem");

/// RSA-128 asn1 public key encoded as PEM
#[cfg(feature = "pem")]
const RSA_128_PUB_PEM: &str = include_str!("examples/pem/rsa128-pub.pem");

/// RSA-192 asn1 public key encoded as PEM
#[cfg(feature = "pem")]
const RSA_192_PUB_PEM: &str = include_str!("examples/pem/rsa192-pub.pem");

/// RSA-256 asn1 public key encoded as PEM
#[cfg(feature = "pem")]
const RSA_256_PUB_PEM: &str = include_str!("examples/pem/rsa256-pub.pem");

/// RSA-512 asn1 public key encoded as PEM
#[cfg(feature = "pem")]
const RSA_512_PUB_PEM: &str = include_str!("examples/pem/rsa512-pub.pem");

/// RSA-768 asn1 public key encoded as PEM
#[cfg(feature = "pem")]
const RSA_768_PUB_PEM: &str = include_str!("examples/pem/rsa768-pub.pem");

/// RSA-1024 asn1 public key encoded as PEM
#[cfg(feature = "pem")]
const RSA_1024_PUB_PEM: &str = include_str!("examples/pem/rsa1024-pub.pem");

// /// RSA-512 encrypted "The quick brown fox jumps over the lazy dog"
// #[cfg(feature = "pem")]
// const RSA_512_CIPHER: &[u8] = include_bytes!("examples/pem/rsa512-ciphertext.bin");

// /// RSA-1024 encrypted "The quick brown fox jumps over the lazy dog"
// #[cfg(feature = "pem")]
// const RSA_1024_CIPHER: &[u8] = include_bytes!("examples/pem/rsa1024-ciphertext.bin");

#[test]
#[cfg(feature = "pem")]
fn decode_rsa512_priv_pem() {
    let key = RsaPrivateKey::from_pkcs1_pem(RSA_512_PRIV_PEM).unwrap();

    // Extracted using:
    // $ openssl asn1parse -in tests/examples/pem/rsa512-priv.pem
    assert_eq!(&key.n().to_bytes_be(), &hex!("A91C2928B39150F622CF8C18012B9AEE69F665C857D92C3641FDC25CA00323B9E38E5BDFE8F2A183BCC2B4BC70F6C0C5921BE1B9CBFCDD586AE5B4DD5425986F"));
    assert_eq!(&key.e().to_bytes_be(), &hex!("010001"));
    assert_eq!(&key.d().to_bytes_be(), &hex!("58A175C0EB3C021EBE67E098C424427329FE05A256C86FAF902E9B2B4881DCBABA32CA4A98BCC71FBA00B85DFEA28621485786CEB7BBA7037DC3FD0AEA239FA1"));
    assert_eq!(
        &key.primes()[0].to_bytes_be(),
        &hex!("D3B7F93BC05D0F85802CBB39C48A9151098942EE1B3AB0529342CC14826063AD")
    );
    assert_eq!(
        &key.primes()[1].to_bytes_be(),
        &hex!("CC7ACC326E59A5EF15610A2F6A254176A1BA7C67B5CF18122DCC632C47B0900B")
    );
}

#[test]
#[cfg(feature = "pem")]
fn decode_rsa1024_priv_pem() {
    let key = RsaPrivateKey::from_pkcs1_pem(RSA_1024_PRIV_PEM).unwrap();

    // Extracted using:
    // $ openssl asn1parse -in tests/examples/pem/rsa1024-priv.pem
    assert_eq!(&key.n().to_bytes_be(), &hex!("CC34188FBDA3A6841E11045CB7711C8FD78037D876DF69BC730983B390FDF8458630F1B406BFD082BA95481BBF960282632D51B7E44C95A28768E347D9BCAA25DCA9FA2AEA1B14D45C612C1AC76B357DEC842F67AE887D5653F85C134B6BCF414A9C888B669AC54E6CBC85B4AB130156B1D21222565FD15A1F25A09D506708CF"));
    assert_eq!(&key.e().to_bytes_be(), &hex!("010001"));
    assert_eq!(&key.d().to_bytes_be(), &hex!("21515AB491479352B92923A211183685CDAE90EE13AF2E2C5E44AE256D41D2F15D0CBD53174AD2B591C5EBA7036271745EC4353220E0D2055BBCA460C3C901A5B30899D072B64397F7E0024992CC484057911769BCD712F3679AA379CE65BBB0FCD81B1FFD8BB27CA4C9041D7530D47680D97938B40BC893141FB349E6E6A4C9"));
    assert_eq!(
        &key.primes()[0].to_bytes_be(),
        &hex!("F55290302B010A805A30D2F4BC8233F4EEF3A40AA097B0068866D3950D05680BB1811B4F311C5F9DD11D0A56A4F9C846C1232C20B6B33AF4154035AA5B7B95F3")
    );
    assert_eq!(
        &key.primes()[1].to_bytes_be(),
        &hex!("D517602FBD317EBF46C7B2DD79C8AF425E83CEEDC5677B65FFC233FEBCD1A800078B53C280572845F7F89DC24E0ED74177663031E7F6CA171CDCD6491D8EECB5")
    );
}

#[test]
#[cfg(feature = "pem")]
fn decode_rsa1024_pub_pem() {
    let key = RsaPublicKey::from_public_key_pem(RSA_1024_PUB_PEM).unwrap();

    // Extracted using: (remove leading 00 byte)
    // $ openssl rsa -pubin -in tests/examples/pem/rsa1024-pub.pem -text
    assert_eq!(&key.n().to_bytes_be(), &hex!("cc34188fbda3a6841e11045cb7711c8fd78037d876df69bc730983b390fdf8458630f1b406bfd082ba95481bbf960282632d51b7e44c95a28768e347d9bcaa25dca9fa2aea1b14d45c612c1ac76b357dec842f67ae887d5653f85c134b6bcf414a9c888b669ac54e6cbc85b4ab130156b1d21222565fd15a1f25a09d506708cf"));
    assert_eq!(&key.e().to_bytes_be(), &hex!("010001"));
}

#[test]
#[cfg(feature = "pem")]
fn decode_rsa512_pub_pem() {
    let key = RsaPublicKey::from_public_key_pem(RSA_512_PUB_PEM).unwrap();

    // Extracted using: (remove leading 00 byte)
    // $ openssl rsa -pubin -in tests/examples/pem/rsa512-pub.pem -text
    assert_eq!(&key.n().to_bytes_be(), &hex!("a91c2928b39150f622cf8c18012b9aee69f665c857d92c3641fdc25ca00323b9e38e5bdfe8f2a183bcc2b4bc70f6c0c5921be1b9cbfcdd586ae5b4dd5425986f"));
    assert_eq!(&key.e().to_bytes_be(), &hex!("010001"));
}

#[test]
#[cfg(feature = "pem")]
fn encode_rsa1024_priv_pem() {
    let key = RsaPrivateKey::from_pkcs1_pem(RSA_1024_PRIV_PEM).unwrap();
    let pem = key.to_pkcs1_pem(Default::default()).unwrap();
    assert_eq!(&*pem, RSA_1024_PRIV_PEM)
}

#[test]
#[cfg(feature = "pem")]
fn encode_rsa512_priv_pem() {
    let key = RsaPrivateKey::from_pkcs1_pem(RSA_512_PRIV_PEM).unwrap();
    let pem = key.to_pkcs1_pem(Default::default()).unwrap();
    assert_eq!(&*pem, RSA_512_PRIV_PEM)
}

#[test]
#[cfg(feature = "pem")]
fn encode_rsa1024_pub_pem() {
    let key = RsaPublicKey::from_public_key_pem(RSA_1024_PUB_PEM).unwrap();
    let pem = key.to_public_key_pem(Default::default()).unwrap();
    assert_eq!(&*pem, RSA_1024_PUB_PEM)
}

#[test]
#[cfg(feature = "pem")]
fn encode_rsa512_pub_pem() {
    let key = RsaPublicKey::from_public_key_pem(RSA_512_PUB_PEM).unwrap();
    let pem = key.to_public_key_pem(Default::default()).unwrap();
    assert_eq!(&*pem, RSA_512_PUB_PEM)
}

#[test]
#[cfg(feature = "pem")]
fn derive_rsa1024_pub_pem() {
    let secret_key = RsaPrivateKey::from_pkcs1_pem(RSA_1024_PRIV_PEM).unwrap();
    let public_key = RsaPublicKey::from(secret_key);
    let pem = public_key.to_public_key_pem(Default::default()).unwrap();
    assert_eq!(&*pem, RSA_1024_PUB_PEM)
}

#[test]
#[cfg(feature = "pem")]
fn derive_rsa512_pub_pem() {
    let secret_key = RsaPrivateKey::from_pkcs1_pem(RSA_512_PRIV_PEM).unwrap();
    let public_key = RsaPublicKey::from(secret_key);
    let pem = public_key.to_public_key_pem(Default::default()).unwrap();
    assert_eq!(&*pem, RSA_512_PUB_PEM)
}

#[test]
#[cfg(feature = "pem")]
fn encrypt_rsa1024() {
    let mut rng = OsRng;
    let secret_key = RsaPrivateKey::from_pkcs1_pem(RSA_1024_PRIV_PEM).unwrap();
    let public_key = RsaPublicKey::from_public_key_pem(RSA_1024_PUB_PEM).unwrap();
    let message = b"The quick brown fox jumps over the lazy dog";

    let ciphertext = public_key
        .encrypt(
            &mut rng,
            PaddingScheme::new_pkcs1v15_encrypt(),
            &message[..],
        )
        .unwrap();

    fs::write(
        "./tests/examples/pem/rsa1024-ciphertext.bin",
        ciphertext.clone(),
    )
    .unwrap();

    let recovered_message = secret_key
        .decrypt(PaddingScheme::new_pkcs1v15_encrypt(), &ciphertext)
        .unwrap();
    assert_eq!(recovered_message, message);
}

#[test]
#[cfg(feature = "pem")]
fn encrypt_rsa768() {
    let mut rng = OsRng;
    let secret_key = RsaPrivateKey::from_pkcs1_pem(RSA_768_PRIV_PEM).unwrap();
    let public_key = RsaPublicKey::from_public_key_pem(RSA_768_PUB_PEM).unwrap();
    let message = b"The quick brown fox jumps over the lazy dog";

    let ciphertext = public_key
        .encrypt(
            &mut rng,
            PaddingScheme::new_pkcs1v15_encrypt(),
            &message[..],
        )
        .unwrap();

    fs::write(
        "./tests/examples/pem/rsa768-ciphertext.bin",
        ciphertext.clone(),
    )
    .unwrap();

    let recovered_message = secret_key
        .decrypt(PaddingScheme::new_pkcs1v15_encrypt(), &ciphertext)
        .unwrap();
    assert_eq!(recovered_message, message);
}

#[test]
#[cfg(feature = "pem")]
fn encrypt_rsa512() {
    let mut rng = OsRng;
    let secret_key = RsaPrivateKey::from_pkcs1_pem(RSA_512_PRIV_PEM).unwrap();
    let public_key = RsaPublicKey::from_public_key_pem(RSA_512_PUB_PEM).unwrap();
    let message = b"The quick brown fox jumps over the lazy dog";

    let ciphertext = public_key
        .encrypt(
            &mut rng,
            PaddingScheme::new_pkcs1v15_encrypt(),
            &message[..],
        )
        .unwrap();

    fs::write(
        "./tests/examples/pem/rsa512-ciphertext.bin",
        ciphertext.clone(),
    )
    .unwrap();

    let recovered_message = secret_key
        .decrypt(PaddingScheme::new_pkcs1v15_encrypt(), &ciphertext)
        .unwrap();
    assert_eq!(recovered_message, message);
}

#[test]
#[cfg(feature = "pem")]
fn encrypt_rsa256() {
    let mut rng = OsRng;
    let secret_key = RsaPrivateKey::from_pkcs1_pem(RSA_256_PRIV_PEM).unwrap();
    let public_key = RsaPublicKey::from_public_key_pem(RSA_256_PUB_PEM).unwrap();
    let message = b"The quick brown fox j";

    let ciphertext = public_key
        .encrypt(
            &mut rng,
            PaddingScheme::new_pkcs1v15_encrypt(),
            &message[..],
        )
        .unwrap();

    fs::write(
        "./tests/examples/pem/rsa256-ciphertext.bin",
        ciphertext.clone(),
    )
    .unwrap();

    let recovered_message = secret_key
        .decrypt(PaddingScheme::new_pkcs1v15_encrypt(), &ciphertext)
        .unwrap();
    assert_eq!(recovered_message, message);
}

#[test]
#[cfg(feature = "pem")]
fn encrypt_rsa192() {
    let mut rng = OsRng;
    let secret_key = RsaPrivateKey::from_pkcs1_pem(RSA_192_PRIV_PEM).unwrap();
    let public_key = RsaPublicKey::from_public_key_pem(RSA_192_PUB_PEM).unwrap();
    let message = b"The quick bro";

    let ciphertext = public_key
        .encrypt(
            &mut rng,
            PaddingScheme::new_pkcs1v15_encrypt(),
            &message[..],
        )
        .unwrap();

    fs::write(
        "./tests/examples/pem/rsa192-ciphertext.bin",
        ciphertext.clone(),
    )
    .unwrap();

    let recovered_message = secret_key
        .decrypt(PaddingScheme::new_pkcs1v15_encrypt(), &ciphertext)
        .unwrap();
    assert_eq!(recovered_message, message);
}

#[test]
#[cfg(feature = "pem")]
fn encrypt_rsa128() {
    let mut rng = OsRng;
    let secret_key = RsaPrivateKey::from_pkcs1_pem(RSA_128_PRIV_PEM).unwrap();
    let public_key = RsaPublicKey::from_public_key_pem(RSA_128_PUB_PEM).unwrap();
    let message = b"The q";

    let ciphertext = public_key
        .encrypt(
            &mut rng,
            PaddingScheme::new_pkcs1v15_encrypt(),
            &message[..],
        )
        .unwrap();

    fs::write(
        "./tests/examples/pem/rsa128-ciphertext.bin",
        ciphertext.clone(),
    )
    .unwrap();

    let recovered_message = secret_key
        .decrypt(PaddingScheme::new_pkcs1v15_encrypt(), &ciphertext)
        .unwrap();
    assert_eq!(recovered_message, message);
}
