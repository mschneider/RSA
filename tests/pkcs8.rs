//! PKCS#8 encoding tests

#![cfg(feature = "alloc")]

/// RSA-2048 PKCS#8 private key encoded as ASN.1 DER
const RSA_2048_PRIV_DER: &[u8] = include_bytes!("examples/pkcs8/rsa2048-priv.der");

/// RSA-2048 `SubjectPublicKeyInfo` encoded as ASN.1 DER
const RSA_2048_PUB_DER: &[u8] = include_bytes!("examples/pkcs8/rsa2048-pub.der");

/// RSA-2048 PKCS#8 private key encoded as PEM
#[cfg(feature = "pem")]
const RSA_2048_PRIV_PEM: &str = include_str!("examples/pkcs8/rsa2048-priv.pem");

/// RSA-2048 PKCS#8 public key encoded as PEM
#[cfg(feature = "pem")]
const RSA_2048_PUB_PEM: &str = include_str!("examples/pkcs8/rsa2048-pub.pem");

use hex_literal::hex;
use rsa::{
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey},
    PublicKeyParts, RsaPrivateKey, RsaPublicKey,
};

#[test]
fn decode_rsa2048_priv_der() {
    let key = RsaPrivateKey::from_pkcs8_der(RSA_2048_PRIV_DER).unwrap();

    // Note: matches PKCS#1 test vectors
    assert_eq!(&key.n().to_bytes_be(), &hex!("B6C42C515F10A6AAF282C63EDBE24243A170F3FA2633BD4833637F47CA4F6F36E03A5D29EFC3191AC80F390D874B39E30F414FCEC1FCA0ED81E547EDC2CD382C76F61C9018973DB9FA537972A7C701F6B77E0982DFC15FC01927EE5E7CD94B4F599FF07013A7C8281BDF22DCBC9AD7CABB7C4311C982F58EDB7213AD4558B332266D743AED8192D1884CADB8B14739A8DADA66DC970806D9C7AC450CB13D0D7C575FB198534FC61BC41BC0F0574E0E0130C7BBBFBDFDC9F6A6E2E3E2AFF1CBEAC89BA57884528D55CFB08327A1E8C89F4E003CF2888E933241D9D695BCBBACDC90B44E3E095FA37058EA25B13F5E295CBEAC6DE838AB8C50AF61E298975B872F"));
    assert_eq!(&key.e().to_bytes_be(), &hex!("010001"));
    assert_eq!(&key.d().to_bytes_be(), &hex!("7ECC8362C0EDB0741164215E22F74AB9D91BA06900700CF63690E5114D8EE6BDCFBB2E3F9614692A677A083F168A5E52E5968E6407B9D97C6E0E4064F82DA0B758A14F17B9B7D41F5F48E28D6551704F56E69E7AA9FA630FC76428C06D25E455DCFC55B7AC2B4F76643FDED3FE15FF78ABB27E65ACC4AAD0BDF6DB27EF60A6910C5C4A085ED43275AB19C1D997A32C6EFFCE7DF2D1935F6E601EEDE161A12B5CC27CA21F81D2C99C3D1EA08E90E3053AB09BEFA724DEF0D0C3A3C1E9740C0D9F76126A149EC0AA7D8078205484254D951DB07C4CF91FB6454C096588FD5924DBABEB359CA2025268D004F9D66EB3D6F7ADC1139BAD40F16DDE639E11647376C1"));
    assert_eq!(&key.primes()[0].to_bytes_be(), &hex!("DCC061242D4E92AFAEE72AC513CA65B9F77036F9BD7E0E6E61461A7EF7654225EC153C7E5C31A6157A6E5A13FF6E178E8758C1CB33D9D6BBE3179EF18998E422ECDCBED78F4ECFDBE5F4FCD8AEC2C9D0DC86473CA9BD16D9D238D21FB5DDEFBEB143CA61D0BD6AA8D91F33A097790E9640DBC91085DC5F26343BA3138F6B2D67"));
    assert_eq!(&key.primes()[1].to_bytes_be(), &hex!("D3F314757E40E954836F92BE24236AF2F0DA04A34653C180AF67E960086D93FDE65CB23EFD9D09374762F5981E361849AF68CDD75394FF6A4E06EB69B209E4228DB2DFA70E40F7F9750A528176647B788D0E5777A2CB8B22E3CD267FF70B4F3B02D3AAFB0E18C590A564B03188B0AA5FC48156B07622214243BD1227EFA7F2F9"));
}

#[test]
fn decode_rsa2048_pub_der() {
    let key = RsaPublicKey::from_public_key_der(RSA_2048_PUB_DER).unwrap();

    // Note: matches PKCS#1 test vectors
    assert_eq!(&key.n().to_bytes_be(), &hex!("B6C42C515F10A6AAF282C63EDBE24243A170F3FA2633BD4833637F47CA4F6F36E03A5D29EFC3191AC80F390D874B39E30F414FCEC1FCA0ED81E547EDC2CD382C76F61C9018973DB9FA537972A7C701F6B77E0982DFC15FC01927EE5E7CD94B4F599FF07013A7C8281BDF22DCBC9AD7CABB7C4311C982F58EDB7213AD4558B332266D743AED8192D1884CADB8B14739A8DADA66DC970806D9C7AC450CB13D0D7C575FB198534FC61BC41BC0F0574E0E0130C7BBBFBDFDC9F6A6E2E3E2AFF1CBEAC89BA57884528D55CFB08327A1E8C89F4E003CF2888E933241D9D695BCBBACDC90B44E3E095FA37058EA25B13F5E295CBEAC6DE838AB8C50AF61E298975B872F"));
    assert_eq!(&key.e().to_bytes_be(), &hex!("010001"));
}

#[test]
fn encode_rsa2048_priv_der() {
    let key = RsaPrivateKey::from_pkcs8_der(RSA_2048_PRIV_DER).unwrap();
    let der = key.to_pkcs8_der().unwrap();
    assert_eq!(der.as_ref(), RSA_2048_PRIV_DER)
}

#[test]
fn encode_rsa2048_pub_der() {
    let key = RsaPublicKey::from_public_key_der(RSA_2048_PUB_DER).unwrap();
    let der = key.to_public_key_der().unwrap();
    assert_eq!(der.as_ref(), RSA_2048_PUB_DER)
}

#[test]
#[cfg(feature = "pem")]
fn decode_rsa2048_priv_pem() {
    let key = RsaPrivateKey::from_pkcs8_pem(RSA_2048_PRIV_PEM).unwrap();

    // Note: matches PKCS#1 test vectors
    assert_eq!(&key.n().to_bytes_be(), &hex!("B6C42C515F10A6AAF282C63EDBE24243A170F3FA2633BD4833637F47CA4F6F36E03A5D29EFC3191AC80F390D874B39E30F414FCEC1FCA0ED81E547EDC2CD382C76F61C9018973DB9FA537972A7C701F6B77E0982DFC15FC01927EE5E7CD94B4F599FF07013A7C8281BDF22DCBC9AD7CABB7C4311C982F58EDB7213AD4558B332266D743AED8192D1884CADB8B14739A8DADA66DC970806D9C7AC450CB13D0D7C575FB198534FC61BC41BC0F0574E0E0130C7BBBFBDFDC9F6A6E2E3E2AFF1CBEAC89BA57884528D55CFB08327A1E8C89F4E003CF2888E933241D9D695BCBBACDC90B44E3E095FA37058EA25B13F5E295CBEAC6DE838AB8C50AF61E298975B872F"));
    assert_eq!(&key.e().to_bytes_be(), &hex!("010001"));
    assert_eq!(&key.d().to_bytes_be(), &hex!("7ECC8362C0EDB0741164215E22F74AB9D91BA06900700CF63690E5114D8EE6BDCFBB2E3F9614692A677A083F168A5E52E5968E6407B9D97C6E0E4064F82DA0B758A14F17B9B7D41F5F48E28D6551704F56E69E7AA9FA630FC76428C06D25E455DCFC55B7AC2B4F76643FDED3FE15FF78ABB27E65ACC4AAD0BDF6DB27EF60A6910C5C4A085ED43275AB19C1D997A32C6EFFCE7DF2D1935F6E601EEDE161A12B5CC27CA21F81D2C99C3D1EA08E90E3053AB09BEFA724DEF0D0C3A3C1E9740C0D9F76126A149EC0AA7D8078205484254D951DB07C4CF91FB6454C096588FD5924DBABEB359CA2025268D004F9D66EB3D6F7ADC1139BAD40F16DDE639E11647376C1"));
    assert_eq!(&key.primes()[0].to_bytes_be(), &hex!("DCC061242D4E92AFAEE72AC513CA65B9F77036F9BD7E0E6E61461A7EF7654225EC153C7E5C31A6157A6E5A13FF6E178E8758C1CB33D9D6BBE3179EF18998E422ECDCBED78F4ECFDBE5F4FCD8AEC2C9D0DC86473CA9BD16D9D238D21FB5DDEFBEB143CA61D0BD6AA8D91F33A097790E9640DBC91085DC5F26343BA3138F6B2D67"));
    assert_eq!(&key.primes()[1].to_bytes_be(), &hex!("D3F314757E40E954836F92BE24236AF2F0DA04A34653C180AF67E960086D93FDE65CB23EFD9D09374762F5981E361849AF68CDD75394FF6A4E06EB69B209E4228DB2DFA70E40F7F9750A528176647B788D0E5777A2CB8B22E3CD267FF70B4F3B02D3AAFB0E18C590A564B03188B0AA5FC48156B07622214243BD1227EFA7F2F9"));
}

#[test]
#[cfg(feature = "pem")]
fn decode_rsa2048_pub_pem() {
    let key = RsaPublicKey::from_public_key_pem(RSA_2048_PUB_PEM).unwrap();

    // Note: matches PKCS#1 test vectors
    assert_eq!(&key.n().to_bytes_be(), &hex!("B6C42C515F10A6AAF282C63EDBE24243A170F3FA2633BD4833637F47CA4F6F36E03A5D29EFC3191AC80F390D874B39E30F414FCEC1FCA0ED81E547EDC2CD382C76F61C9018973DB9FA537972A7C701F6B77E0982DFC15FC01927EE5E7CD94B4F599FF07013A7C8281BDF22DCBC9AD7CABB7C4311C982F58EDB7213AD4558B332266D743AED8192D1884CADB8B14739A8DADA66DC970806D9C7AC450CB13D0D7C575FB198534FC61BC41BC0F0574E0E0130C7BBBFBDFDC9F6A6E2E3E2AFF1CBEAC89BA57884528D55CFB08327A1E8C89F4E003CF2888E933241D9D695BCBBACDC90B44E3E095FA37058EA25B13F5E295CBEAC6DE838AB8C50AF61E298975B872F"));
    assert_eq!(&key.e().to_bytes_be(), &hex!("010001"));
}

#[test]
#[cfg(feature = "pem")]
fn encode_rsa2048_priv_pem() {
    let key = RsaPrivateKey::from_pkcs8_pem(RSA_2048_PRIV_PEM).unwrap();
    let pem = key.to_pkcs8_pem(Default::default()).unwrap();
    assert_eq!(&*pem, RSA_2048_PRIV_PEM)
}

#[test]
#[cfg(feature = "pem")]
fn encode_rsa2048_pub_pem() {
    let key = RsaPublicKey::from_public_key_pem(RSA_2048_PUB_PEM).unwrap();
    let pem = key.to_public_key_pem(Default::default()).unwrap();
    assert_eq!(&*pem, RSA_2048_PUB_PEM)
}
