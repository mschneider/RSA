use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};

use core::ops::Deref;
use num_bigint::traits::ModInverse;
use num_bigint::Sign::Plus;
use num_bigint::{BigInt, BigUint};
use num_traits::{One, ToPrimitive};
#[cfg(feature = "serde")]
use serde_crate::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::algorithms::{generate_multi_prime_key, generate_multi_prime_key_with_exp};
use crate::errors::{Error, Result};

use crate::padding::PaddingScheme;
use crate::raw::{DecryptionPrimitive, EncryptionPrimitive};
use crate::{oaep, pkcs1v15, pss};

static MIN_PUB_EXPONENT: u64 = 2;
static MAX_PUB_EXPONENT: u64 = 1 << (31 - 1);

pub trait PublicKeyParts {
    /// Returns the modulus of the key.
    fn n(&self) -> &BigUint;

    /// Returns the public exponent of the key.
    fn e(&self) -> &BigUint;

    /// Returns the modulus size in bytes. Raw signatures and ciphertexts for
    /// or by this public key will have the same size.
    fn size(&self) -> usize {
        (self.n().bits() + 7) / 8
    }
}

pub trait PrivateKey: DecryptionPrimitive + PublicKeyParts {}

/// Represents the public part of an RSA key.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, Hash, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
pub struct RsaPublicKey {
    n: BigUint,
    e: BigUint,
}

/// Represents a whole RSA key, public and private parts.
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct RsaPrivateKey {
    /// Public components of the private key.
    pubkey_components: RsaPublicKey,
    /// Private exponent
    pub(crate) d: BigUint,
    /// Prime factors of N, contains >= 2 elements.
    pub(crate) primes: Vec<BigUint>,
    /// precomputed values to speed up private operations
    #[cfg_attr(feature = "serde", serde(skip))]
    #[borsh_skip]
    pub(crate) precomputed: Option<PrecomputedValues>,
}

impl PartialEq for RsaPrivateKey {
    #[inline]
    fn eq(&self, other: &RsaPrivateKey) -> bool {
        self.pubkey_components == other.pubkey_components
            && self.d == other.d
            && self.primes == other.primes
    }
}

impl Eq for RsaPrivateKey {}

impl Zeroize for RsaPrivateKey {
    fn zeroize(&mut self) {
        self.d.zeroize();
        for prime in self.primes.iter_mut() {
            prime.zeroize();
        }
        self.primes.clear();
        if self.precomputed.is_some() {
            self.precomputed.take().unwrap().zeroize();
        }
    }
}

impl Drop for RsaPrivateKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Deref for RsaPrivateKey {
    type Target = RsaPublicKey;
    fn deref(&self) -> &RsaPublicKey {
        &self.pubkey_components
    }
}

#[derive(Debug, Clone)]
pub(crate) struct PrecomputedValues {
    /// D mod (P-1)
    pub(crate) dp: BigUint,
    /// D mod (Q-1)
    pub(crate) dq: BigUint,
    /// Q^-1 mod P
    pub(crate) qinv: BigInt,

    /// CRTValues is used for the 3rd and subsequent primes. Due to a
    /// historical accident, the CRT for the first two primes is handled
    /// differently in PKCS#1 and interoperability is sufficiently
    /// important that we mirror this.
    pub(crate) crt_values: Vec<CRTValue>,
}

impl Zeroize for PrecomputedValues {
    fn zeroize(&mut self) {
        self.dp.zeroize();
        self.dq.zeroize();
        self.qinv.zeroize();
        for val in self.crt_values.iter_mut() {
            val.zeroize();
        }
        self.crt_values.clear();
    }
}

impl Drop for PrecomputedValues {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Contains the precomputed Chinese remainder theorem values.
#[derive(Debug, Clone)]
pub(crate) struct CRTValue {
    /// D mod (prime - 1)
    pub(crate) exp: BigInt,
    /// R·Coeff ≡ 1 mod Prime.
    pub(crate) coeff: BigInt,
    /// product of primes prior to this (inc p and q)
    pub(crate) r: BigInt,
}

impl Zeroize for CRTValue {
    fn zeroize(&mut self) {
        self.exp.zeroize();
        self.coeff.zeroize();
        self.r.zeroize();
    }
}

impl From<RsaPrivateKey> for RsaPublicKey {
    fn from(private_key: RsaPrivateKey) -> Self {
        (&private_key).into()
    }
}

impl From<&RsaPrivateKey> for RsaPublicKey {
    fn from(private_key: &RsaPrivateKey) -> Self {
        let n = private_key.n.clone();
        let e = private_key.e.clone();

        RsaPublicKey { n, e }
    }
}

/// Generic trait for operations on a public key.
pub trait PublicKey: EncryptionPrimitive + PublicKeyParts {
    /// Verify a signed message.
    /// `hashed`must be the result of hashing the input using the hashing function
    /// passed in through `hash`.
    /// If the message is valid `Ok(())` is returned, otherwiese an `Err` indicating failure.
    fn verify(&self, padding: PaddingScheme, hashed: &[u8], sig: &[u8]) -> Result<()>;
}

impl PublicKeyParts for RsaPublicKey {
    fn n(&self) -> &BigUint {
        &self.n
    }

    fn e(&self) -> &BigUint {
        &self.e
    }
}

impl PublicKey for RsaPublicKey {
    fn verify(&self, padding: PaddingScheme, hashed: &[u8], sig: &[u8]) -> Result<()> {
        match padding {
            PaddingScheme::PKCS1v15Sign { ref hash } => {
                pkcs1v15::verify(self, hash.as_ref(), hashed, sig)
            }
            PaddingScheme::PSS { mut digest, .. } => pss::verify(self, hashed, sig, &mut *digest),
            _ => Err(Error::InvalidPaddingScheme),
        }
    }
}

impl RsaPublicKey {
    /// Create a new key from its components.
    pub fn new(n: BigUint, e: BigUint) -> Result<Self> {
        let k = RsaPublicKey { n, e };
        check_public(&k)?;

        Ok(k)
    }
}

impl<'a> PublicKeyParts for &'a RsaPublicKey {
    /// Returns the modulus of the key.
    fn n(&self) -> &BigUint {
        &self.n
    }

    /// Returns the public exponent of the key.
    fn e(&self) -> &BigUint {
        &self.e
    }
}

impl<'a> PublicKey for &'a RsaPublicKey {
    fn verify(&self, padding: PaddingScheme, hashed: &[u8], sig: &[u8]) -> Result<()> {
        (*self).verify(padding, hashed, sig)
    }
}

impl PublicKeyParts for RsaPrivateKey {
    fn n(&self) -> &BigUint {
        &self.n
    }

    fn e(&self) -> &BigUint {
        &self.e
    }
}

impl PrivateKey for RsaPrivateKey {}

impl<'a> PublicKeyParts for &'a RsaPrivateKey {
    fn n(&self) -> &BigUint {
        &self.n
    }

    fn e(&self) -> &BigUint {
        &self.e
    }
}

impl<'a> PrivateKey for &'a RsaPrivateKey {}

impl RsaPrivateKey {
    /// Generate a new Rsa key pair of the given bit size using the passed in `rng`.
    pub fn new<R>(rng: &mut R, bit_size: usize) -> Result<RsaPrivateKey> {
        generate_multi_prime_key(rng, 2, bit_size)
    }

    /// Generate a new RSA key pair of the given bit size and the public exponent
    /// using the passed in `rng`.
    ///
    /// Unless you have specific needs, you should use `RsaPrivateKey::new` instead.
    pub fn new_with_exp<R>(rng: &mut R, bit_size: usize, exp: &BigUint) -> Result<RsaPrivateKey> {
        generate_multi_prime_key_with_exp(rng, 2, bit_size, exp)
    }

    /// Constructs an RSA key pair from the individual components.
    pub fn from_components(
        n: BigUint,
        e: BigUint,
        d: BigUint,
        primes: Vec<BigUint>,
    ) -> RsaPrivateKey {
        let mut k = RsaPrivateKey {
            pubkey_components: RsaPublicKey { n, e },
            d,
            primes,
            precomputed: None,
        };

        // precompute when possible, ignore error otherwise.
        let _ = k.precompute();

        k
    }

    /// Get the public key from the private key, cloning `n` and `e`.
    ///
    /// Generally this is not needed since `RsaPrivateKey` implements the `PublicKey` trait,
    /// but it can occationally be useful to discard the private information entirely.
    pub fn to_public_key(&self) -> RsaPublicKey {
        // Safe to unwrap since n and e are already verified.
        RsaPublicKey::new(self.n().clone(), self.e().clone()).unwrap()
    }

    /// Performs some calculations to speed up private key operations.
    pub fn precompute(&mut self) -> Result<()> {
        if self.precomputed.is_some() {
            return Ok(());
        }

        let dp = &self.d % (&self.primes[0] - BigUint::one());
        let dq = &self.d % (&self.primes[1] - BigUint::one());
        let qinv = self.primes[1]
            .clone()
            .mod_inverse(&self.primes[0])
            .ok_or(Error::InvalidPrime)?;

        let mut r: BigUint = &self.primes[0] * &self.primes[1];
        let crt_values: Vec<CRTValue> = {
            let mut values = Vec::with_capacity(self.primes.len() - 2);
            for prime in &self.primes[2..] {
                let res = CRTValue {
                    exp: BigInt::from_biguint(Plus, &self.d % (prime - BigUint::one())),
                    r: BigInt::from_biguint(Plus, r.clone()),
                    coeff: BigInt::from_biguint(
                        Plus,
                        r.clone()
                            .mod_inverse(prime)
                            .ok_or(Error::InvalidCoefficient)?
                            .to_biguint()
                            .unwrap(),
                    ),
                };
                r *= prime;

                values.push(res);
            }
            values
        };

        self.precomputed = Some(PrecomputedValues {
            dp,
            dq,
            qinv,
            crt_values,
        });

        Ok(())
    }

    /// Clears precomputed values by setting to None
    pub fn clear_precomputed(&mut self) {
        self.precomputed = None;
    }

    /// Returns the private exponent of the key.
    pub fn d(&self) -> &BigUint {
        &self.d
    }

    /// Returns the prime factors.
    pub fn primes(&self) -> &[BigUint] {
        &self.primes
    }

    /// Performs basic sanity checks on the key.
    /// Returns `Ok(())` if everything is good, otherwise an approriate error.
    pub fn validate(&self) -> Result<()> {
        check_public(self)?;

        // Check that Πprimes == n.
        let mut m = BigUint::one();
        for prime in &self.primes {
            // Any primes ≤ 1 will cause divide-by-zero panics later.
            if *prime < BigUint::one() {
                return Err(Error::InvalidPrime);
            }
            m *= prime;
        }
        if m != self.n {
            return Err(Error::InvalidModulus);
        }

        // Check that de ≡ 1 mod p-1, for each prime.
        // This implies that e is coprime to each p-1 as e has a multiplicative
        // inverse. Therefore e is coprime to lcm(p-1,q-1,r-1,...) =
        // exponent(ℤ/nℤ). It also implies that a^de ≡ a mod p as a^(p-1) ≡ 1
        // mod p. Thus a^de ≡ a mod n for all a coprime to n, as required.
        let mut de = self.e.clone();
        de *= self.d.clone();
        for prime in &self.primes {
            let congruence: BigUint = &de % (prime - BigUint::one());
            if !congruence.is_one() {
                return Err(Error::InvalidExponent);
            }
        }

        Ok(())
    }

    /// Decrypt the given message.
    pub fn decrypt<R>(&self, padding: PaddingScheme, ciphertext: &[u8]) -> Result<Vec<u8>> {
        match padding {
            // need to pass any Rng as the type arg, so the type checker is happy, it is not actually used for anything
            PaddingScheme::PKCS1v15Encrypt => pkcs1v15::decrypt::<R, _>(None, self, ciphertext),
            PaddingScheme::OAEP {
                mut digest,
                mut mgf_digest,
                label,
            } => oaep::decrypt::<R, _>(
                None,
                self,
                ciphertext,
                &mut *digest,
                &mut *mgf_digest,
                label,
            ),
            _ => Err(Error::InvalidPaddingScheme),
        }
    }

    /// Decrypt the given message.
    ///
    /// Uses `rng` to blind the decryption process.
    pub fn decrypt_blinded<R>(
        &self,
        rng: &mut R,
        padding: PaddingScheme,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        match padding {
            PaddingScheme::PKCS1v15Encrypt => pkcs1v15::decrypt(Some(rng), self, ciphertext),
            PaddingScheme::OAEP {
                mut digest,
                mut mgf_digest,
                label,
            } => oaep::decrypt(
                Some(rng),
                self,
                ciphertext,
                &mut *digest,
                &mut *mgf_digest,
                label,
            ),
            _ => Err(Error::InvalidPaddingScheme),
        }
    }
}

/// Check that the public key is well formed and has an exponent within acceptable bounds.
#[inline]
pub fn check_public(public_key: &impl PublicKeyParts) -> Result<()> {
    let public_key = public_key
        .e()
        .to_u64()
        .ok_or(Error::PublicExponentTooLarge)?;

    if public_key < MIN_PUB_EXPONENT {
        return Err(Error::PublicExponentTooSmall);
    }

    if public_key > MAX_PUB_EXPONENT {
        return Err(Error::PublicExponentTooLarge);
    }

    Ok(())
}
