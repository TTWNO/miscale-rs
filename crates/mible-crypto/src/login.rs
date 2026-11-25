//! The login key schedule and the two HMAC proofs.
//!
//! ```text
//! okm      = HKDF-SHA256(ikm = token, salt = app_rand ‖ dev_rand,
//!                        info = "mible-login-info", L = 64)
//! dev_key  = okm[0..16]    app_key = okm[16..32]
//! dev_iv   = okm[32..36]   app_iv  = okm[36..40]
//! device proof = HMAC-SHA256(dev_key, dev_rand ‖ app_rand)
//! app proof    = HMAC-SHA256(app_key, app_rand ‖ dev_rand)
//! ```

use core::fmt;

use hkdf::Hkdf;
use hmac::{Hmac, KeyInit as _, Mac as _};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::Token;

/// Length of each side's login random.
pub const RANDOM_LEN: usize = 16;

/// Length of an HMAC-SHA256 proof.
pub const PROOF_LEN: usize = 32;

/// One side's 16-byte login random.
pub type Random = [u8; RANDOM_LEN];

/// An HMAC-SHA256 login proof.
pub type Proof = [u8; PROOF_LEN];

/// HKDF `info` for the login key schedule.
const LOGIN_INFO: &[u8] = b"mible-login-info";

/// Keys for one login session, zeroised on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct LoginKeys {
    /// AES key the device encrypts with.
    dev_key: [u8; 16],
    /// AES key the app encrypts with.
    app_key: [u8; 16],
    /// Nonce prefix for device-to-app messages.
    dev_iv: [u8; 4],
    /// Nonce prefix for app-to-device messages.
    app_iv: [u8; 4],
}

impl fmt::Debug for LoginKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LoginKeys(<redacted>)")
    }
}

impl LoginKeys {
    /// Derives the session keys from the token and both randoms.
    #[must_use]
    pub fn derive(token: &Token, app_rand: &Random, dev_rand: &Random) -> Self {
        let mut salt = Zeroizing::new([0_u8; 2 * RANDOM_LEN]);
        let (app_half, dev_half) = salt.split_at_mut(RANDOM_LEN);
        app_half.copy_from_slice(app_rand);
        dev_half.copy_from_slice(dev_rand);
        let mut okm = Zeroizing::new([0_u8; 64]);
        // 64 bytes is far below HKDF-SHA256's 8160-byte limit, so this cannot fail.
        let _expanded: Result<(), hkdf::InvalidLength> =
            Hkdf::<Sha256>::new(Some(salt.as_slice()), token.as_bytes())
                .expand(LOGIN_INFO, okm.as_mut_slice());
        let mut keys = Self {
            dev_key: [0; 16],
            app_key: [0; 16],
            dev_iv: [0; 4],
            app_iv: [0; 4],
        };
        let (dev_key, rest) = okm.split_at(16);
        let (app_key, rest) = rest.split_at(16);
        let (dev_iv, rest) = rest.split_at(4);
        let (app_iv, _) = rest.split_at(4);
        keys.dev_key.copy_from_slice(dev_key);
        keys.app_key.copy_from_slice(app_key);
        keys.dev_iv.copy_from_slice(dev_iv);
        keys.app_iv.copy_from_slice(app_iv);
        keys
    }

    /// The app-to-device key and nonce prefix.
    pub(crate) const fn app_direction(&self) -> (&[u8; 16], [u8; 4]) {
        (&self.app_key, self.app_iv)
    }

    /// The device-to-app key and nonce prefix.
    pub(crate) const fn device_direction(&self) -> (&[u8; 16], [u8; 4]) {
        (&self.dev_key, self.dev_iv)
    }

    /// The proof the device sends: `HMAC(dev_key, dev_rand ‖ app_rand)`.
    #[must_use]
    pub fn device_proof(&self, app_rand: &Random, dev_rand: &Random) -> Proof {
        hmac_sha256(&self.dev_key, dev_rand, app_rand)
    }

    /// The proof the app sends: `HMAC(app_key, app_rand ‖ dev_rand)`.
    #[must_use]
    pub fn app_proof(&self, app_rand: &Random, dev_rand: &Random) -> Proof {
        hmac_sha256(&self.app_key, app_rand, dev_rand)
    }

    /// Checks, in constant time, a device proof received during login.
    ///
    /// # Errors
    ///
    /// [`ProofMismatch`] if the proof was not made with this session's keys,
    /// which in practice means the token is wrong.
    pub fn verify_device_proof(
        &self,
        app_rand: &Random,
        dev_rand: &Random,
        proof: &[u8],
    ) -> Result<(), ProofMismatch> {
        verify_hmac_sha256(&self.dev_key, dev_rand, app_rand, proof)
    }

    /// Checks, in constant time, an app proof (the device's side of login).
    ///
    /// # Errors
    ///
    /// [`ProofMismatch`] if the proof was not made with this session's keys.
    pub fn verify_app_proof(
        &self,
        app_rand: &Random,
        dev_rand: &Random,
        proof: &[u8],
    ) -> Result<(), ProofMismatch> {
        verify_hmac_sha256(&self.app_key, app_rand, dev_rand, proof)
    }
}

/// `HMAC-SHA256(key, first ‖ second)`.
fn hmac_sha256(key: &[u8; 16], first: &Random, second: &Random) -> Proof {
    let mut mac = new_mac(key);
    mac.update(first);
    mac.update(second);
    mac.finalize().into_bytes().into()
}

/// Constant-time check of `HMAC-SHA256(key, first ‖ second) == proof`.
fn verify_hmac_sha256(
    key: &[u8; 16],
    first: &Random,
    second: &Random,
    proof: &[u8],
) -> Result<(), ProofMismatch> {
    let mut mac = new_mac(key);
    mac.update(first);
    mac.update(second);
    mac.verify_slice(proof)
        .map_err(|hmac::digest::MacError| ProofMismatch)
}

/// A keyed HMAC-SHA256 instance.
fn new_mac(key: &[u8; 16]) -> Hmac<Sha256> {
    // HMAC zero-pads a key shorter than the 64-byte SHA-256 block (RFC 2104,
    // section 2), so padding here is equivalent and allows the infallible
    // constructor.
    let mut block = Zeroizing::new([0_u8; 64]);
    let (head, _) = block.split_at_mut(16);
    head.copy_from_slice(key);
    Hmac::<Sha256>::new((&*block).into())
}

/// A login proof did not verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[expect(
    clippy::exhaustive_structs,
    reason = "a unit error; there is nothing to add to it"
)]
pub struct ProofMismatch;

impl fmt::Display for ProofMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("login proof does not match (wrong token?)")
    }
}

impl core::error::Error for ProofMismatch {}
