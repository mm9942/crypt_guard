//! Caller authentication hooks.
//!
//! The adapter does not implement an identity system. It asks an
//! [`Authenticator`] to turn request metadata (headers, extensions such as a
//! verified mTLS peer identity) into a [`Principal`]. Authorization is a
//! separate concern (`crypt_guard_service::Authorizer`).

use core::fmt;

use http::request::Parts;
use zeroize::Zeroizing;

use crypt_guard_service::{CryptoServiceError, Principal, SecretBytes};

/// Extracts the caller identity from request metadata.
pub trait Authenticator: Send + Sync + 'static {
    /// `Ok(Some(principal))` for an authenticated caller, `Ok(None)` for an
    /// anonymous request, `Err(Unauthenticated)` for invalid credentials.
    fn authenticate(&self, parts: &Parts) -> Result<Option<Principal>, CryptoServiceError>;
}

/// Treats every request as anonymous.
#[derive(Clone, Copy, Debug, Default)]
pub struct Anonymous;

impl Authenticator for Anonymous {
    fn authenticate(&self, _parts: &Parts) -> Result<Option<Principal>, CryptoServiceError> {
        Ok(None)
    }
}

/// Static bearer-token table (`Authorization: Bearer <token>`).
///
/// Tokens are credentials: they are stored in zeroizing memory, compared in
/// constant time (no early exit on the first differing byte, and every
/// registered token is compared), and never printed. Note that the token
/// bytes in the received header belong to Hyper and are not zeroized.
///
/// Behaviour (WAVE1(auth)):
/// - no `Authorization` header → `Ok(None)` (anonymous);
/// - header present but not `Bearer <token>`, not valid ASCII, or no token
///   matches → `Err(CryptoServiceError::Unauthenticated)`;
/// - match → `Ok(Some(principal.clone()))`.
#[derive(Default)]
pub struct BearerTokens {
    tokens: Vec<(Zeroizing<Box<[u8]>>, Principal)>,
}

impl BearerTokens {
    /// An empty table (every presented token is rejected).
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `token` for `principal`. The token is moved in; its bytes are
    /// copied once into the table's own zeroizing storage.
    pub fn insert(&mut self, token: SecretBytes, principal: Principal) -> &mut Self {
        let stored = Zeroizing::new(Box::<[u8]>::from(token.as_ref()));
        self.tokens.push((stored, principal));
        self
    }
}

impl fmt::Debug for BearerTokens {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BearerTokens([REDACTED; {}])", self.tokens.len())
    }
}

impl Authenticator for BearerTokens {
    fn authenticate(&self, parts: &Parts) -> Result<Option<Principal>, CryptoServiceError> {
        let mut headers = parts.headers.get_all(http::header::AUTHORIZATION).iter();
        let header = match headers.next() {
            None => return Ok(None),
            Some(header) => header,
        };
        if headers.next().is_some() {
            // More than one `Authorization` header: reject rather than pick one.
            return Err(CryptoServiceError::Unauthenticated);
        }

        let value = header
            .to_str()
            .map_err(|_| CryptoServiceError::Unauthenticated)?;
        let presented = value
            .strip_prefix("Bearer ")
            .ok_or(CryptoServiceError::Unauthenticated)?;
        if presented.is_empty() {
            return Err(CryptoServiceError::Unauthenticated);
        }
        let presented = presented.as_bytes();

        // Compare against every registered token, in constant time, without
        // exiting early on the first match, so the response time does not
        // leak which (if any) token matched.
        let mut matched: Option<usize> = None;
        for (index, (stored, _principal)) in self.tokens.iter().enumerate() {
            if ct_eq(stored, presented) {
                matched = Some(index);
            }
        }

        matched
            .and_then(|index| self.tokens.get(index))
            .map(|(_, principal)| Some(principal.clone()))
            .ok_or(CryptoServiceError::Unauthenticated)
    }
}

/// Constant-time byte-slice comparison: always inspects every byte of `a`
/// (the stored token) and never branches on the comparison result before the
/// end, so the timing does not depend on where (or whether) `a` and `b`
/// first differ.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = (a.len() != b.len()) as u8;
    for (i, &byte) in a.iter().enumerate() {
        let other = b.get(i).copied().unwrap_or(0);
        diff |= byte ^ other;
    }
    core::hint::black_box(diff) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parts_with_auth(value: Option<&str>) -> Parts {
        let mut builder = http::Request::builder();
        if let Some(value) = value {
            builder = builder.header(http::header::AUTHORIZATION, value);
        }
        builder.body(()).unwrap().into_parts().0
    }

    fn parts_with_two_auth_headers(a: &str, b: &str) -> Parts {
        let request = http::Request::builder()
            .header(http::header::AUTHORIZATION, a)
            .header(http::header::AUTHORIZATION, b)
            .body(())
            .unwrap();
        request.into_parts().0
    }

    fn table() -> BearerTokens {
        let mut table = BearerTokens::new();
        table.insert(
            SecretBytes::copy_from_slice(b"right-token"),
            Principal::new("alice"),
        );
        table
    }

    #[test]
    fn no_header_is_anonymous() {
        let table = table();
        let parts = parts_with_auth(None);
        assert_eq!(table.authenticate(&parts), Ok(None));
    }

    #[test]
    fn right_token_matches_principal() {
        let table = table();
        let parts = parts_with_auth(Some("Bearer right-token"));
        assert_eq!(
            table.authenticate(&parts),
            Ok(Some(Principal::new("alice")))
        );
    }

    #[test]
    fn wrong_token_is_unauthenticated() {
        let table = table();
        let parts = parts_with_auth(Some("Bearer wrong-token"));
        assert_eq!(
            table.authenticate(&parts),
            Err(CryptoServiceError::Unauthenticated)
        );
    }

    #[test]
    fn wrong_scheme_is_unauthenticated() {
        let table = table();
        let parts = parts_with_auth(Some("Basic right-token"));
        assert_eq!(
            table.authenticate(&parts),
            Err(CryptoServiceError::Unauthenticated)
        );
    }

    #[test]
    fn empty_token_is_unauthenticated() {
        let table = table();
        let parts = parts_with_auth(Some("Bearer "));
        assert_eq!(
            table.authenticate(&parts),
            Err(CryptoServiceError::Unauthenticated)
        );
    }

    #[test]
    fn two_authorization_headers_is_unauthenticated() {
        let table = table();
        let parts = parts_with_two_auth_headers("Bearer right-token", "Bearer right-token");
        assert_eq!(
            table.authenticate(&parts),
            Err(CryptoServiceError::Unauthenticated)
        );
    }

    #[test]
    fn debug_contains_no_token_bytes() {
        let table = table();
        let rendered = format!("{table:?}");
        assert_eq!(rendered, "BearerTokens([REDACTED; 1])");
        assert!(!rendered.contains("right-token"));
    }

    #[test]
    fn ct_eq_matches_and_rejects() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
        assert!(!ct_eq(b"abc", b"abcd"));
    }
}
