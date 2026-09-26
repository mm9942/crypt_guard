//! Reference KMS route table.
//!
//! ```text
//! POST /v1/keys                                  generate
//! GET  /v1/keys/{namespace}/{id}[@version]         describe
//! GET  /v1/keys/{namespace}/{id}[@version]/public  public key
//! POST /v1/keys/{namespace}/{id}[@version]:{op}    encrypt | decrypt | sign | verify |
//!                                                rotate | disable | enable | destroy |
//!                                                wrap | unwrap | rewrap
//! ```
//!
//! Key names only contain `[A-Za-z0-9._-]`, so `@` and `:` are unambiguous
//! separators and no percent-decoding is needed.

use http::Method;

use crypt_guard_service::{KeyId, KeyNamespace, KeyRef, KeyVersion};

use crate::config::BodyLimits;

/// A KMS operation addressed by a route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteOp {
    /// `POST /v1/keys`
    Generate,
    /// `GET /v1/keys/{key}`
    Describe,
    /// `GET /v1/keys/{key}/public`
    PublicKey,
    /// `POST …:encrypt`
    Encrypt,
    /// `POST …:decrypt`
    Decrypt,
    /// `POST …:sign`
    Sign,
    /// `POST …:verify`
    Verify,
    /// `POST …:rotate`
    Rotate,
    /// `POST …:disable`
    Disable,
    /// `POST …:enable`
    Enable,
    /// `POST …:destroy`
    Destroy,
    /// `POST …:wrap`
    Wrap,
    /// `POST …:unwrap`
    Unwrap,
    /// `POST …:rewrap`
    Rewrap,
}

impl RouteOp {
    fn from_verb(verb: &str) -> Option<Self> {
        Some(match verb {
            "encrypt" => Self::Encrypt,
            "decrypt" => Self::Decrypt,
            "sign" => Self::Sign,
            "verify" => Self::Verify,
            "rotate" => Self::Rotate,
            "disable" => Self::Disable,
            "enable" => Self::Enable,
            "destroy" => Self::Destroy,
            "wrap" => Self::Wrap,
            "unwrap" => Self::Unwrap,
            "rewrap" => Self::Rewrap,
            _ => return None,
        })
    }

    /// Maximum body size for this operation.
    pub fn body_limit(self, limits: &BodyLimits) -> usize {
        match self {
            Self::Generate
            | Self::Describe
            | Self::PublicKey
            | Self::Rotate
            | Self::Disable
            | Self::Enable
            | Self::Destroy => limits.metadata,
            Self::Sign | Self::Verify => limits.sign,
            Self::Encrypt | Self::Decrypt => limits.crypt,
            Self::Wrap | Self::Unwrap | Self::Rewrap => limits.import,
        }
    }
}

/// A matched route.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Route {
    /// The operation.
    pub op: RouteOp,
    /// The addressed key; `None` only for [`RouteOp::Generate`].
    pub key: Option<KeyRef>,
}

/// Why a request did not match a route.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RouteError {
    /// No such route.
    NotFound,
    /// The path exists but not for this method.
    MethodNotAllowed,
    /// The path matched but the key name or version is invalid.
    InvalidKey,
}

impl core::fmt::Display for RouteError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::NotFound => "no such route",
            Self::MethodNotAllowed => "method not allowed",
            Self::InvalidKey => "invalid key",
        })
    }
}

impl core::fmt::Debug for RouteError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "RouteError({self})")
    }
}

impl std::error::Error for RouteError {}

const PREFIX: &str = "/v1/keys";

/// Match a method and path against the route table.
pub fn parse(method: &Method, path: &str) -> Result<Route, RouteError> {
    let rest = path.strip_prefix(PREFIX).ok_or(RouteError::NotFound)?;

    if rest.is_empty() || rest == "/" {
        return if method == Method::POST {
            Ok(Route {
                op: RouteOp::Generate,
                key: None,
            })
        } else {
            Err(RouteError::MethodNotAllowed)
        };
    }

    let rest = rest.strip_prefix('/').ok_or(RouteError::NotFound)?;
    let mut segments = rest.split('/');
    let namespace = segments.next().ok_or(RouteError::NotFound)?;
    let key_segment = segments.next().ok_or(RouteError::NotFound)?;
    let tail = segments.next();
    if segments.next().is_some() {
        return Err(RouteError::NotFound);
    }

    let (key_part, verb) = match key_segment.split_once(':') {
        Some((key, verb)) => (key, Some(verb)),
        None => (key_segment, None),
    };

    let (op, expected_method) = match (verb, tail) {
        (None, None) => (RouteOp::Describe, Method::GET),
        (None, Some("public")) => (RouteOp::PublicKey, Method::GET),
        (Some(verb), None) => (
            RouteOp::from_verb(verb).ok_or(RouteError::NotFound)?,
            Method::POST,
        ),
        _ => return Err(RouteError::NotFound),
    };
    if method != expected_method {
        return Err(RouteError::MethodNotAllowed);
    }

    let key = parse_key(namespace, key_part)?;
    Ok(Route { op, key: Some(key) })
}

fn parse_key(namespace: &str, key_part: &str) -> Result<KeyRef, RouteError> {
    let namespace = KeyNamespace::new(namespace).map_err(|_| RouteError::InvalidKey)?;
    let (id, version) = match key_part.split_once('@') {
        Some((id, version)) => {
            let version: u32 = version.parse().map_err(|_| RouteError::InvalidKey)?;
            (
                id,
                Some(KeyVersion::new(version).map_err(|_| RouteError::InvalidKey)?),
            )
        }
        None => (key_part, None),
    };
    let id = KeyId::new(id).map_err(|_| RouteError::InvalidKey)?;
    Ok(KeyRef {
        namespace,
        id,
        version,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(route: &Route) -> String {
        route.key.as_ref().unwrap().to_string()
    }

    #[test]
    fn matches_reference_routes() {
        let r = parse(&Method::POST, "/v1/keys").unwrap();
        assert_eq!((r.op, r.key), (RouteOp::Generate, None));

        let r = parse(&Method::GET, "/v1/keys/app/k1").unwrap();
        assert_eq!((r.op, key(&r).as_str()), (RouteOp::Describe, "app/k1"));

        let r = parse(&Method::GET, "/v1/keys/app/k1@3/public").unwrap();
        assert_eq!((r.op, key(&r).as_str()), (RouteOp::PublicKey, "app/k1@3"));

        let r = parse(&Method::POST, "/v1/keys/app/k1:decrypt").unwrap();
        assert_eq!((r.op, key(&r).as_str()), (RouteOp::Decrypt, "app/k1"));
    }

    #[test]
    fn rejects_unknown_and_invalid() {
        assert_eq!(parse(&Method::GET, "/v2/keys"), Err(RouteError::NotFound));
        assert_eq!(
            parse(&Method::POST, "/v1/keys/app/k1:explode"),
            Err(RouteError::NotFound)
        );
        assert_eq!(
            parse(&Method::GET, "/v1/keys/app/k1/x/y"),
            Err(RouteError::NotFound)
        );
        assert_eq!(
            parse(&Method::DELETE, "/v1/keys/app/k1"),
            Err(RouteError::MethodNotAllowed)
        );
        assert_eq!(
            parse(&Method::GET, "/v1/keys"),
            Err(RouteError::MethodNotAllowed)
        );
        assert_eq!(
            parse(&Method::GET, "/v1/keys/app/k%201"),
            Err(RouteError::InvalidKey)
        );
        assert_eq!(
            parse(&Method::GET, "/v1/keys/app/k1@0"),
            Err(RouteError::InvalidKey)
        );
    }
}
