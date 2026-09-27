//! Authorization policy.
//!
//! A [`PolicyProvider`] wraps any [`CryptoProvider`] and asks an
//! [`Authorizer`] before every operation. The provider never sees an
//! unauthorized request.

use core::task::{Context, Poll};
use std::collections::HashMap;

use crate::{
    error::CryptoServiceError,
    key::KeyNamespace,
    op::{CryptoOperation, CryptoRequest, CryptoResponse, OpKind, Principal, RequestContext},
    provider::CryptoProvider,
};

/// Decides whether a caller may perform an operation.
pub trait Authorizer: Send + 'static {
    /// Return `Ok(())` to allow the operation, or an error (normally
    /// [`CryptoServiceError::Forbidden`] or
    /// [`CryptoServiceError::Unauthenticated`]) to reject it.
    fn authorize(
        &self,
        ctx: &RequestContext,
        op: &CryptoOperation,
    ) -> Result<(), CryptoServiceError>;
}

/// Allows everything. Only for tests and single-tenant, fully trusted setups.
#[derive(Clone, Copy, Debug, Default)]
pub struct AllowAll;

impl Authorizer for AllowAll {
    fn authorize(
        &self,
        _ctx: &RequestContext,
        _op: &CryptoOperation,
    ) -> Result<(), CryptoServiceError> {
        Ok(())
    }
}

/// A provider guarded by an authorizer.
pub struct PolicyProvider<P, A> {
    inner: P,
    authorizer: A,
}

impl<P, A> PolicyProvider<P, A> {
    /// Guard `inner` with `authorizer`.
    pub fn new(inner: P, authorizer: A) -> Self {
        Self { inner, authorizer }
    }

    /// Borrow the guarded provider.
    pub fn inner(&self) -> &P {
        &self.inner
    }

    /// Borrow the authorizer.
    pub fn authorizer(&self) -> &A {
        &self.authorizer
    }
}

impl<P, A> core::fmt::Debug for PolicyProvider<P, A> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PolicyProvider").finish_non_exhaustive()
    }
}

impl<P: CryptoProvider, A: Authorizer> CryptoProvider for PolicyProvider<P, A> {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), CryptoServiceError>> {
        self.inner.poll_ready(cx)
    }

    fn execute(&mut self, request: CryptoRequest) -> Result<CryptoResponse, CryptoServiceError> {
        // Authorize, then delegate. A rejected request is dropped here (its
        // secrets are zeroized on drop) and never reaches `inner`.
        self.authorizer
            .authorize(&request.context, &request.operation)?;
        self.inner.execute(request)
    }
}

/// A set of [`OpKind`]s, used to express grants.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct OpSet(u16);

impl OpSet {
    /// No operations.
    pub const NONE: Self = Self(0);
    /// Read-only, non-secret operations: describe, public key, verify.
    pub const READ_PUBLIC: Self = Self(0)
        .with(OpKind::Describe)
        .with(OpKind::PublicKey)
        .with(OpKind::Verify);
    /// Encrypt and wrap.
    pub const ENCRYPT: Self = Self(0).with(OpKind::Encrypt).with(OpKind::WrapKey);
    /// Secret egress: decrypt and unwrap. Grant deliberately.
    pub const SECRET_EGRESS: Self = Self(0).with(OpKind::Decrypt).with(OpKind::UnwrapKey);
    /// Sign.
    pub const SIGN: Self = Self(0).with(OpKind::Sign);
    /// Rewrap.
    pub const REWRAP: Self = Self(0).with(OpKind::RewrapKey);
    /// Key lifecycle administration: generate, rotate, disable, enable, destroy.
    pub const ADMIN: Self = Self(0)
        .with(OpKind::Generate)
        .with(OpKind::Rotate)
        .with(OpKind::Disable)
        .with(OpKind::Enable)
        .with(OpKind::Destroy);
    /// Every operation.
    pub const ALL: Self = Self::READ_PUBLIC
        .union(Self::ENCRYPT)
        .union(Self::SECRET_EGRESS)
        .union(Self::SIGN)
        .union(Self::REWRAP)
        .union(Self::ADMIN);

    /// The single-operation bit for `op`.
    const fn bit(op: OpKind) -> u16 {
        match op {
            OpKind::Generate => 1 << 0,
            OpKind::Rotate => 1 << 1,
            OpKind::Disable => 1 << 2,
            OpKind::Enable => 1 << 3,
            OpKind::Destroy => 1 << 4,
            OpKind::Describe => 1 << 5,
            OpKind::PublicKey => 1 << 6,
            OpKind::Encrypt => 1 << 7,
            OpKind::Decrypt => 1 << 8,
            OpKind::Sign => 1 << 9,
            OpKind::Verify => 1 << 10,
            OpKind::WrapKey => 1 << 11,
            OpKind::UnwrapKey => 1 << 12,
            OpKind::RewrapKey => 1 << 13,
        }
    }

    /// This set plus `op`.
    pub const fn with(self, op: OpKind) -> Self {
        Self(self.0 | Self::bit(op))
    }

    /// Union of two sets.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Whether `op` is in the set.
    pub const fn contains(self, op: OpKind) -> bool {
        self.0 & Self::bit(op) != 0
    }
}

/// Grants per principal and namespace.
///
/// Deny by default: anonymous callers get [`CryptoServiceError::Unauthenticated`],
/// known callers without a matching grant get [`CryptoServiceError::Forbidden`].
/// An operation touching several namespaces (rewrap) needs a grant in each.
/// Rewrapping into a namespace where the caller holds `UnwrapKey` also
/// requires `UnwrapKey` on the source namespace, because the result could be
/// unwrapped right away (rewrap must never widen secret egress).
#[derive(Debug, Default)]
pub struct NamespacePolicy {
    grants: HashMap<Principal, HashMap<KeyNamespace, OpSet>>,
}

impl NamespacePolicy {
    /// An empty (deny-all) policy.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add `ops` for `principal` in `namespace` (merged with earlier grants).
    pub fn grant(
        &mut self,
        principal: Principal,
        namespace: KeyNamespace,
        ops: OpSet,
    ) -> &mut Self {
        let existing = self
            .grants
            .entry(principal)
            .or_default()
            .entry(namespace)
            .or_insert(OpSet::NONE);
        *existing = existing.union(ops);
        self
    }

    /// The operations `principal` may perform in `namespace`.
    pub fn allowed(&self, principal: &Principal, namespace: &KeyNamespace) -> OpSet {
        self.grants
            .get(principal)
            .and_then(|by_ns| by_ns.get(namespace))
            .copied()
            .unwrap_or(OpSet::NONE)
    }
}

impl Authorizer for NamespacePolicy {
    fn authorize(
        &self,
        ctx: &RequestContext,
        op: &CryptoOperation,
    ) -> Result<(), CryptoServiceError> {
        let principal = ctx
            .principal
            .as_ref()
            .ok_or(CryptoServiceError::Unauthenticated)?;
        let kind = op.kind();
        for namespace in op.namespaces().into_iter().flatten() {
            if !self.allowed(principal, namespace).contains(kind) {
                return Err(CryptoServiceError::Forbidden);
            }
        }
        // Rewrapping into a namespace where the caller may unwrap is
        // equivalent to unwrapping from the source namespace, so it requires
        // secret egress (UnwrapKey) on the source as well. Otherwise a REWRAP
        // grant on a shared namespace would leak key material into any
        // namespace the caller controls.
        if let CryptoOperation::RewrapKey(op) = op {
            let can_unwrap_target = self
                .allowed(principal, &op.to.namespace)
                .contains(OpKind::UnwrapKey);
            let can_unwrap_source = self
                .allowed(principal, &op.from.namespace)
                .contains(OpKind::UnwrapKey);
            if can_unwrap_target && !can_unwrap_source {
                return Err(CryptoServiceError::Forbidden);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        blob::CiphertextBlob,
        key::{KeyId, KeyRef},
        op::{DescribeKey, RequestId, RewrapKey},
    };

    fn ns(name: &str) -> KeyNamespace {
        KeyNamespace::new(name).unwrap()
    }

    fn key(namespace: &str, id: &str) -> KeyRef {
        KeyRef::latest(ns(namespace), KeyId::new(id).unwrap())
    }

    fn describe(namespace: &str, id: &str) -> CryptoOperation {
        CryptoOperation::Describe(DescribeKey {
            key: key(namespace, id),
        })
    }

    #[test]
    fn opset_algebra() {
        assert!(OpSet::READ_PUBLIC.contains(OpKind::Describe));
        assert!(OpSet::READ_PUBLIC.contains(OpKind::PublicKey));
        assert!(OpSet::READ_PUBLIC.contains(OpKind::Verify));
        assert!(!OpSet::READ_PUBLIC.contains(OpKind::Decrypt));

        assert!(OpSet::NONE.with(OpKind::Sign).contains(OpKind::Sign));
        assert!(!OpSet::NONE.contains(OpKind::Sign));

        let union = OpSet::READ_PUBLIC.union(OpSet::SIGN);
        assert!(union.contains(OpKind::Describe));
        assert!(union.contains(OpKind::Sign));
        assert!(!union.contains(OpKind::Decrypt));

        for kind in [
            OpKind::Generate,
            OpKind::Rotate,
            OpKind::Disable,
            OpKind::Enable,
            OpKind::Destroy,
            OpKind::Describe,
            OpKind::PublicKey,
            OpKind::Encrypt,
            OpKind::Decrypt,
            OpKind::Sign,
            OpKind::Verify,
            OpKind::WrapKey,
            OpKind::UnwrapKey,
            OpKind::RewrapKey,
        ] {
            assert!(OpSet::ALL.contains(kind));
        }
    }

    #[test]
    fn deny_by_default() {
        let policy = NamespacePolicy::new();
        let principal = Principal::new("alice");
        let namespace = ns("team-a");
        assert_eq!(policy.allowed(&principal, &namespace), OpSet::NONE);
    }

    #[test]
    fn anonymous_is_unauthenticated() {
        let mut policy = NamespacePolicy::new();
        policy.grant(Principal::new("alice"), ns("team-a"), OpSet::READ_PUBLIC);

        let ctx = RequestContext::anonymous(RequestId(1));
        let op = describe("team-a", "k1");
        assert_eq!(
            policy.authorize(&ctx, &op),
            Err(CryptoServiceError::Unauthenticated)
        );
    }

    #[test]
    fn known_principal_without_grant_is_forbidden() {
        let policy = NamespacePolicy::new();
        let ctx = RequestContext {
            request_id: RequestId(1),
            principal: Some(Principal::new("alice")),
        };
        let op = describe("team-a", "k1");
        assert_eq!(
            policy.authorize(&ctx, &op),
            Err(CryptoServiceError::Forbidden)
        );
    }

    #[test]
    fn grant_allows_matching_operation() {
        let mut policy = NamespacePolicy::new();
        policy.grant(Principal::new("alice"), ns("team-a"), OpSet::READ_PUBLIC);

        let ctx = RequestContext {
            request_id: RequestId(1),
            principal: Some(Principal::new("alice")),
        };
        let op = describe("team-a", "k1");
        assert_eq!(policy.authorize(&ctx, &op), Ok(()));
    }

    #[test]
    fn grant_merges_with_existing() {
        let mut policy = NamespacePolicy::new();
        let principal = Principal::new("alice");
        let namespace = ns("team-a");
        policy.grant(principal.clone(), namespace.clone(), OpSet::READ_PUBLIC);
        policy.grant(principal.clone(), namespace.clone(), OpSet::SIGN);

        let allowed = policy.allowed(&principal, &namespace);
        assert!(allowed.contains(OpKind::Describe));
        assert!(allowed.contains(OpKind::Sign));
    }

    #[test]
    fn rewrap_needs_both_namespaces() {
        let mut policy = NamespacePolicy::new();
        let principal = Principal::new("alice");
        policy.grant(principal.clone(), ns("from-ns"), OpSet::REWRAP);
        // No grant in "to-ns" yet.

        let ctx = RequestContext {
            request_id: RequestId(1),
            principal: Some(principal.clone()),
        };
        let op = CryptoOperation::RewrapKey(RewrapKey {
            from: key("from-ns", "k1"),
            from_context: Default::default(),
            to: key("to-ns", "k2"),
            to_context: Default::default(),
            wrapped: CiphertextBlob::new(Vec::new()),
        });
        assert_eq!(
            policy.authorize(&ctx, &op),
            Err(CryptoServiceError::Forbidden)
        );

        policy.grant(principal, ns("to-ns"), OpSet::REWRAP);
        assert_eq!(policy.authorize(&ctx, &op), Ok(()));
    }

    /// Test-only provider that records whether `execute` was called, so
    /// tests can assert a rejected request never reaches it.
    #[derive(Default)]
    struct RecordingProvider {
        called: bool,
    }

    impl CryptoProvider for RecordingProvider {
        fn execute(
            &mut self,
            _request: CryptoRequest,
        ) -> Result<CryptoResponse, CryptoServiceError> {
            self.called = true;
            Err(CryptoServiceError::Unsupported)
        }
    }

    /// Test-only authorizer that always rejects.
    struct DenyAll;

    impl Authorizer for DenyAll {
        fn authorize(
            &self,
            _ctx: &RequestContext,
            _op: &CryptoOperation,
        ) -> Result<(), CryptoServiceError> {
            Err(CryptoServiceError::Forbidden)
        }
    }

    #[test]
    fn rejected_request_never_reaches_inner() {
        let mut provider = PolicyProvider::new(RecordingProvider::default(), DenyAll);
        let request = CryptoRequest::new(RequestId(1), describe("team-a", "k1"));
        let result = provider.execute(request);
        assert!(matches!(result, Err(CryptoServiceError::Forbidden)));
        assert!(!provider.inner().called);
    }

    #[test]
    fn allowed_request_reaches_inner() {
        let mut provider = PolicyProvider::new(RecordingProvider::default(), AllowAll);
        let request = CryptoRequest::new(RequestId(1), describe("team-a", "k1"));
        let _ = provider.execute(request);
        assert!(provider.inner().called);
    }

    #[test]
    fn rewrap_into_unwrappable_namespace_requires_source_egress() {
        use crate::{op::RewrapKey, CiphertextBlob, CryptoContext, KeyId, KeyRef, RequestId};

        let shared = KeyNamespace::new("shared").unwrap();
        let own = KeyNamespace::new("mallory-ns").unwrap();
        let mallory = Principal::new("mallory");
        let op = CryptoOperation::RewrapKey(RewrapKey {
            from: KeyRef::latest(shared.clone(), KeyId::new("k").unwrap()),
            from_context: CryptoContext::default(),
            to: KeyRef::latest(own.clone(), KeyId::new("mk").unwrap()),
            to_context: CryptoContext::default(),
            wrapped: CiphertextBlob::new(Vec::new()),
        });
        let ctx = RequestContext {
            request_id: RequestId(1),
            principal: Some(mallory.clone()),
        };

        let mut policy = NamespacePolicy::new();
        policy
            .grant(mallory.clone(), shared.clone(), OpSet::REWRAP)
            .grant(mallory.clone(), own.clone(), OpSet::ALL);
        assert_eq!(
            policy.authorize(&ctx, &op),
            Err(CryptoServiceError::Forbidden)
        );

        // With egress on the source as well, rewrap is no escalation.
        policy.grant(mallory.clone(), shared.clone(), OpSet::SECRET_EGRESS);
        assert_eq!(policy.authorize(&ctx, &op), Ok(()));

        // Rewrapping into a namespace without unwrap rights stays allowed.
        let escrow = KeyNamespace::new("escrow").unwrap();
        let mut policy = NamespacePolicy::new();
        policy.grant(mallory.clone(), shared, OpSet::REWRAP).grant(
            mallory,
            escrow.clone(),
            OpSet::REWRAP,
        );
        let op = match op {
            CryptoOperation::RewrapKey(mut r) => {
                r.to = KeyRef::latest(escrow, KeyId::new("ek").unwrap());
                CryptoOperation::RewrapKey(r)
            }
            _ => unreachable!(),
        };
        assert_eq!(policy.authorize(&ctx, &op), Ok(()));
    }
}
