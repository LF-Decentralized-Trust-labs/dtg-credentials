//! Verifying a chain of Verifiable Delegation Credentials.
//!
//! # What a VDC chain establishes, and what it does not
//!
//! A delegation chain answers exactly one question: *may this party act in the
//! principal's name, for this act?* It does **not** answer whether the act is permitted.
//! A VDC neither carries authority nor confers it — a verifier substitutes the principal
//! for the delegate and then asks the permission question it would have asked of the
//! principal directly, live, at the time of the act.
//!
//! [`verify_chain`] therefore returns a [`VerifiedDelegation`] naming the principal and
//! the acts the chain appoints for. That is one of two checks. The other — may the
//! *principal* do this? — is the caller's, and a governing party may add a third: whether
//! the delegate must independently qualify. The reach of a delegated act is the
//! **intersection** of what the principal may do and what the chain appoints for; never
//! the union, and never more than either.
//!
//! # Re-delegation is opt-in, unlike attenuation
//!
//! A VAC may be attenuated by default; a VDC may be re-delegated only where its `maxDepth`
//! says so, and absence prohibits it. The asymmetry is deliberate. A delegate speaks in
//! the principal's name, so the principal keeps the register of who may do that and can
//! withdraw any of them; a delegate that needs a further delegate ordinarily asks for a
//! fresh root delegation rather than minting one. Re-delegation exists for when that round
//! trip is unavailable.
//!
//! # Bearer-side resolution
//!
//! As in [`crate::authority`], the holder presents every link and this module never
//! dereferences a `parent` to fetch one. Presenting a derived VDC discloses the whole
//! ancestry, including the principal's identity — which is the other reason a single hop
//! is the default.
//!
//! # Not implemented here
//!
//! **The acceptance.** A delegation edge is complete only when the delegate has
//! countersigned, and a verifier MUST obtain and verify that half before accepting any
//! party as acting under the delegation. This module verifies the grant chain;
//! [`crate::DTGCredential::accepts`] checks an acceptance against its grant, and a
//! verifier needs both.
//!
//! **Revocation.** A VDC's `credentialStatus` is a live lookup this crate does not
//! perform. See [`crate::DTGCommon::credential_status`].
//!
//! **Invocation binding.** A VDC is not a bearer token. Nothing here establishes that the
//! party presenting the chain controls the leaf's `credentialSubject.id`; that
//! demonstration belongs to the trust task in which the delegation is exercised.

use chrono::{DateTime, Utc};

use crate::{DTGCredential, DTGCredentialType};

/// Why a delegation chain was refused.
///
/// Each variant names a specific way of acquiring representation that was not granted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DelegationError {
    /// The chain was empty. Nothing to verify.
    #[error("delegation chain is empty")]
    EmptyChain,

    /// The chain is longer than [MAX_CHAIN_DEPTH].
    #[error("delegation chain is {found} deep, exceeding the maximum of {MAX_CHAIN_DEPTH}")]
    TooDeep { found: usize },

    /// A link was not a DelegationCredential carrying a grant.
    #[error("credential at index {index} is a {found}, not a delegation grant")]
    NotADelegationGrant { index: usize, found: String },

    /// A link carried `accepts`, making it an acceptance rather than a grant.
    ///
    /// An acceptance appoints nobody; it consents to an appointment made elsewhere. A
    /// chain built from them establishes no representation.
    #[error("credential at index {index} is an acceptance, not a grant")]
    AcceptanceInChain { index: usize },

    /// A link's `scope` was empty or absent.
    #[error("delegation at index {index} carries no scope, and so appoints for nothing")]
    NoScope { index: usize },

    /// A link carried no `validUntil`, which a VDC MUST have.
    #[error("VDC at index {index} carries no validUntil, which a VDC MUST have")]
    NoExpiry { index: usize },

    /// A link was outside its validity window at the instant asked about.
    #[error("delegation at index {index} is not valid at {at}")]
    NotValidNow { index: usize, at: DateTime<Utc> },

    /// A link's `parent` did not match the credential presented above it.
    #[error("delegation at index {index} names parent {named}, but {presented} was presented")]
    BrokenLink {
        index: usize,
        named: String,
        presented: String,
    },

    /// A link's digest could not be computed, or one it carries could not be read.
    #[error("digest error at index {index}: {reason}")]
    Digest { index: usize, reason: String },

    /// A link was issued by someone other than the delegate its parent appointed.
    #[error(
        "delegation at index {index} is issued by {issuer}, but its parent appointed {subject}"
    )]
    IssuerNotParentSubject {
        index: usize,
        issuer: String,
        subject: String,
    },

    /// A link appointed for an act absent from its parent's scope.
    #[error("delegation at index {index} adds `{act}`, which its parent does not appoint for")]
    WidensScope { index: usize, act: String },

    /// A link outlived the delegation it derives from.
    #[error(
        "delegation at index {index} is valid until {until}, beyond its parent's {parent_until}"
    )]
    OutlivesParent {
        index: usize,
        until: DateTime<Utc>,
        parent_until: DateTime<Utc>,
    },

    /// A re-delegation was made below a VDC that does not permit one.
    ///
    /// `maxDepth` absent or `0` prohibits it, and there is no other way to authorise one.
    #[error(
        "delegation at index {index} re-delegates below a parent whose maxDepth is {parent_depth}"
    )]
    RedelegationNotPermitted { index: usize, parent_depth: u32 },

    /// A link's `maxDepth` exceeded one less than its parent's.
    #[error(
        "delegation at index {index} bears maxDepth {depth}, above its parent's {parent_depth} - 1"
    )]
    DepthNotNarrowed {
        index: usize,
        depth: u32,
        parent_depth: u32,
    },

    /// The chain's root was not issued by the principal the verifier intends to deal with.
    #[error("chain root is issued by {root_issuer}, not the principal {expected}")]
    RootNotPrincipal {
        root_issuer: String,
        expected: String,
    },

    /// The leaf does not appoint for the act asked about.
    #[error("the delegation does not appoint for `{act}`")]
    ActNotAppointed { act: String },
}

/// Maximum number of VDCs in a chain, including the root delegation.
///
/// The specification bounds depth per-ancestor through `maxDepth` rather than globally,
/// and a conforming chain is bounded by that. This ceiling is a second, blunter bound on
/// the same denial-of-service surface the VAC's has: verification is linear in depth and
/// runs on every presentation.
pub const MAX_CHAIN_DEPTH: usize = 8;

/// What a verified delegation chain establishes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDelegation {
    /// The delegate the chain appoints — the leaf's subject.
    pub delegate: String,

    /// The acts the chain appoints the delegate for, which is never more than the root
    /// delegation conferred.
    pub scope: Vec<String>,

    /// The entity in whose name the acts would be performed, and to whom they are
    /// attributed. The root delegation's issuer.
    pub principal: String,
}

/// Verify a chain of delegation grants and return what it appoints for.
///
/// `chain` is **leaf first**: `chain[0]` is the credential being presented, and the last
/// element must be the root delegation issued by `principal`. Every link the holder relies
/// on must be present — this function never fetches one.
///
/// The signature on each credential is *not* checked here, nor is any acceptance, nor any
/// revocation status. Verify those separately; this function answers whether a set of
/// otherwise valid grants adds up to the representation claimed.
///
/// # This establishes representation, not permission
///
/// A successful return means the delegate may act in `principal`'s name for
/// `requested_act`. Whether *`principal`* may perform that act is a separate question this
/// crate does not answer, and a VDC never influences its outcome.
pub fn verify_chain(
    chain: &[DTGCredential],
    principal: &str,
    requested_act: &str,
    at: DateTime<Utc>,
) -> Result<VerifiedDelegation, DelegationError> {
    if chain.is_empty() {
        return Err(DelegationError::EmptyChain);
    }
    if chain.len() > MAX_CHAIN_DEPTH {
        return Err(DelegationError::TooDeep { found: chain.len() });
    }

    // Every link must be a delegation *grant* carrying a scope and an expiry.
    for (index, link) in chain.iter().enumerate() {
        if !matches!(link.type_(), DTGCredentialType::Delegation) {
            return Err(DelegationError::NotADelegationGrant {
                index,
                found: link.type_().to_string(),
            });
        }
        let grant =
            link.credential()
                .delegation()
                .ok_or_else(|| DelegationError::NotADelegationGrant {
                    index,
                    found: "DelegationCredential without a delegation object".to_string(),
                })?;

        // An acceptance consents to an appointment; it does not make one. A chain of them
        // establishes nothing.
        if grant.accepts.is_some() {
            return Err(DelegationError::AcceptanceInChain { index });
        }
        if grant.scope.as_ref().is_none_or(|s| s.is_empty()) {
            return Err(DelegationError::NoScope { index });
        }

        let c = link.credential();
        if c.valid_from() > at {
            return Err(DelegationError::NotValidNow { index, at });
        }
        // REQUIRED on a VDC: an appointment with no expiry cannot be reasoned about by a
        // verifier that cannot reach the delegator.
        let Some(until) = c.valid_until() else {
            return Err(DelegationError::NoExpiry { index });
        };
        if until < at {
            return Err(DelegationError::NotValidNow { index, at });
        }
    }

    // Walk leaf -> root. Each step checks the link against the credential above it.
    for index in 0..chain.len() - 1 {
        let link = &chain[index];
        let parent = &chain[index + 1];
        let grant = link.credential().delegation().expect("checked above");
        let parent_grant = parent.credential().delegation().expect("checked above");

        // The link must point at the credential presented as its parent, by digest —
        // compared as decoded bytes, never as strings.
        let presented_digest = parent
            .digest_multibase()
            .map_err(|e| DelegationError::Digest {
                index: index + 1,
                reason: e.to_string(),
            })?;
        match &grant.parent {
            Some(named) => {
                let matches = crate::digests_match(named, &presented_digest).map_err(|e| {
                    DelegationError::Digest {
                        index,
                        reason: e.to_string(),
                    }
                })?;
                if !matches {
                    return Err(DelegationError::BrokenLink {
                        index,
                        named: named.clone(),
                        presented: presented_digest,
                    });
                }
            }
            None => {
                // A link with no `parent` claims to be a root delegation, but something
                // was presented above it.
                return Err(DelegationError::BrokenLink {
                    index,
                    named: "<none — link claims to be a root delegation>".to_string(),
                    presented: presented_digest,
                });
            }
        }

        // Only the party a delegation appointed may re-delegate it.
        if link.credential().issuer() != parent.credential().subject() {
            return Err(DelegationError::IssuerNotParentSubject {
                index,
                issuer: link.credential().issuer().to_string(),
                subject: parent.credential().subject().to_string(),
            });
        }

        // Re-delegation must have been authorised, and each step must narrow the budget.
        let parent_depth = parent_grant.max_depth.unwrap_or(0);
        if parent_depth == 0 {
            return Err(DelegationError::RedelegationNotPermitted {
                index,
                parent_depth,
            });
        }
        if let Some(depth) = grant.max_depth
            && depth > parent_depth - 1
        {
            return Err(DelegationError::DepthNotNarrowed {
                index,
                depth,
                parent_depth,
            });
        }

        // Scope is set inclusion over exact matches: the specification defines no wildcard,
        // prefix or hierarchical semantics, so a governing vocabulary wanting structure
        // must put it in the terms themselves.
        let parent_scope = parent_grant.scope.as_deref().expect("checked above");
        for act in grant.scope.as_deref().expect("checked above") {
            if !parent_scope.contains(act) {
                return Err(DelegationError::WidensScope {
                    index,
                    act: act.clone(),
                });
            }
        }

        // Both are present: the loop above rejected any link without one.
        if let (Some(until), Some(parent_until)) = (
            link.credential().valid_until(),
            parent.credential().valid_until(),
        ) && until > parent_until
        {
            return Err(DelegationError::OutlivesParent {
                index,
                until,
                parent_until,
            });
        }
    }

    // The chain must terminate in a root delegation issued by the principal — the entity
    // in whose name the acts would ultimately be performed. A chain that cannot be
    // resolved to such a root establishes no representation.
    let root = chain.last().expect("non-empty");
    let root_grant = root.credential().delegation().expect("checked above");
    if root.credential().issuer() != principal {
        return Err(DelegationError::RootNotPrincipal {
            root_issuer: root.credential().issuer().to_string(),
            expected: principal.to_string(),
        });
    }
    if let Some(named) = &root_grant.parent {
        // The chain was truncated: its "root" derives from something not presented.
        return Err(DelegationError::BrokenLink {
            index: chain.len() - 1,
            named: named.clone(),
            presented: "<nothing — chain ends here>".to_string(),
        });
    }

    let leaf = &chain[0];
    let leaf_grant = leaf.credential().delegation().expect("checked above");
    let scope = leaf_grant.scope.clone().expect("checked above");
    if !scope.iter().any(|a| a == requested_act) {
        return Err(DelegationError::ActNotAppointed {
            act: requested_act.to_string(),
        });
    }

    Ok(VerifiedDelegation {
        delegate: leaf.credential().subject().to_string(),
        scope,
        principal: principal.to_string(),
    })
}
