# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.9.0] - 2026-09-09

**Two additions from the conformance audit in #10**, which the Working Draft 02 work
closed without. Both are additive: no API breaks, and nothing changes on the wire for a
credential that does not use them.

### Added — `credentialStatus` can be set on a credential being built

[`DTGCredential::with_credential_status`] and its non-consuming `set_credential_status`
attach the status mechanism through which a verifier determines whether a credential has
been revoked. `DTGCommon::credential_status` has been modelled since 0.7.0, but only so
that an entry already on the wire survived a round trip without changing the digest — a
credential built by one of the `new_*` constructors had no way to acquire one short of
reaching through `credential_mut`.

This is CONDITIONAL on a VDC rather than required, which is why it is a setter and not a
constructor parameter. A verifier must be able to establish that an appointment is in force
without contacting the delegator, and either of two things satisfies that: a `validUntil`
short enough that expiry alone bounds the exposure, or a status entry it can check. A VDC
MUST carry one where its validity exceeds the freshness window the governing VTC or VTN
defines for delegations, and MAY omit it otherwise. That window is governance this library
does not know, so it cannot decide which side of the condition a given VDC falls on;
demanding the entry from every caller would forbid the short-validity case the
specification prefers.

Neither `delegation::verify_chain` nor `authority::verify_chain` resolves the entry.
Revocation remains a live lookup the caller performs.

### Added — `PartialEq` on `DTGCredentialType`

Consumers had to assert by pattern (`matches!`) rather than by equality; `assert_eq!` now
works and reports the actual variant when it fails. `Eq` is derived alongside it.

## [0.8.0] - 2026-09-09

**A VAC is not a bearer credential.** This release implements the rule and removes the
field that was standing in for it.

### Changed — `verify_chain` requires the presenter to be the leaf's subject (breaking)

`authority::verify_chain` already took a `presenter`, and used it for one thing: comparing
it against the leaf's optional `audience`. A leaf without an `audience` was therefore
accepted from **anybody**, which made a captured presentation a bearer token — the chain
names what may be done, not who is doing it.

It now requires the leaf to grant to `presenter`, and refuses otherwise with the new
`AuthorityError::NotThePresenter`. This is the rule
[PR #41](https://github.com/trustoverip/dtgwg-cred-spec/pull/41) states normatively: a
verifier MUST NOT accept a party as holding the authority a VAC confers unless that party
demonstrates control of the verification method associated with the presented VAC's
`credentialSubject.id`. Only the leaf's subject demonstrates anything — the links above it
are not present and are asked for nothing, which is what keeps attenuation working.

Both known consumers were already doing this by hand, having each hit the gap
independently: `vti-rooms-dtg`'s chain verifier and its nomination check both call
`verify_chain` and then re-compare the subject themselves, with a comment explaining why
they must. Two copies of a check is one place for it to be forgotten, so it moves here.

`presenter` must be an identifier whose key control the caller has already established for
that request. Passing a value read out of the request body reduces the check to a string
comparison an attacker chooses both sides of.

### Removed — `authority.audience` (breaking, on the wire and in the API)

Gone from `AuthorityGrant`, from `attenuate` and `attenuate_from_json` (which each lose
their trailing `Option<String>` parameter), and from the verifier along with
`AuthorityError::WrongAudience`.

Once the presenter must be the subject, an `audience` can only name that same subject —
adding nothing — or name somebody else, which no presentation can ever satisfy. PR #41
removes it for exactly that reason, and it is removed here rather than kept as a weaker
second check.

The property was also being read two incompatible ways, which is what brought this
forward: this library compared it to the **presenter**, while
`trusttasks.org/spec/rooms/keys/present/0.1` described it as the party the presentation is
**for** — "a host's identifier, normally". An implementation that followed the registry
minted leaves the verifier refused every time. See
[dtgwg-trust-tasks-tf#414](https://github.com/trustoverip/dtgwg-trust-tasks-tf/issues/414).
The destination question is real and is answered one layer up, by the trust task
document's `recipient` member, which its `proof` covers.

**Migrating.** Drop the final argument from `attenuate`/`attenuate_from_json` calls. Where
you passed the agent's DID, it was already redundant with `subject`. Where you passed a
verifier's or host's identifier, that binding now belongs on the request document, not the
credential. Callers already comparing the leaf's subject to the presenter can delete that
check.


## [0.7.0] - 2026-09-08

Brings the library up to **Working Draft 02** of the DTG Core Credentials
specification. Both drafts the 0.6.0 release tracked have merged — the VAC as PR #29 and
the VDC as PR #19 — and the digest encoding changed underneath them. This release is
breaking on the wire as well as in the API.

### Changed — the digest encoding (breaking, on the wire)

Working Draft 02 replaced the `sha256:<lowercase hex>` digest with a **base58btc
multibase multihash**, and renamed the property that carries it from `digest` to
`digestMultibase`. Every cross-credential reference in the specification now uses that one
encoding: the member-issued VMC's digest of the grant it acknowledges, the VWC's of the
edge credential it attests, a VAC's `authority.parent`, and a VDC's `delegation.parent`
and `delegation.accepts`.

- `DTGCredential::digest_multibase` is the conformant digest, and now excludes the
  top-level `proof` — it previously included it, which is why it was deprecated. It is
  un-deprecated. `digest_multibase_json` is its wire-form counterpart.
- `DTGCredential::digest` and `digest_json` are **deprecated**. They still emit the
  Working Draft 01 form, unchanged, so a caller migrating can recompute an old digest to
  compare against one they stored.
- `CredentialSubjectMembership::digest` and `CredentialSubjectWitness::digest` are renamed
  to `digest_multibase`, serializing as `digestMultibase`. The old property name `digest`
  is still **accepted when parsing**, so credentials issued against Working Draft 01 still
  deserialize. Their *values* do not compare — an old digest reaching a new verifier fails
  with `InvalidDigest` rather than as a silent mismatch, which is the intended outcome.
- **Digests are compared as decoded bytes, never as strings.** The specification requires
  it, because one digest has more than one spelling, and a string comparison would report
  a mismatch where the two credentials agree. `verify_digest`, `acknowledges` and chain
  verification all decode. `digests_match` and `decode_digest_multibase` are public for
  callers doing the comparison themselves.
- A digest naming a hash algorithm this library does not implement is **rejected**
  (`UnsupportedDigestAlgorithm`) rather than treated as a mismatch. A governing party may
  require a stronger hash, and a verifier that conflated the two would silently downgrade
  that choice into a failed comparison.

### Changed — `authority.parent` is a digest, not an `id` (breaking)

An attenuated VAC now names its parent by digest. This is the change with the most
reasoning behind it in the specification, and it is worth restating: a digest names
nothing that can be fetched. Verification cannot come to depend on network availability,
a verifier cannot be induced to make a request against an address of the *holder's*
choosing, and nobody hosting an identifier learns when a credential is used.

It also binds a link to the exact claims its issuer narrowed from. Re-issuing a parent
with different claims orphans the VACs attenuated from it — each must be re-derived, which
for a chain of narrowing authority is the intended behaviour — while re-proofing it with
identical claims leaves them undisturbed, because the digest excludes `proof`.

- `DTGCredential::attenuate` no longer requires the parent to carry an `id`, and
  `DTGCredentialError::AttenuationParentHasNoId` is deprecated and never returned. Not
  needing a top-level identifier merely in order to be referenced is precisely what the
  change was for.
- `DTGCredential::attenuate_from_json` is new: attenuate a VAC that **arrived from a
  counterparty**, digesting the bytes received rather than a re-serialisation of the
  parse. The same distinction `new_member_vmc` has always drawn.
- `authority::AuthorityError::Digest` is new, for a digest that cannot be *read*. Distinct
  from `BrokenLink` on purpose: a malformed chain and a widening one are different
  findings, and a verifier that reported one as the other would mislead whoever reads the
  log.

### Added — the VDC, which was previously a type name and nothing else

0.6.0 shipped `new_vdc` as a `DelegationCredential` type string over a bare subject. It
carried no `delegation` object, formed no edge, and had no chain verification. All of that
is now implemented.

- `DelegationGrant` and `CredentialSubject::Delegation`: `scope`, `parent`, `maxDepth`,
  `accepts`.
- `DTGCredential::new_vdc` now takes the appointment: a non-empty `scope`, a required
  `valid_until`, and an optional `max_depth`. **Signature change.**
- `DTGCredential::new_delegate_vdc` — the delegate's **acceptance**, built from the
  grant's wire form. The acceptance is REQUIRED: a grant alone establishes what the
  delegator appointed, not what the delegate agreed to, and a delegator cannot produce the
  countersignature. Same consent rule as a membership edge, for the same reason.
- `DTGCredential::accepts` — the delegation counterpart of `acknowledges`: checks the
  digest *and* that the two halves are the right types and name the same parties in
  mirrored roles.
- `DTGCredential::redelegate` and `redelegate_from_json`. Re-delegation is **opt-in**,
  the opposite default from a VAC's attenuation. A delegate speaks in the principal's
  name, so the principal keeps the register of who may do so; absence of `maxDepth`
  prohibits it, and setting it above zero is the delegator's only way to authorise one.
- `delegation::verify_chain` — scope subset, expiry not beyond the parent's, each link
  issued by its parent's delegate, depth budget narrowing on the way down, and a chain
  terminating in a root delegation issued by the principal.

  It returns what the chain **appoints** for, and deliberately not whether the act is
  permitted. A VDC moves the permission question; it does not answer it. Whether the
  *principal* may perform the act is the caller's check, against whatever the act requires
  of them — and the reach of a delegated act is the intersection of the two, never the
  union.

### Changed — `validUntil` is REQUIRED on a VAC and a VDC (breaking)

`new_vac`, `attenuate`, `new_vdc` and the delegation constructors take a
`DateTime<Utc>` rather than an `Option`, and both chain verifiers reject a link without
one (`NoExpiry`). For a VAC the reasoning is sharper than for a VDC: nothing about the
subject's current standing is consulted when one is verified, so authority that does not
expire is authority nobody can withdraw by waiting.

### Added — `credentialStatus`, and unmodelled members survive a round trip

`DTGCommon::credential_status` is modelled, and `DTGCommon::extra` captures top-level
members this library does not name at all. Both exist for the same reason: a
parse-then-re-serialise used to drop them silently, changing a credential's digest.

This narrows, but does not close, the "digest what you received" hazard — a timestamp is
still normalized on the way out, so `2026-01-06T10:00:00.000+00:00` and the
`2026-01-06T10:00:00Z` this library re-emits are the same instant and different bytes.
The wire-form constructors remain the safe habit, and there is a test pinning exactly
that.

Status is modelled but **not resolved**: no revocation checking is performed anywhere in
this crate.

### Fixed

- `new_member_vmc` probed `credentialSubject` for `digest` when deciding whether it had
  been handed a grant or an acknowledgement. After the rename it would have accepted an
  acknowledgement as a grant, and acknowledging one forms no edge. It now probes both
  spellings.

### Notes — what is deliberately not implemented

Three changes to the VAC are in flight upstream and are not here. `audience` is kept
until the last of them lands, rather than removing a shipped field twice.
*(Superseded by 0.8.0, which implements PR #41 and removes `audience`.)*

- Revocation via `credentialStatus`, cascading to everything attenuated below
  ([PR #39](https://github.com/trustoverip/dtgwg-cred-spec/pull/39)).
- A `maxAttenuation` ceiling, bounding depth per-ancestor rather than only globally
  ([PR #40](https://github.com/trustoverip/dtgwg-cred-spec/pull/40)).
- Key control at invocation, which **removes `audience`** as redundant
  ([PR #41](https://github.com/trustoverip/dtgwg-cred-spec/pull/41)). Neither chain
  verifier establishes that the party presenting a chain controls the leaf's subject
  identifier; a VAC and a VDC are both non-bearer, and that demonstration belongs to the
  trust task in which they are exercised.

Correlation scope (PR #30) retired the R-DID / M-DID / C-DID / P-DID identifier types in
favour of a holder-declared `pairwise` | `directed` | `public`. Nothing to implement yet —
the specification has not named the property that carries the declaration — so this
release only drops the retired names from the documentation.

### Changed — dependencies

- Dependencies updated to their current releases. Three are semver-major: `sha2` 0.10 → 0.11,
  and — dev-only — `chacha20poly1305` 0.10 → 0.11 and `rand` 0.8 → 0.10. The `sha2` bump is
  the one worth noting: `affinidi-data-integrity` already pulls `sha2` 0.11 through
  `affinidi-crypto`, so the library was linking two copies of it and hashing with the older
  one. The library graph now carries a single `sha2`. Digest output is unchanged — the tests
  that pin known digests pass untouched.
- `affinidi-tdk` 0.10 → 0.12 (dev-dependency; the examples' DIDs and signing).
- The `data_room` example moves to the `rand` 0.10 API (`rand::rng()`, `rand::Rng`) and off
  the now-deprecated `Key::from_slice`/`Nonce::from_slice` in `chacha20poly1305`.

## [0.6.0] - 2026-09-03

Adds the two credentials that confer rather than assert: the **VAC** (verifiable authority
credential) and the **VDC** (verifiable delegation credential). Both track drafts —
`trustoverip/dtgwg-cred-spec` PR #29 and #19 respectively — and their shapes may move before
those are approved. They are marked as such in the API docs.

### Added

- `DTGCredentialType::{Authority, Delegation}`, `CredentialSubject::Authority`, and the
  `AuthorityGrant` object it carries: `scope`, `actions`, and the optional `parent` and
  `audience` that make attenuation work.
- `DTGCredential::{new_vac, new_vdc}`, following the existing `new_v*` constructors.
- `DTGCredential::attenuate` — derive a narrower VAC from one you hold, without the issuer.
  This is what lets a member equip an agent with four hours of read-only access instead of
  lending it their own standing authority.
- `authority::verify_chain` — **the part that matters.** Issuing a VAC is a struct and a
  signature; what stops a holder acquiring authority they were never given is a verifier
  refusing a chain that widens. Anyone can mint a well-formed VAC naming any scope and any
  actions, and it will verify perfectly as a *credential*. What makes it worthless is that
  its chain does not reach the party governing the scope.

  Seven rules, each closing one way of getting more than was granted: the chain must reach a
  root issued by the governing party; no link may add an action, widen scope, or outlive its
  parent; each link's issuer must be its parent's subject (so a grant cannot be grafted onto
  someone else's chain); `audience`, where set, must be the presenter; and depth is bounded
  at 8, because verification is linear and runs on every presentation.

- `DTGCommon::{authority, authority_mut}` accessors. The mutable one exists so tests can
  build chains `attenuate` would refuse — nothing stops another implementation emitting such
  JSON, so the verifier must be tested against it directly.

### Notes

- **Resolution is bearer-side.** `verify_chain` takes the whole chain as a slice and never
  dereferences `parent` to fetch a link it was not given. Deliberate: resolving over the
  network would make verification depend on availability, turn every `id` into a request the
  verifier can be induced to make against an address the *holder* chooses, and signal
  credential use to whoever hosts the identifier. `id` values are identifiers, not locators.
- **An empty `actions` list confers nothing, not everything.** Refused by the constructor and
  at the deserialization boundary, so it cannot be reached either way.
- `DTGCredentialType` is `#[non_exhaustive]`, so the two new variants are not a breaking
  change for callers matching with a wildcard arm. Callers matching exhaustively need one arm
  each.

### Fixed

- Both examples now declare `required-features = ["affinidi-signing"]`. A
  `--no-default-features` build previously failed on them while the library
  itself compiled fine, and the error named `.sign()` rather than the disabled
  backend

## [0.5.0] - 2026-08-30

`new_member_vmc` in 0.4.0 took a parsed `DTGCredential` and digested it. That is wrong for
the case it exists to serve. `DTGCommon` does not model `credentialStatus`, which every VMC
issued against a status list carries, so parsing a *received* grant and re-serialising it
drops that member — and the acknowledgement went out carrying a digest over a document the
community never issued. Both credentials verify; only the digest comparison fails, with
nothing in either to say why.

### Added

- `digest_json()`, the digest computed over a credential in its **wire form**. This is the
  one to use for anything received. `DTGCredential::digest()` now delegates to it and is
  documented as safe only for a credential built in-process

### Changed

- **BREAKING:** `DTGCredential::new_member_vmc()` takes the grant as `&serde_json::Value`
  — the JSON the community sent — rather than a parsed `DTGCredential`, and reads the
  member, the community and the digest from it. Its errors are now all
  `NotAMembershipGrant`, naming which part of the document was missing or wrong


## [0.4.0] - 2026-08-30

Membership is a **pair** of VMCs, and this release is what makes the second one
expressible. DTG Core Credentials defines a community-issued VMC (the membership grant) and
a member-issued VMC (the acknowledgement) whose `credentialSubject.digest` binds it to the
grant; a member-issued VMC whose digest matches no valid grant MUST NOT be treated as
completing a membership edge. This library could not represent that: `CredentialSubjectBasic`
is `deny_unknown_fields` over `id` alone, so an acknowledgement carrying a digest could not
be built or deserialized as a VMC at all.

### Added

- `DTGCredential::new_member_vmc()` builds the member-issued half from the grant it
  acknowledges, computing the digest and reading both parties off the grant — so the two
  halves cannot disagree about who they are between. Refuses anything that is not a
  community-issued grant
- `DTGCredential::acknowledges()` answers whether a member-issued VMC completes a given
  grant's edge: right types, mirrored parties, matching digest. It deliberately checks
  neither proof nor validity window — proof verification needs a resolver this crate does
  not hold, and whether a window is current is a question about an instant the caller
  chooses
- `DTGCredential::digest()`, the specification's digest: `sha256:` + lowercase hex SHA-256
  over the JCS (RFC 8785) canonical form **excluding the top-level `proof`**. One
  computation now serves both places the spec uses a digest — the member-issued VMC and the
  VWC. Excluding `proof` is what lets an acknowledgement survive its grant being re-signed
- `DTGCredential::subject_digest()` reads the `digest` off whichever subject carries one
- `CredentialSubjectMembership`, the VMC subject, carrying the OPTIONAL `digest`

### Changed

- **BREAKING:** a `MembershipCredential` now deserializes with
  `CredentialSubject::Membership`, not `CredentialSubject::Basic`. A `{ id, digest }`
  subject is shape-identical to a VWC subject and the untagged enum matches `Witness`
  first, so the subject object alone cannot say which it is — only the credential's `type`
  can. `TryFrom<DTGCommon>` therefore normalizes whichever variant the untagged match
  landed on, the same way it already re-wrapped a `Basic` subject as `Witness` on a VWC.
  Deserialization is deterministic rather than order-dependent, and code matching on a
  VMC's subject sees one shape rather than two
- **BREAKING:** `CredentialSubject` has a new variant. A match over it must be updated;
  the variant is last and is never selected by the untagged match, so nothing that
  deserializes changes shape beyond the VMC normalization above
- **BREAKING:** a `MembershipCredential` whose subject fits none of those shapes — an
  endorsement subject, or a `witnessContext`, which belongs to a VWC and has no meaning
  here — is now refused as `UnknownCredential` rather than accepted unexamined. The
  `Membership` arm previously took any subject at all
- `new_vmc()` documents itself as the community-issued grant and builds a `Membership`
  subject. The wire form is unchanged: `digest` is absent on a grant, and skipped when
  `None`

### Deprecated

- `DTGCredential::digest_multibase()`. It emits a base58btc multibase multihash over the
  credential *including* its proof — neither the encoding nor the coverage the
  specification requires, so digests it produced never interoperated. This was the known
  divergence documented at the top of the README, which that README no longer carries.
  `verify_digest()` now compares against `digest()`, so a conformant credential from
  another implementation verifies and one built on `digest_multibase()` does not


## [0.3.0] - 2026-08-29

### Added

- `id` property on `DTGCommon`, the OPTIONAL top-level credential identifier of the W3C VC
  Data Model. It was missing entirely, so a credential built with this library could not
  carry one — and a counterparty that keys credentials by `id` had nothing to key on. Every
  reciprocal `MembershipCredential` an OpenVTC member issued was rejected by the VTC for
  exactly this reason, with the rejection arriving as a problem-report the member's client
  discarded, so the failure was silent on both sides
- `DTGCredential::with_id()` and `DTGCredential::set_id()` to set it while building, and
  `DTGCredential::id()` / `DTGCommon::id()` to read it back. `id` is inside what a Data
  Integrity proof covers, so it MUST be set before `sign()`; a test pins that (adding or
  changing it afterwards invalidates the proof)

### Changed

- **BREAKING:** `DTGCommon` has a new public field. Construction through
  `..Default::default()` (as every `new_*` constructor does) is unaffected; an exhaustive
  struct literal will need the extra field

## [0.2.0] - 2026-08-10

### Added

- `taskContext` property on `DTGCommon`, per the Trust Task Context Binding section of the
  new specification. It is REQUIRED on a `WitnessCredential` and OPTIONAL elsewhere.
  Previously this property was silently dropped on deserialization, which broke signing and
  verification of any spec-conformant VWC: `sign()` serializes the credential, so a dropped
  `taskContext` meant issuers signed a document missing the field and verifiers hashed a
  different document than the one that was signed
- `DTGCredential::task_context()` and `DTGCommon::task_context()` accessors
- `DTGCredential::digest_multibase()`, computing the digest of a credential for use as the
  `digest` of a Witness Credential attesting it
- `DTGCredential::verify_digest()`, checking a VWC's `digest` against the credential it
  claims to witness
- `DTGCredentialError::MissingTaskContext` and `DTGCredentialError::Canonicalization`

### Changed

- Tracked the [DTG Core Credentials specification](https://github.com/trustoverip/dtgwg-cred-spec)
  v1.0 Working Draft 01, which supersedes the v0.3 proposal draft this library was built against
- **BREAKING:** `DTGCredential::new_vwc()` takes a required `task_context: String` argument
- **BREAKING:** Deserializing a `WitnessCredential` without a `taskContext` now fails with
  `DTGCredentialError::MissingTaskContext`
- Added `multibase`, `sha2` and `serde_json_canonicalizer` as direct dependencies (all were
  already present transitively via `affinidi-data-integrity`)

### Deprecated

- `DTGCredentialType::RCard`, `CredentialSubject::RCard`, `CredentialSubjectRCard` and
  `DTGCredential::new_rcard()`. Working Draft 01 reclassifies the r-card as a verifiable data
  structure (VDS) rather than a `DTGCredential` subtype, to be defined by the planned
  *DTG Verifiable Data Structures* specification. These will be removed in a future release

### Notes

- **⚠️ KNOWN SPEC DIVERGENCE — VWC `digest` encoding.** WD-01 requires the VWC `digest` to be
  encoded as `sha256:` followed by a lowercase hex digest. This library instead emits a
  multibase-encoded multihash (base58btc, `z...`), matching the W3C `digestMultibase`
  convention used elsewhere in the VC ecosystem. The underlying hash — SHA-256 over the JCS
  (RFC 8785) canonical form — is identical; only the encoding differs.
  **VWCs produced by this library do not interoperate with spec-conformant implementations
  in either direction:** `verify_digest()` rejects conformant VWCs, and conformant verifiers
  reject ours. Unresolved; to be raised with the DTGWG. See README.md

## [0.1.3] - 2026-06-06

### Changed

- Updated `affinidi-data-integrity` dependency from 0.6 to 0.7
- Updated `affinidi-tdk` dev-dependency from 0.6 to 0.7

## [0.1.2] - 2026-04-30

### Changed

- Updated `affinidi-data-integrity` dependency from 0.5 to 0.6

### Fixed

- Migrated to the `affinidi-data-integrity` 0.6 API

## [0.1.1] - 2026-03-29

### Changed

- `DTGCredential::sign()` is now an `async` method (breaking change) to align with upstream `affinidi-data-integrity` v0.5
- Updated `affinidi-data-integrity` dependency from 0.4 to 0.5
- Updated `affinidi-tdk` dev-dependency from 0.5 to 0.6
- Relaxed `tokio` dev-dependency version from 1.49 to 1
- Updated repository URL to `https://github.com/OpenVTC/dtg-credentials`
- Enabled crate publishing (`publish = true`)

## [0.1.0] - 2026-02-25

Never published to crates.io; `publish` was enabled in 0.1.1.

### Added

- Initial release
- Support for W3C VC 1.1 and 2.0 specifications
- DTG credential types: VMC, VRC, VIC, VPC, VEC, VWC, and RCard
- Credential signing via W3C Data Integrity Proof (JCS EdDSA 2022)
- Credential verification with public key bytes
- Optional `affinidi-signing` feature for integrated signing support
