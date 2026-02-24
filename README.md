# Decentralized Trust Graph (DTG) Credentials

**_NOTE:_** This is an early implementation to v0.3 of these [specifications](https://github.com/trustoverip/dtgwg-cred-tf).

See the [First Person Project Whitepaper](https://www.firstperson.network/white-paper)
for more information.

This library supports both W3C VC 1.1 and 2.0 specifications.

## Credential Type Hierarchy

All credentials inherit from the abstract `DTGCredential`.

```text
VerifiableCredential
└── DTGCredential
    ├── MembershipCredential (VMC)
    ├── RelationshipCredential (VRC)
    ├── InvitationCredential (VIC)
    ├── PersonaCredential (VPC)
    ├── EndorsementCredential (VEC)
    ├── WitnessCredential (VWC)
    └── RelationshipCard (RCard) [VDS - not a credential]
```

## End to End Example

An end-to-end example of creating, signing and verifying a DTG Credential exists
in `examples`

```bash
cargo run --example sign_and_verify
```

## Creating credentials

Each credential type has it's own `new_*()` function to create a new credential
of that type.

Example:

```Rust
let vpc = DTGCredential::new_vpc(issuer, subject, valid_from, valid_to);
```

The created `TDGCredential` can be Serialized to JSON using `serde_json` allowing
it to be passed into various signing libraries

## Signing credentials

By default the `affinidi-signing` feature is enabled which allows you to sign a
credential

```Rust
let mut vpc = DTGCredential::new_vpc(issuer, subject, valid_from, valid_to);

vpc.sign(&signing_key)?;
```

### Verifying credentials

There are two ways to validate a credential:

**Method 1:** If you have the public key bytes that correspond to the signing
key, then you can directly verify the credential:

```Rust
let signing_key = Secret::generate_ed25519(None, None);
let mut vpc = DTGCredential::new_vpc(issuer, subject, valid_from, valid_to);

vpc.sign(&signing_key)?;

vpc.verify(&signing_key.get_public_bytes())?;
```

**Method 2:** If you do not have the public key material, you are likely going to
need to resolve the DID VerificationMethod and derive the public key bytes used
when creating the credential.

```Rust
let mut credential = serde_json::from_str(<raw_credential_string>);

// Get the proof
let proof = if let Some(proof) = &credential.credential().proof {
  proof.clone()
} else {
    bail!("credential is not signed!");
};

// Strip proof from the credential
let unsigned = DTGCommon {
  proof: None,
  ..credential.credential().clone()
};

tdk.verify_data(&unsigned, None, &proof).await?;
```

## Common functions

You can deal with the raw credential as required.

```Rust
let vrc = DTGCredential::new_vrc(issuer, subject, valid_from, valid_to);

let credential = vrc.credential();
```

You can determine the credential type easily using:

```Rust
let vmc = DTGCredential::new_vmc(issuer, subject, valid_from, valid_to);

if let DTGCredentialType::VMC = vmc.type_() {
  // Good
}
```

Has this Credential been signed?

```Rust
let vmc = DTGCredential::new_vmc(issuer, subject, valid_from, valid_to);

if vmc.signed() {
  println!("Credential has been signed");
} else {
  println!("Credential has not been signed");
}
```
