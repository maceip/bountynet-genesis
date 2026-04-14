//! Registry of approved Value X entries.
//!
//! A registry entry says: "this Value X has been reviewed and is approved
//! for some status (recommended / deprecated / revoked)." Entries live as
//! JSON files in a `registry/` directory — same-repo today.
//!
//! ## Trust roots
//!
//! Entries are signed. There is no single global signer — this is not
//! a CI-only system. A `TrustRoot` is a configuration that says "these
//! signer identities are trusted." Our own project ships with a default
//! `TrustRoot` pointing at our GitHub workflow, but a downstream user
//! (e.g., a JS developer running their webserver in a TEE) configures
//! their own `TrustRoot` that trusts their signer. The registry format
//! does not change; only the set of accepted identities does.
//!
//! Signature verification is stubbed pending Sigstore keyless integration.
//! The on-disk format is stable: swapping the verifier impl does not
//! require a migration.
//!
//! See `v2/registry/README.md` for the schema and trust model.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Recommended,
    Deprecated,
    Revoked,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PlatformMeasurements {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nitro_pcr0: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tdx_mrtd: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snp_measurement: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub value_x: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_commit: Option<String>,
    #[serde(default)]
    pub platform_measurements: PlatformMeasurements,
    pub status: Status,
    pub approved_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deprecated_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub notes: String,
}

/// Result of looking up a Value X in the registry.
#[derive(Debug, Clone)]
pub enum Lookup {
    /// Entry found and signature verified (or signature verification skipped).
    Found { entry: Entry, signature: SignatureState },
    /// Value X is not in the registry at all.
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureState {
    /// Sidecar present and signature valid against the pinned identity.
    Verified,
    /// Sidecar present but verifier is stubbed — not yet checked.
    Unchecked,
    /// Sidecar missing.
    Missing,
}

/// Identity of a trusted signer. Describes *who* is allowed to sign
/// registry entries for a given consumer of the registry. Having this
/// as data (not a hardcoded constant) is the hinge that keeps the
/// system from collapsing into "GitHub CI only."
#[derive(Debug, Clone)]
pub enum TrustedIdentity {
    /// Sigstore keyless signer, pinned by Fulcio cert subject.
    /// Matches any workflow identity matching (issuer, subject_pattern).
    /// `subject_pattern` is a glob — e.g.,
    ///   `https://github.com/maceip/bountynet-runner/.github/workflows/registry-sign.yml@refs/heads/main`
    /// or a looser match for downstream users.
    SigstoreKeyless {
        issuer: String,
        subject_pattern: String,
    },
    /// Raw public key (ed25519 or ecdsa). For offline / YubiKey signers
    /// who don't want GitHub or Sigstore in their trust chain.
    RawPublicKey {
        algorithm: String, // "ed25519" | "ecdsa-p256"
        spki_der: Vec<u8>,
        label: String,     // human-readable, shown on verify
    },
}

/// A set of trusted identities. An entry is accepted if *any* identity
/// in the trust root successfully verifies its signature. The set can
/// be empty — in which case the registry is informational only and
/// every entry comes back as `SignatureState::Missing`.
#[derive(Debug, Clone, Default)]
pub struct TrustRoot {
    pub identities: Vec<TrustedIdentity>,
}

impl TrustRoot {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn with(mut self, id: TrustedIdentity) -> Self {
        self.identities.push(id);
        self
    }

    /// The project's own default trust root: our GitHub workflow signing
    /// via Sigstore keyless. Downstream users should NOT use this — they
    /// should build their own `TrustRoot` pointing at their own signers.
    /// This exists so `bountynet check` of our own runner works out of
    /// the box without a config file.
    pub fn bountynet_default() -> Self {
        Self::empty().with(TrustedIdentity::SigstoreKeyless {
            issuer: "https://token.actions.githubusercontent.com".to_string(),
            subject_pattern:
                "https://github.com/maceip/bountynet-runner/.github/workflows/registry-sign.yml@refs/heads/main"
                    .to_string(),
        })
    }
}

pub struct Registry {
    entries: HashMap<String, (Entry, SignatureState)>,
    trust_root: TrustRoot,
}

impl Registry {
    /// Load every `*.json` in the given directory as a registry entry.
    /// Files named `README.md` or `*.sig` are skipped. Signatures are
    /// checked against the provided `trust_root`.
    pub fn load(dir: &Path, trust_root: TrustRoot) -> anyhow::Result<Self> {
        let mut entries = HashMap::new();
        if !dir.exists() {
            return Ok(Self { entries, trust_root });
        }
        for e in std::fs::read_dir(dir)? {
            let e = e?;
            let path = e.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            let body = std::fs::read_to_string(&path)?;
            let entry: Entry = serde_json::from_str(&body)
                .map_err(|err| anyhow::anyhow!("{}: {err}", path.display()))?;
            let sig_state = Self::check_sidecar(&path, &body, &trust_root)?;
            entries.insert(entry.value_x.clone(), (entry, sig_state));
        }
        Ok(Self { entries, trust_root })
    }

    /// Default load: look for the project's registry directory and use
    /// the project's default `TrustRoot`. This is the path
    /// `bountynet check` takes when no config is provided.
    pub fn load_default() -> anyhow::Result<Self> {
        let candidates = [
            PathBuf::from("v2/registry"),
            PathBuf::from("registry"),
        ];
        for c in &candidates {
            if c.exists() {
                return Self::load(c, TrustRoot::bountynet_default());
            }
        }
        Ok(Self {
            entries: HashMap::new(),
            trust_root: TrustRoot::bountynet_default(),
        })
    }

    pub fn lookup(&self, value_x_hex: &str) -> Lookup {
        match self.entries.get(value_x_hex) {
            Some((entry, sig)) => Lookup::Found {
                entry: entry.clone(),
                signature: *sig,
            },
            None => Lookup::Unknown,
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn trust_root(&self) -> &TrustRoot {
        &self.trust_root
    }

    fn check_sidecar(
        json_path: &Path,
        _body: &str,
        _trust_root: &TrustRoot,
    ) -> anyhow::Result<SignatureState> {
        let sig_path = {
            let mut p = json_path.as_os_str().to_owned();
            p.push(".sig");
            PathBuf::from(p)
        };
        if !sig_path.exists() {
            return Ok(SignatureState::Missing);
        }
        // Sidecar present. Verification is stubbed — see next step in the plan.
        // When implemented:
        //   for identity in &trust_root.identities {
        //       match identity {
        //           SigstoreKeyless { issuer, subject_pattern } => {
        //               // parse cosign bundle
        //               // verify Rekor inclusion → Fulcio chain → subject match → sig
        //           }
        //           RawPublicKey { algorithm, spki_der, .. } => {
        //               // direct pubkey verify over body
        //           }
        //       }
        //       if verified { return Ok(Verified); }
        //   }
        //   Ok(Unchecked)  // sig present but no identity in trust root matched
        Ok(SignatureState::Unchecked)
    }
}

/// Human-readable summary of a lookup result. Used by `bountynet check`.
pub fn describe(lookup: &Lookup) -> String {
    match lookup {
        Lookup::Found { entry, signature } => {
            let sig = match signature {
                SignatureState::Verified => "signed",
                SignatureState::Unchecked => "signed (unchecked)",
                SignatureState::Missing => "UNSIGNED",
            };
            let status = match entry.status {
                Status::Recommended => "RECOMMENDED",
                Status::Deprecated => "DEPRECATED",
                Status::Revoked => "REVOKED",
            };
            format!("{status} ({sig}) — approved {}", entry.approved_at)
        }
        Lookup::Unknown => "UNKNOWN (not in registry)".to_string(),
    }
}
