# bountynet-genesis

**A GitHub Actions runner that proves it hasn't been tampered with.**

bountynet-genesis runs your CI/CD jobs inside hardware-protected environments and produces cryptographic proof that the machine, the software, and the execution are all genuine. This proof works across three different hardware platforms and can be verified by anyone — including a smart contract.

---

## The Problem

When you run code on someone else's computer — a cloud VM, a CI runner, a build server — you're trusting that:

1. The machine is running the software it claims to be running
2. Nobody modified the software after it was deployed
3. Nobody is watching or tampering with the execution

Normally, you just have to take the cloud provider's word for it. bountynet-genesis replaces that trust with math.

## How It Works

Your code runs inside a **Trusted Execution Environment** (TEE) — a hardware feature built into modern CPUs that creates an isolated, encrypted area of memory. The CPU itself enforces the isolation. Not the operating system, not the hypervisor, not the cloud provider. The silicon.

When the TEE boots, the CPU measures everything that loaded into it — every byte of code, every configuration — and produces a **quote**: a signed statement saying "this exact software is running inside genuine hardware, and here's the cryptographic proof."

bountynet-genesis wraps quotes from three different hardware platforms into a single format called **UnifiedQuote**, so verifiers don't need to care which cloud or chip produced the proof.

---

## The Three Platforms

### AWS Nitro Enclaves

Amazon's custom hardware security module, built into every modern EC2 instance. When you create a Nitro Enclave, the Nitro Hypervisor carves off dedicated CPU cores and memory that become completely inaccessible to the parent instance — even to AWS employees with root access to the host.

| Component | What it does |
|-----------|-------------|
| **Nitro Security Module (NSM)** | A dedicated chip on the motherboard. It holds a private key that never leaves the hardware. When asked, it signs a document containing measurements of everything running in the enclave. |
| **PCR values (0-15)** | Platform Configuration Registers — a chain of hashes. PCR0 captures the enclave image, PCR1 the kernel, PCR2 the application. Changing anything changes everything downstream. |
| **Attestation document** | A signed blob containing all PCR values, a timestamp, any data the enclave wants to include (we put our signing key hash here), and the NSM's signature over all of it. |
| **Certificate chain** | The NSM's signing key has a certificate issued by AWS, chaining up to the AWS Nitro Root CA — a public key anyone can verify against. |

**Signature:** ECDSA with the P-384 curve.

**How it could be compromised:**
- A vulnerability in the Nitro Hypervisor that lets code be injected without changing measurements. AWS runs a bug bounty for this.
- Theft of AWS's root CA private key. Stored in HSMs with physical security.
- A hardware bug that lets measurements be spoofed. Nitro uses a separate chip (not CPU microcode), which limits this risk compared to SGX-based approaches.

---

### AMD SEV-SNP

A feature in AMD EPYC server CPUs — the chips running a large portion of AWS, Azure, and GCP. SEV-SNP encrypts the entire VM's memory with a key the CPU generates and that nobody — not the hypervisor, not the host OS, not even AMD — can extract.

| Component | What it does |
|-----------|-------------|
| **AMD Secure Processor (PSP)** | A separate ARM processor embedded in every EPYC chip. It runs its own firmware, manages encryption keys, and signs attestation reports. Operates independently of the x86 cores running your code. |
| **MEASUREMENT** | A 48-byte hash of everything loaded into the VM at launch. The PSP computes this before the VM starts executing. Any modification changes this value. |
| **REPORT_DATA** | 64 bytes of arbitrary data the VM provides when requesting a report. We put our signing key hash here, binding our identity to the hardware attestation. |
| **VCEK** | Versioned Chip Endorsement Key — a unique signing key per physical chip, per firmware version. The PSP uses this to sign reports. The matching certificate is publicly available from AMD's Key Distribution Service. |
| **Certificate chain** | VCEK &rarr; ASK (AMD SEV Signing Key) &rarr; ARK (AMD Root Key). ARK is self-signed and published by AMD. |

**Signature:** ECDSA with P-384. Covers 672 bytes of the attestation report.

**How it could be compromised:**
- Extracting the VCEK from the Secure Processor. The PSP is hardened against physical attacks, but firmware bugs have been found in older SEV versions (before SNP). SNP was designed to fix those.
- Compromise of AMD's root key. Stored in HSMs.
- A bug in PSP firmware that lets the hypervisor influence measurements. AMD revokes old TCB versions when this happens — the "Versioned" in VCEK means each firmware version gets a different key.
- Side-channel attacks through shared CPU resources. SNP's memory encryption prevents direct reads, but cache timing remains an active research area.

---

### Intel TDX

Intel's confidential VM technology, available on 4th Gen Xeon (Sapphire Rapids) and newer. Similar to AMD SNP — the CPU encrypts the VM's memory and prevents the hypervisor from reading it — but the architecture differs in one important way: it adds an extra layer called the Quoting Enclave.

| Component | What it does |
|-----------|-------------|
| **TDX Module** | Intel-signed firmware running at a privilege level between the hypervisor and the CPU microcode. It manages Trust Domains (encrypted VMs) and enforces isolation. |
| **MRTD** | Measurement of the Trust Domain — a 48-byte hash of the initial VM image, computed by the TDX Module before the VM starts. |
| **RTMRs (0-3)** | Runtime Measurement Registers. Extend-only — you can add measurements but never erase them. RTMR0 captures firmware, RTMR1 the OS, RTMR2 the application. |
| **REPORTDATA** | 64 bytes of VM-supplied data included in the quote. We bind our signing key here. |
| **Quoting Enclave (QE)** | A special Intel-signed SGX enclave that converts local TDX reports into remotely-verifiable quotes. It holds an Attestation Key and signs the quote. |
| **Certificate chain** | The QE's Attestation Key &rarr; PCK cert (per-CPU) &rarr; Intel Platform CA &rarr; Intel SGX Root CA. All three certificates are embedded in the quote itself. |

**Signature:** ECDSA with P-256. Two signatures per quote: one from the Attestation Key over the measurements, one from the PCK cert over the QE's identity.

**How it could be compromised:**
- A vulnerability in the TDX Module. It's firmware (updatable), so Intel can patch it, but there's an exposure window. The Module is much smaller than a hypervisor, limiting attack surface.
- The Quoting Enclave runs in SGX, which has had notable vulnerabilities (Foreshadow, Plundervolt, AEPIC Leak, Downfall). Each was patched, but the pattern suggests more will be found. Intel revokes old TCB versions with each fix.
- Side-channel attacks. TDX inherits some of SGX's surface, though it's better isolated at the VM level.
- Compromise of Intel's root CA key. Standard HSM protection.

---

## What bountynet-genesis Adds

### Value X — A Universal Identity

We compute `sha384(every file in the runner directory)` — deterministically sorted, recursively hashed. This produces a 48-byte fingerprint that is identical regardless of which TEE platform runs the code.

Rebuild from source, get the same Value X, and you know the runner is running exactly what's in the repo.

### UnifiedQuote — One Format, Three Platforms

```
UnifiedQuote {
    version:              1
    platform:             Nitro | SevSnp | Tdx
    value_x:              [48 bytes]
    platform_quote:       [raw TEE evidence]
    platform_quote_hash:  sha256(raw evidence)
    timestamp:            when generated
    nonce:                anti-replay
    signature:            ed25519 over all fields
    pubkey:               signing key, bound into TEE quote
}
```

A verifier calls one function. It doesn't matter which platform produced the quote.

### Two-Layer Verification

- **Layer 1 (cheap):** Verify the ed25519 signature. Confirms the quote hasn't been tampered with. Just math on ~180 bytes. This goes on-chain.
- **Layer 2 (deep):** Fetch the full platform quote and verify the hardware signature chain back to the vendor's root CA. Proves it came from real TEE hardware. This stays off-chain but is hash-linked.

---

## Architecture

```
                         TEE Hardware
                    (Nitro / SNP / TDX)
                            |
                    bountynet-shim (Rust)
                   /        |          \
          Compute X    Collect TEE     Start Runner
          (sha384)      Evidence       (GitHub Actions)
                   \        |          /
                    UnifiedQuote + /attest endpoint
                            |
                   -------------------------
                  |                         |
           GitHub Actions              On-chain Oracle
         (build, test, deploy)      (stores ~180 bytes)
                  |                         |
           artifacts +               anyone can verify
           SLSA provenance           the runner's identity
```

## Quick Start

```bash
# Run tests (uses real attestation data from Nitro, SNP, and TDX hardware)
cargo test --release

# Build the Docker image
docker build -t bountynet-genesis .

# Deploy on GCP TDX
GITHUB_TOKEN=ghp_xxx GITHUB_REPO=you/repo ./deploy/gcp-tdx.sh

# Query the attestation endpoint
curl http://RUNNER_IP:9384/attest | jq .
curl -X POST http://RUNNER_IP:9384/attest/full | jq .
```

## Repository Structure

```
src/
  main.rs             entrypoint: detect TEE, compute X, start runner
  quote/
    mod.rs            UnifiedQuote format
    value_x.rs        deterministic image hashing
    verify.rs         full crypto verification (P-384, P-256, cert chains)
  tee/
    detect.rs         auto-detect TEE platform
    nitro.rs          AWS Nitro NSM interface
    snp.rs            AMD SEV-SNP ioctl
    tdx.rs            Intel TDX configfs-tsm
  attest/
    mod.rs            HTTP endpoint with rate limiting
contracts/
  TeeGated.vy        Vyper contract: gate actions behind TEE proof
tests/
  integration_nitro.rs    6 tests with real Nitro data
  integration_snp.rs      2 tests with real SNP data
  integration_tdx.rs      2 tests with real TDX data
  integration_value_x.rs  determinism test on real runner
testdata/
  nitro_attestation.json  captured from AWS i3.metal
  snp_attestation.json    captured from AMD EPYC c6a.large
  tdx_attestation.json    captured from Intel Sapphire Rapids (GCP c3-standard-4)
```

## License

MIT
