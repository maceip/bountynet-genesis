# Stages

## Stage 0: The Attested Builder

Stage 0 is a build environment running inside a TEE. It takes source
code, builds it, and produces an artifact with a hardware-rooted proof
of what was built. The proof is a TEE quote binding the source hash,
dependency hash, and artifact hash into a single signed statement from
the CPU.

Stage 0 is the root of trust for the entire system. Everything
downstream depends on the integrity of the build. If stage 0 is
compromised, nothing else matters.

### Why it exists

Two academic papers motivate this design:

**Attestable Containers** (Hugenroth et al., Cambridge/JKU, CCS 2025)
says: build inside a TEE, and the hardware attests that source S was
compiled into artifact A by environment E. No reproducible builds
required — the TEE is the witness. The ratcheting mechanism locks
the source hash before any untrusted code runs.

**LATTE** (Xu et al., SJTU, EuroS&P 2025) says: separate platform
measurements (what the hardware measures) from application identity
(what the developer cares about). Check both independently. The
platform measurement proves the build environment is genuine. The
application identity (Value X) proves the output matches expectations.

Stage 0 combines them: the platform measurement proves the builder
is genuine TEE hardware. The ratchet locks the source. The build
runs inside the TEE. The quote binds everything together. Anyone
can verify the proof without trusting the operator.

### Requirements for a stage 0 implementation

1. The TEE measurement of the build environment must be verifiable
   from source, or from a trusted endorsement.
2. The build must run inside the TEE's trust boundary.
3. The source hash (CT) must be locked before the build starts.
4. The output (artifact hash, Value X) must be bound into the
   TEE quote alongside CT.

## Stage 0 Implementations

| Platform | Provider | TEE | Firmware verification | Kernel in measurement | Status |
|----------|----------|-----|----------------------|----------------------|--------|
| AWS Nitro | Amazon | Nitro Enclave | .eif reproducible from source | Yes — PCR0 covers everything | **Ready** |
| GCP TDX | Google | Intel TDX | Google signed endorsement (MRTD). RTMR[1-3] cover our code, verifiable from source. | RTMR[1-2] cover kernel | **Ready** |
| Azure SNP | Microsoft | AMD SEV-SNP | Custom OVMF via IGVM, reproducible from source | Full control — MEASUREMENT covers everything | **Next** |
| Azure TDX | Microsoft | Intel TDX | Custom firmware, reproducible from source | Full control | **Next** |
| AWS SNP | Amazon | AMD SEV-SNP | Published source does not match production firmware. `SNP_KERNEL_HASHES` not enabled. Issues filed: [aws/uefi#19](https://github.com/aws/uefi/issues/19), [aws/uefi#20](https://github.com/aws/uefi/issues/20) | Kernel not in MEASUREMENT | **Blocked** |
| Equinix Metal | Equinix | AMD SEV-SNP (bare metal) | Full BIOS control via IPMI. Run your own hypervisor + OVMF. | Full control | Not tested |
| Hetzner | Hetzner | None | BIOS locked, no SNP/TDX exposed | N/A | Not available |
| OVH | OVHcloud | None | BIOS locked, no SNP/TDX | N/A | Not available |
| Vultr | Vultr | None | No confidential VM offering | N/A | Not available |
| Oracle Cloud | Oracle | AMD SEV (not full SNP) | No remote attestation path documented | N/A | Not viable |
| Scaleway | Scaleway | None | No confidential computing | N/A | Not available |
| DigitalOcean | DigitalOcean | None | No TEE support | N/A | Not available |
| IBM Cloud | IBM | SGX (x86), Secure Execution (s390x) | SGX bare metal only, no TDX/SNP | N/A | Not viable for our use |
| STACKIT | Schwarz Group | None GA | CCC member, no public product | N/A | Not available |

## Stage 1: The Attested Runtime

Stage 1 is the artifact from stage 0, running inside a TEE. At boot,
it loads the stage 0 attestation, re-computes Value X from its own
files, and verifies the match. If anything was modified between build
and deploy, stage 1 refuses to start.

Stage 1 produces its own TEE quote chaining to the stage 0 attestation.
A verifier can walk the full chain: source → attested build → attested
runtime.

Stage 1 can run on any TEE platform. The trust model for the runtime
platform is independent of stage 0. Stage 0 provides the build trust.
The runtime platform provides the execution trust.

| Stage 1 platform | Firmware verification | Our code verification |
|------------------|----------------------|----------------------|
| GCP TDX | Google endorsement (MRTD) | RTMR[1-3] from source |
| Azure SNP | Our OVMF via IGVM (MEASUREMENT from source) | Included in MEASUREMENT |
| Azure TDX | Our OVMF (MRTD from source) | RTMR[1-3] from source |
| AWS SNP | Published source stale | Not in MEASUREMENT |
| AWS Nitro | .eif reproducible | PCR0 covers everything |
| Equinix Metal | Full control | Full control |
