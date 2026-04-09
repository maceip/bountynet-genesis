# Trust Bootstrapping

How a verifier knows the running code matches the source.

## The Question

You have source code in a git repo. A machine claims to be running
software built from that source. How do you know it's telling the truth?

## The Answer (per platform)

### AWS Nitro

Nitro Enclaves use the .eif image format. The format is simple:
kernel + ramdisk + application, hashed into PCR0. The .eif build
is deterministic.

**Verification:**
1. Clone the repo
2. Build the .eif from source
3. Record PCR0 from your build
4. Connect to the running enclave, request a quote with your challenge nonce
5. PCR0 in the quote matches your build → same code

**Trust assumption:** AWS Nitro root CA signs the quote honestly.

### AWS SNP (AMD SEV-SNP)

AWS controls the OVMF firmware, but publishes the source at
github.com/aws/uefi with Nix reproducible builds.

**Verification:**
1. Clone github.com/aws/uefi, run `nix-build --pure` → get ovmf_img.fd
2. Clone the application repo, build the AMI
3. Run `sev-snp-measure --mode snp --vmm-type ec2 --ovmf ovmf_img.fd --vcpus N --kernel vmlinuz --initrd initrd.img`
4. This gives you the expected MEASUREMENT (48 bytes)
5. Connect to the running VM, request an SNP attestation report
6. MEASUREMENT in the report (offset 0x090) matches → same code

**Trust assumption:** AMD's PSP signs the report honestly. AWS's
published OVMF source matches what they actually run. Nix build
is deterministic.

### GCP TDX (Intel TDX)

Google controls the firmware (closed source, not published).
However, TDX has separate measurement registers:

- MRTD = firmware (Google's, opaque)
- RTMR[0] = TDVF config
- RTMR[1] = bootloader (yours)
- RTMR[2] = kernel + cmdline (yours)
- RTMR[3] = user-extensible (yours)

Google publishes signed firmware binaries and the gce-tcb-verifier
tool to verify MRTD against their endorsement.

**Verification:**
1. Verify MRTD against Google's signed endorsement (platform layer)
2. Build your kernel + application from source
3. Compute expected RTMR[1], RTMR[2], RTMR[3] from your build
4. Connect to the running VM, request a TDX quote
5. RTMR values in the quote match → your code is genuine
6. MRTD matches Google's endorsement → firmware is genuine

**Trust assumption:** Intel's SGX root CA signs the quote honestly.
Google's firmware endorsement is authentic. RTMR values are
computed by the TDX Module, which Google cannot modify post-launch.

### Azure SNP/TDX

Azure supports custom firmware via the IGVM format.
Full control over the measurement chain.

**Verification:**
1. Build OVMF from source
2. Build the application from source
3. Compute expected measurement from (firmware + kernel + application)
4. Connect, request quote, compare measurement

**Trust assumption:** CPU vendor root CA only.

## Cross-platform: Anytrust

Build the same source on 2+ platforms. If Value X matches across
platforms, trust at least one vendor → trust the build.

AWS Nitro (PCR0) + AWS SNP (MEASUREMENT) + GCP TDX (RTMR[1-3]):
three independent hardware vendors attest the same Value X.
An attacker would need to compromise AMD, Intel, AND Amazon
simultaneously.

## What the verifier needs

For any platform, the verifier needs:
1. The source code (to compute expected hashes)
2. Network access to the running machine (to request a fresh quote)
3. A challenge nonce (to prove the quote is fresh)
4. The vendor's root CA fingerprint (pinned in our code)

No external database. No trusted third party beyond the CPU vendor.
No account or API key. Just source code + network access.
