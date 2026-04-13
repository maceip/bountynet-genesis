# Constitution

## What we're building

A system that answers one question with cryptographic proof:

**Is the code running on that machine the same code that's in the repo?**

Not "probably." Not "we checked last Tuesday." Not "the cloud provider promises." A proof rooted in hardware that anyone can verify and nobody can argue with.

## Where the ideas come from

Two papers:

**LATTE** says: separate what the hardware measures (the platform) from what the developer cares about (the application). Check both. If the platform measurement is correct, the code that computed the application identity is trustworthy.

**Attestable Containers** says: you don't need reproducible builds. Build inside a TEE. The hardware attests that this source became this artifact. The build environment is the witness.

We combine them: build inside a TEE (Attestable Containers), then run inside a TEE (LATTE), and the attestation chains from source to build to runtime. At every step, the hardware is the proof.

## The Value X problem

Value X is a single number — a hash — that represents "this exact software." It's the answer to "what's running?"

For Value X to mean anything:

1. It must be computed inside a TEE. Not on a developer's laptop. Not in an unattested CI runner. Inside hardware that can prove it wasn't tampered with.

2. The hardware measurement of the TEE must be checked. Value X is only trustworthy because the code that computed it is genuine. If nobody checks the platform measurement, Value X is just a number someone made up.

3. It must be the same across platforms. The same source built on TDX, SNP, or Nitro must produce the same Value X. Platform differences are in the hardware quote, not in the identity.

4. The chain must be unbroken. Source → attested build → artifact → attested runtime. If any link is missing, the proof has a gap.

## What we will not do

- We will not add features that don't serve the Value X problem.
- We will not build plumbing (token formats, HTTP endpoints, smart contracts, compatibility layers) before the core proof works end-to-end.
- We will not claim to implement a paper's contribution unless we actually implement it.
- We will not let the system work in "insecure mode" without making that loudly visible.
- We will not take shortcuts in verification. If a signature can't be checked, the result is "unverified," not "true."
- We will not optimize for adoption before correctness.

## What we will do

- Build stage 0: an attested builder that runs inside a TEE, takes source code, and produces an artifact with a hardware-rooted proof of what was built.
- Build stage 1: an attested runtime where the artifact runs, re-verifies its identity, and serves proof to anyone who asks.
- Make it work on Intel TDX, AMD SEV-SNP, and AWS Nitro.
- Make it usable by developers who don't know what a TEE is. They push code. They get a proof. They don't touch a wallet, install a driver, or read a spec.
- Keep the codebase small enough that a single person can read and understand every line.

## How we decide what to build next

Ask: "Does this make the Value X proof stronger or more complete?"

If yes, build it. If no, don't. Not yet.
