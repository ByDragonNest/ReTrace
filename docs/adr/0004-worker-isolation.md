# ADR 0004 — VM / dedicated Windows workers for native dynamic tooling

**Status:** SUPERSEDED 2026-10-13 by the scope decision below · **Closes:** T-3 (partly)

## Context
x64dbg, Procmon and Frida need a real Windows kernel, driver-level visibility and, for x64dbg, a
debugger attached to a live process. Forcing them into Linux containers produces a demo, not a
product. Today they run **in the analyst's own session with the analyst's own privileges**, gated
only by an approval mechanism that is off in the shipped configuration.

## Decision
- **Containers** for the control plane, Linux static analysis, report rendering and deterministic
  analyzers.
- **VMs or dedicated Windows hosts** for x64dbg, Procmon, Frida and native PE tooling, treated as
  a worker pool addressed through the same job interface.
- Every job, on any worker: ephemeral workspace, least-privilege identity, CPU/RAM/disk/wall-clock
  quotas, network disabled by default with an egress allow-list, verifiable workspace deletion,
  no shared storage between customers, immutable capture of logs, tool versions and artifact hashes.
- In the `workstation` profile the worker is the local process — but it uses the **same** job
  interface, quotas and workspace lifecycle, so the security model does not change shape between
  profiles.

## Consequences
Dynamic analysis stops running next to the analyst's mail client and SSH keys. Cost: VM fleet
provisioning, image maintenance and Windows licensing in the enterprise profile — a real operating
expense, and the honest price of running untrusted binaries.


---

## Superseded (2026-10-13)

ReTrace targets **a single analyst and small teams**. A managed Windows worker fleet is not the
proportionate answer to T-3 at that scale, and this ADR argued for one because the threat model it
was written against used malware-analysis framing: "dynamic analysis executes hostile code".

The analysed binary is benign but untrusted. The real exposure is narrower and differently shaped:
confirming a memory-corruption bug means driving a program off its intended path with inputs built
to corrupt it, so a working proof of concept executes attacker-shaped data — on the analyst's own
machine, beside their keys and every other customer's binary.

**The decision now, in order of cost:**

1. **Run ReTrace on the reverse-engineering VM the analyst already has**, next to x64dbg and
   Ghidra, rather than on their daily workstation. Configuration and a paragraph of documentation.
   It closes most of the exposure and costs nothing to build.
2. **Refuse unisolated dynamic execution on a shared install** — implemented
   (`allow_unisolated_execution`, forced false on `team`).
3. **A subprocess target** for write-class work, so limits bind the job rather than the
   application — implemented.

A worker fleet is reconsidered only if customers start running assessments unattended at a scale
where (1) stops being practical. What remains true from the original ADR: x64dbg, Procmon and
Frida need a real Windows kernel and do not containerise, so if isolation is ever built it is a VM
and not a container.
