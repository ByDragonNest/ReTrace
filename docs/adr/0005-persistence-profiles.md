# ADR 0005 — One repository interface, SQLite and PostgreSQL adapters

**Status:** SUPERSEDED 2026-10-13 by the scope decision below · **Closes:** P2-15 (partly)

## Context
Projects live in SQLite (`reforge.db`) mirrored to `projects/*.json`; jobs are in-process,
persisted to `jobs/` and restored at startup. There are no migrations, no optimistic locking on
findings, no object storage, no durable queue, no backup/restore and no retention. This is a
sound single-workstation design and an unsound multi-user one.

## Decision
Define `FindingRepository`, `EvidenceStore`, `ArtifactStore` and `JobQueue` as interfaces in the
domain layer. Ship two adapter sets:
- **workstation** — SQLite + local filesystem + in-process queue, no external service;
- **enterprise** — PostgreSQL + object storage + durable queue.

Both get: versioned, reversible migrations with a mandatory pre-migration backup; optimistic
locking/versioning on findings; configurable retention with verifiable per-project deletion;
documented backup and restore. The JSON mirror becomes an export format, not a second store.

## Consequences
No infrastructure is imposed on the single-analyst user, and nothing in the domain layer knows
which adapter is active. Cost: an adapter boundary to maintain and migrations to write for two
backends. Accepted, because the alternative is a product that cannot leave one laptop.

## Alternatives rejected
*PostgreSQL everywhere* — kills the zero-dependency workstation profile, which is a differentiator.
*SQLite everywhere* — no concurrent multi-user writes, no HA.


---

## Superseded (2026-10-13)

ReTrace targets **a single analyst and small teams**. SQLite is the right database for that, and a
second adapter set is work with no one to serve: a PostgreSQL adapter exists to support
concurrent writers across nodes, and this product has one node.

**The decision now:** SQLite, and the parts of this ADR that were about *discipline* rather than
*scale* are kept and are implemented —

* versioned, reversible migrations with a **mandatory** pre-migration backup;
* optimistic locking, so two people with the same project open cannot silently overwrite each
  other — which is the concurrency problem a small team actually has;
* retention with soft-delete and a separate, deliberate purge;
* pruned backups.

What is dropped: the PostgreSQL adapter, object storage, the durable queue, and the repository
interface that existed to abstract between them. An interface with one implementation is
indirection, not abstraction.

SQLite's limit for this shape of product is concurrent *writers*, not data volume or users. If a
team outgrows it, the symptom will be write contention on `projects`, and that is the signal to
revisit — not a headcount.
