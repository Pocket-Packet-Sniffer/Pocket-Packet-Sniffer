# ADR 0001: Explicit Analysis-to-Storage Record Adapter

- **Status:** Accepted for the current implementation (maintainer closeout decision)
- **Date:** 2026-10-26
- **Decision owners:** Layer owners; review requested from the full team

## Context

The Capture Layer emits `CapturedPacket`, which carries the raw link-layer bytes and capture metadata. The Analysis Layer emits a normalized `analysis.models.PacketRecord` with protocol, addresses, capture timestamp, packet size, interface, link type, and backend. The Storage Layer's `storage.models.PacketRecord` also needs a session identifier, original bytes, persistence identifier, and storage constraints.

Treating these two Python record classes as interchangeable would couple Analysis to persistence details or lose raw bytes needed for PCAP storage. The repository should keep Analysis independent of the concrete Storage implementation.

## Decision

Use an explicit adapter at the application boundary, implemented by `application.CaptureSession`:

1. Capture delivers a backend-neutral `CapturedPacket`.
2. Analysis parses it into normalized metadata using `PacketParser` or `AnalyzerPipeline`.
3. The application session combines normalized fields with the original `CapturedPacket.packet_data`, link type, and original length to create the Storage record with its session ID.
4. Storage receives only its own validated record and persists PCAP bytes plus indexed metadata.

Analysis does not import the Storage package. The adapter preserves the original captured bytes and is covered by generated-PCAP integration tests.

For Sprint 1 closeout, the project maintainer accepts this application-boundary adapter as the implemented contract: the Analysis record is metadata-only; Storage's record retains session identity and original frame bytes. The layer owners may propose a different shared-domain model in a follow-up ADR if a later review or an explicit SRS/SASD requirement demands it. Do not make Analysis import the concrete Storage implementation as an unreviewed workaround.

## Alternatives considered

- **Make Analysis import Storage's PacketRecord:** rejected because it reverses the layer dependency and makes Analysis depend on persistence details.
- **Drop original bytes after parsing:** rejected because Storage must persist PCAP data.
- **Use a new shared domain package:** possible, but it would require moving/reworking the current Storage model and validation. The explicit application adapter is the smaller, testable boundary for this iteration.

## Consequences

- Analysis remains independent of concrete Storage implementation.
- The application boundary has one clear mapping location and tests catch field loss.
- Two record types remain intentionally distinct; changes to either contract must update the adapter and integration tests.
- This decision documents the architecture shipped in PR #24. A future alternative requires a reviewed ADR and coordinated code/traceability changes.
