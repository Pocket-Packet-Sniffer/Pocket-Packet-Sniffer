# ADR 0001: Explicit Analysis-to-Storage Record Adapter

- **Status:** Proposed in PR review
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

This is a proposed design decision in this PR; the layer owners should confirm it during review. If the team requires a single shared record class instead, agree that alternative explicitly and update this ADR, the SASD, and the RTM together.

## Alternatives considered

- **Make Analysis import Storage's PacketRecord:** rejected because it reverses the layer dependency and makes Analysis depend on persistence details.
- **Drop original bytes after parsing:** rejected because Storage must persist PCAP data.
- **Use a new shared domain package:** possible, but it would require moving/reworking the current Storage model and validation. The explicit application adapter is the smaller, testable boundary for this iteration.

## Consequences

- Analysis remains independent of concrete Storage implementation.
- The application boundary has one clear mapping location and tests catch field loss.
- Two record types remain intentionally distinct; changes to either contract must update the adapter and integration tests.
- The exact decision is pending team review; it is not treated as approved until the layer owners review this PR.
