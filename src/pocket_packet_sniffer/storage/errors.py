"""Storage-layer exceptions with stable, caller-facing meanings."""


class RepositoryError(Exception):
    """Base class for repository failures."""


class InvalidRecordError(RepositoryError, ValueError):
    """A packet record or query filter is malformed."""


class DuplicateRecordError(RepositoryError):
    """A record with the same record ID already exists."""


class StorageUnavailableError(RepositoryError):
    """A referenced capture or metadata file is missing or unavailable."""


class StorageAccessError(RepositoryError):
    """The process cannot read or write the configured storage location."""


class StorageCorruptionError(RepositoryError):
    """PCAP or indexed metadata is malformed or inconsistent."""
