"""Single source of truth for multi-file ingest and HTTP upload limits.

Batch (one artifact per file) and bundle (one combined artifact) endpoints use
the same cap on multipart ``files`` parts / ``members`` rows per request.
"""


MAX_MULTIPART_SOURCE_FILES = 1024

MAX_UPLOAD_BYTES_PER_FILE = 2 * 1024 * 1024
