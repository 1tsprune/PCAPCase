# PCAPCase Output Schema v1.0

This document is the stable output contract for PCAPCase v1.0. Fields listed here will not be removed, renamed, or have their type changed without a major version bump. New optional fields may be added in minor releases when they do not break existing consumers.

All timestamps are UTC ISO-8601 strings ending in `Z`. JSON output is UTF-8, pretty-printed, and deterministic with sorted keys where practical. CSV output is UTF-8 with a header row and deterministic row ordering.

PCAPCase outputs are offline artifacts. They must not contain API keys, raw PCAP bytes, executed content, or unredacted secrets.

## Common primitives

| Type | Format |
| --- | --- |
| `timestamp` | ISO-8601 UTC string, e.g. `2024-01-01T00:00:00Z` |
| `sha256` | Lowercase hex SHA-256 string, 64 characters |
| `severity` | `critical`, `high`, `medium`, `low`, `info` |
| `confidence` | `high`, `medium`, `low` |
| `indicator_type` | `ip`, `domain`, `url`, `hash`, `filename`, `user_agent`, `sni` |

## `case.json`

Top-level object:

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `capture` | object | yes | Capture metadata. |
| `hosts` | array[`Host`] | yes | Host inventory. |
| `events` | array[`NetworkEvent`] | yes | Timeline events. |
| `indicators` | array[`Indicator`] | yes | Extracted IOCs. |
| `extracted_objects` | array[`ExtractedObject`] | yes | Safely carved objects, if any. |
| `findings` | array[`Finding`] | yes | Evidence-backed findings. |
| `run` | object | yes | PCAPCase run metadata. |

### `CaptureMetadata`

| Field | Type | Required |
| --- | --- | --- |
| `path` | string | yes |
| `sha256` | sha256 | yes |
| `tshark_version` | string or null | yes |
| `frame_count` | integer or null | yes |
| `first_seen` | timestamp or null | yes |
| `last_seen` | timestamp or null | yes |
| `duration_seconds` | number or null | yes |

### `RunMetadata`

| Field | Type | Required |
| --- | --- | --- |
| `pcapcase_version` | string | yes |
| `started_at` | timestamp | yes |
| `cli_args` | array[string] | yes |
| `tshark_version` | string or null | yes |
| `input_sha256` | sha256 or null | yes |
| `output_directory` | string or null | yes |

## `findings.json`

Array of `Finding` objects. Same objects also appear under `case.json.findings`.

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `id` | string | yes | Deterministic finding ID. |
| `title` | string | yes | Short finding title. |
| `description` | string | yes | Analyst-readable description. |
| `severity` | severity | yes | Finding severity. |
| `confidence` | confidence | yes | Detection confidence. |
| `category` | string | yes | Behavior category. |
| `first_seen` | timestamp | yes | First evidence timestamp. |
| `last_seen` | timestamp | yes | Last evidence timestamp. |
| `source_hosts` | array[string] | yes | Source hosts observed in evidence. |
| `destination_hosts` | array[string] | yes | Destination hosts observed in evidence. |
| `evidence` | array[`Evidence`] | yes | Frame-level evidence. |
| `recommendations` | array[string] | yes | Analyst next steps. |
| `mitre_attack` | array[object] | yes | Optional ATT&CK mappings. Empty when not applicable. |

### `Evidence`

Every finding must contain at least one `Evidence` object.

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `frame_number` | integer | yes | Packet frame reference. May be `0` only for derived file-only evidence such as local YARA matches. |
| `timestamp` | timestamp | yes | Evidence timestamp. |
| `protocol` | string | yes | Protocol or evidence source. |
| `tcp_stream` | integer or null | yes | TCP stream when known. |
| `field` | string | yes | TShark/model field supporting the claim. |
| `value` | string | yes | Redacted value supporting the claim. |
| `reproduction_command` | string | yes | Reproducible local command. |

## `iocs.json`

Array of `Indicator` objects. Same objects also appear under `case.json.indicators`.

| Field | Type | Required |
| --- | --- | --- |
| `type` | indicator_type | yes |
| `value` | string | yes |
| `first_seen` | timestamp | yes |
| `last_seen` | timestamp | yes |
| `source` | string | yes |
| `evidence` | array[`Evidence`] | yes |

Indicator values must pass the active redaction rules before writing.

## `hosts.csv`

Header order is stable:

```csv
ip,mac_addresses,hostnames,protocols,first_seen,last_seen,sent_events,received_events
```

| Column | Type | Description |
| --- | --- | --- |
| `ip` | string | Host IP. |
| `mac_addresses` | semicolon-delimited string | Observed MAC addresses. |
| `hostnames` | semicolon-delimited string | Observed hostnames. |
| `protocols` | semicolon-delimited string | Protocols observed for host. |
| `first_seen` | timestamp or empty | First event. |
| `last_seen` | timestamp or empty | Last event. |
| `sent_events` | integer | Events where host is source. |
| `received_events` | integer | Events where host is destination. |

## `timeline.csv`

Header order is stable:

```csv
timestamp,frame_number,protocol,event_type,src_ip,src_port,dst_ip,dst_port,stream_id,summary
```

| Column | Type | Description |
| --- | --- | --- |
| `timestamp` | timestamp | Event time. |
| `frame_number` | integer | Frame number. |
| `protocol` | string | Normalized protocol. |
| `event_type` | string | Normalized event type. |
| `src_ip` | string or empty | Source IP. |
| `src_port` | integer or empty | Source port. |
| `dst_ip` | string or empty | Destination IP. |
| `dst_port` | integer or empty | Destination port. |
| `stream_id` | integer or empty | TCP stream. |
| `summary` | string | Redacted event summary. |

## `extracted-files/manifest.json`

Top-level object:

| Field | Type | Required |
| --- | --- | --- |
| `schema_version` | string | yes, value `1.0` |
| `objects` | array[`ExtractedObject`] | yes |

### `ExtractedObject`

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `sha256` | sha256 | yes | Hash of carved bytes. |
| `original_filename` | string | yes | Sanitized original filename. |
| `sanitized_filename` | string | yes | Filesystem-safe stored filename. |
| `size` | integer | yes | Size in bytes. |
| `source_frame` | integer or null | yes | Source frame when available. |
| `tcp_stream` | integer or null | yes | TCP stream when available. |
| `extraction_timestamp` | timestamp | yes | Local extraction time. |
| `path` | string | yes | Output path under `extracted-files/`. |
| `yara_matches` | array[object] | yes | Optional local YARA metadata; empty by default. |

Extracted object names must be sanitized and must not allow path traversal. Extracted files are never executed.

## `rerun-manifest.json`

`rerun-manifest.json` is an audit artifact, not part of deterministic analytical output. It records run-specific inputs such as timestamp and CLI args.

| Field | Type | Required |
| --- | --- | --- |
| `schema_version` | string | yes, value `1.0` |
| `pcapcase_version` | string | yes |
| `run_timestamp` | timestamp | yes |
| `input_path` | string | yes |
| `input_sha256` | sha256 | yes |
| `tshark_version` | string or null | yes |
| `cli_args` | array[string] | yes |
| `output_directory` | string | yes |
| `python_version` | string | yes |
| `filters` | object | yes |
| `optional_features` | object | yes |

## Compatibility policy

Schema v1.0 is stable for PCAPCase 1.x. Breaking changes require PCAPCase 2.0 and a new schema version. Additive optional fields may appear in 1.x releases, but required fields and CSV header order will remain stable.
