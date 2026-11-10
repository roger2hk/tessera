# GCP MTC Mirror

This directory contains an MTC mirror server backed by Tessera's GCP storage implementation.
The server's HTTP API is intended to comply with the [`tlog-mirror`](https://c2sp.org/tlog-mirror)
specification.

A `tlog-mirror` is both:
- a regular `tlog-witness` server which can optionally be configured to sign consistent log checkpoints
- an additional "extended" `tlog-witness` which will sign a consistent checkpoint only once it has _also_
  stored a copy of the log content which that checkpoint commits to.

A [POSIX implementation](../posix/) of this server is also available.

> [!WARNING]
> This binary and the internal packages it uses are still under active development, and should be
> considered experimental and not production-ready. They remain outside the SemVer policy.

## Storage overview

This server uses the following GCP services:
- [GCS](https://cloud.google.com/storage): a bucket stores the mirrored log data, which is intended to be
  publicly readable.
- [Spanner](https://cloud.google.com/spanner): a database stores the mirror's coordination state, and the
  state of its integrated witness.
- [Secret Manager](https://cloud.google.com/secret-manager): stores the mirror's cosigner key, and
  optionally the witness cosigner key.

### GCS

The mirrored log data is stored in the bucket provided via the `--bucket` flag, using the following layout:
```
gs://${BUCKET}
├── 2ee6a567373ee0c7d6783ae6633e61...  # Each mirrored log is stored under the lower-cased hex-encoded SHA256 hash
├── cf89f0e5f78e09351f0fa84efa5bc3...  # of its origin, following the tlog-tiles layout (checkpoint, tile/, etc.)
└── ...
```

This follows the `tlog-mirror` specification, which requires that each mirrored log is served at
`<monitoring prefix>/<origin hash>`. The root of the bucket should therefore be made publicly readable,
and its URL (e.g. `https://storage.googleapis.com/${BUCKET}`, or that of a CDN in front of it) used as the
mirror's monitoring prefix.

> [!WARNING]
> Since the contents of this bucket are intended to be public, it should be dedicated to this mirror and not
> used to store anything else.

### Spanner

The mirror's state is stored in the database provided via the `--spanner` flag, in the following tables:
```
${SPANNER_DB}
├── checkpoints                    # State for the integrated Tessera witness used by the
├── logs                           # `add-checkpoint` endpoint.
│
├── mirror_2ee6a567373ee0c7_*      # Coordination state for each mirrored log is stored in its own set of
├── mirror_cf89f0e5f78e0935_*      # tables, which are prefixed with the first 16 characters of the
└── ...                            # corresponding origin hash.
```

All tables are created automatically on startup if they don't already exist. It's recommended that a
database be dedicated to this mirror.

> [!NOTE]
> Feedback is very welcome, and we'd particularly love to hear opinions from potential operators on operational
> characteristics such as the storage details outlined above.

## Running

A quick getting-started guide is provided below.

### GCP resources

You will need a GCS bucket, a Spanner database, and the Secret Manager secrets described in the [Keys](#keys)
section below. The identity the server runs as (e.g. a service account) needs the following roles:

| Resource | Role | Reason |
|---|---|---|
| GCS bucket | `roles/storage.objectUser` | To read and write mirrored log data. |
| Spanner database | `roles/spanner.databaseAdmin` | To create tables on startup, and read and write state. |
| Cosigner key secrets | `roles/secretmanager.secretAccessor` | To read the cosigner keys on startup. |

To serve the mirrored log data publicly, grant `allUsers` the `roles/storage.objectViewer` role on the bucket
(this requires that public access prevention isn't enforced on it), or serve it through a CDN.

### Keys

You will need:
1. An MLDSA key to be used to cosign fully mirrored checkpoints.
2. Optionally, if you want your MTC mirror to also function as a "regular" witness, an additional MLDSA key to be
   used to cosign those checkpoints.

The private keys must be stored in Secret Manager in the note-formatted secret key format (`PRIVATE+KEY+...`),
and their secret versions passed to the server via the `--mirror_cosigner_private_key_secret_name` and
`--witness_cosigner_private_key_secret_name` flags respectively, in the form
`projects/{projectId}/secrets/{secretName}/versions/{secretVersion}`.

You can generate MLDSA key pairs and store them directly in Secret Manager with the
[`generate_keys_gcp`](https://github.com/transparency-dev/witness/blob/main/cmd/generate_keys_gcp/main.go) command
from the [witness](https://github.com/transparency-dev/witness) repo.

The command below will generate such a key pair, with an origin of "mirror.example.com/mtctest", storing the
private and public keys in the `witness-secret-mtc-mirror` and `witness-verifier-mtc-mirror` secrets
respectively:

```bash
go run github.com/transparency-dev/witness/cmd/generate_keys_gcp@main \
  --mldsa \
  --origin "mirror.example.com/mtctest" \
  --project_id "${PROJECT_ID}" \
  --resource_suffix "mtc-mirror"
```

The corresponding flag value for the mirror cosigner key would then be
`projects/${PROJECT_ID}/secrets/witness-secret-mtc-mirror/versions/1`.

> [!WARNING]
> Avoid using the `latest` secret version alias: the cosigner key would change if a newer version of the
> secret were created.

The set of logs which are permitted to be pushed to the mirror is defined by a configuration
file which uses the same format as the
[public witness network configuration file](https://witness-network.org/log-list-format/).

An example is provided in the [`example_config`](../posix/example_config) file of the POSIX mirror.

Edit this or create your own with appropriate entries. Then, place the config file in a suitable location.

### Starting the mirror server

An example command for starting the server is given below:

```bash
go run ./cmd/mtc/mirror/gcp \
  --bucket="${BUCKET}" \
  --spanner="projects/${PROJECT_ID}/instances/${SPANNER_INSTANCE}/databases/${SPANNER_DB}" \
  --mirror_cosigner_private_key_secret_name="projects/${PROJECT_ID}/secrets/witness-secret-mtc-mirror/versions/1" \
  --config_path=cmd/mtc/mirror/posix/example_config \
  --slog_level=-9
```

A Docker image can be built from the root of the repository with:

```bash
docker build -f cmd/mtc/mirror/gcp/Dockerfile -t mtc-mirror-gcp .
```

## Known limitations

- Tickets returned by `add-entries` can only be validated by the server instance which issued them, and are
  invalidated when it restarts. When running multiple instances behind a load balancer, clients may see more
  `409 Conflict` responses while uploading entries, so running a single instance is currently recommended.
- GCS limits the rate at which a single object can be updated to approximately once per second. Since a
  mirrored log's checkpoint is updated each time an upload completes, uploads for a given log which complete
  more frequently than that may fail and need to be retried.
- On startup, the server ensures that the Spanner tables for each mirrored log exist, so startup time increases
  with the number of mirrored logs.
