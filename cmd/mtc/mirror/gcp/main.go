// Copyright 2026 The Tessera authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// gcp runs an MTC tlog-mirror server backed by Tessera's GCP storage implementation.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"cloud.google.com/go/spanner"
	gcs "cloud.google.com/go/storage"
	fnote "github.com/transparency-dev/formats/note"
	"github.com/transparency-dev/tessera/cmd/mtc/mirror"
	"github.com/transparency-dev/tessera/storage/gcp"
	witnessConfig "github.com/transparency-dev/witness/config"
	wspanner "github.com/transparency-dev/witness/persistence/spanner"
	"github.com/transparency-dev/witness/witness"
	"golang.org/x/mod/sumdb/note"
)

const (
	// spannerTablePrefixHashLen is the number of hex characters of a mirrored log's origin hash which are used
	// in the prefix of the names of the Spanner tables holding that log's state.
	spannerTablePrefixHashLen = 16
)

var (
	listenAddr                = flag.String("listen_addr", ":8080", "The address to listen on for HTTP requests.")
	bucket                    = flag.String("bucket", "", "Name of the GCS bucket to store mirrored log data in. Each mirrored log is stored under the lowercase hex-encoded SHA-256 hash of its origin, so the bucket root should be made publicly readable and used as the mirror's monitoring prefix.")
	spannerDB                 = flag.String("spanner", "", "Spanner database URI to store mirror coordination and witness state in. Format: projects/{projectId}/instances/{instanceId}/databases/{databaseId}.")
	mirrorCosignerSecretName  = flag.String("mirror_cosigner_private_key_secret_name", "", "Secret Manager resource name of the note-formatted MLDSA mirror cosigner secret key. Format: projects/{projectId}/secrets/{secretName}/versions/{secretVersion}.")
	witnessCosignerSecretName = flag.String("witness_cosigner_private_key_secret_name", "", "Optional Secret Manager resource name of the note-formatted MLDSA witness cosigner secret key. Format: projects/{projectId}/secrets/{secretName}/versions/{secretVersion}.")
	mirrorConfigPath          = flag.String("config_path", "", "The path to the mirror configuration file.")
	slogLevel                 = flag.Int("slog_level", 0, "The cut-off threshold for structured logging.")

	readHeaderTimeout = flag.Duration("read_header_timeout", 5*time.Second, "The maximum duration for reading request headers.")
	idleTimeout       = flag.Duration("idle_timeout", 60*time.Second, "The maximum amount of time to wait for the next request when keep-alives are enabled.")
	readTimeout       = flag.Duration("read_timeout", 0, "The maximum duration for reading the entire request. Default 0 permits streaming add-entries uploads.")
	writeTimeout      = flag.Duration("write_timeout", 0, "The maximum duration before timing out writes of the response.")
	maxHeaderBytes    = flag.Int("max_header_bytes", http.DefaultMaxHeaderBytes, "Maximum number of bytes the server will read parsing request headers.")
)

func main() {
	flag.Parse()
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.Level(*slogLevel)})))
	ctx := context.Background()

	// Validate the local configuration before making any calls to GCP.
	logs := mirrorLogsFromFlags(ctx)
	storageCfg := storageConfigFromFlags(ctx)

	witnessCosigners, mirrorCosigner := cosignersFromFlags(ctx)

	w, wp, shutdown := witnessFromFlags(ctx, witnessCosigners)
	defer func() {
		if err := shutdown(); err != nil {
			slog.ErrorContext(ctx, "Failed to shut down Witness", slog.Any("error", err))
		}
	}()

	// The GCP clients are shared by the storage of all mirrored logs.
	gcsClient, err := gcs.NewClient(ctx, gcs.WithJSONReads())
	if err != nil {
		slog.ErrorContext(ctx, "Failed to create GCS client", slog.Any("error", err))
		os.Exit(1)
	}
	defer func() {
		if err := gcsClient.Close(); err != nil {
			slog.ErrorContext(ctx, "Failed to close GCS client", slog.Any("error", err))
		}
	}()
	spannerClient, err := spanner.NewClient(ctx, storageCfg.Spanner)
	if err != nil {
		slog.ErrorContext(ctx, "Failed to create Spanner client", slog.Any("error", err))
		os.Exit(1)
	}
	defer spannerClient.Close()
	storageCfg.GCSClient = gcsClient
	storageCfg.SpannerClient = spannerClient

	cfg := mirrorConfigFromLogs(ctx, storageCfg, logs)
	for _, l := range cfg {
		// Ensure log is known by the witness
		if err := wp.AddLogs(ctx, []witnessConfig.Log{l.Log}); err != nil {
			slog.ErrorContext(ctx, "Failed to add target log to witness", slog.String("origin", l.Log.Origin), slog.Any("error", err))
			os.Exit(1)
		}
	}
	m, err := mirror.New(ctx, w, mirrorCosigner, cfg)
	if err != nil {
		slog.ErrorContext(ctx, "Failed to create mirror", slog.Any("error", err))
		os.Exit(1)
	}

	var protocols http.Protocols
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)

	// TODO(security): The tlog-mirror and tlog-witness endpoints are unauthenticated by design, since the validity
	// of each request is established by verifying the log signatures and proofs it carries. Rate limiting, if
	// required, should be applied by the serving infrastructure (e.g. Cloud Armor, or Cloud Run instance limits).
	server := &http.Server{
		Addr:              *listenAddr,
		Handler:           m,
		Protocols:         &protocols,
		ReadHeaderTimeout: *readHeaderTimeout,
		IdleTimeout:       *idleTimeout,
		ReadTimeout:       *readTimeout,
		WriteTimeout:      *writeTimeout,
		MaxHeaderBytes:    *maxHeaderBytes,
	}

	slog.InfoContext(ctx, "Starting mirror service", slog.String("addr", *listenAddr))
	if err := server.ListenAndServe(); err != nil {
		slog.ErrorContext(ctx, "ListenAndServe failed", slog.Any("error", err))
		os.Exit(1)
	}
}

// mirrorLogsFromFlags returns the logs to be mirrored, read from the mirror configuration file specified by flags.
// Exits if the mirror configuration could not be read, or is invalid.
func mirrorLogsFromFlags(ctx context.Context) []witnessConfig.Log {
	if *mirrorConfigPath == "" {
		slog.ErrorContext(ctx, "Mirror config path not specified")
		os.Exit(1)
	}
	data, err := os.ReadFile(*mirrorConfigPath)
	if err != nil {
		slog.ErrorContext(ctx, "Failed to read mirror config file", slog.String("path", *mirrorConfigPath), slog.Any("error", err))
		os.Exit(1)
	}
	logs, err := parseMirrorConfig(bytes.NewReader(data))
	if err != nil {
		slog.ErrorContext(ctx, "Invalid mirror config", slog.String("path", *mirrorConfigPath), slog.Any("error", err))
		os.Exit(1)
	}
	return logs
}

// parseMirrorConfig parses a mirror configuration in the public witness network log list format, and returns the
// logs to be mirrored.
// Returns an error if the configuration is invalid, or contains duplicate origins.
func parseMirrorConfig(r io.Reader) ([]witnessConfig.Log, error) {
	cfg, err := witnessConfig.ParsePublicWitnessConfig(r)
	if err != nil {
		return nil, fmt.Errorf("failed to parse mirror config: %v", err)
	}
	seenOrigins := make(map[string]struct{}, len(cfg))
	for i := range cfg {
		if cfg[i].Origin == "" {
			cfg[i].Origin = cfg[i].Verifier.Name()
		}
		o := cfg[i].Origin
		if _, seen := seenOrigins[o]; seen {
			return nil, fmt.Errorf("duplicate origin %q in mirror config", o)
		}
		seenOrigins[o] = struct{}{}
	}
	return cfg, nil
}

// storageConfigFromFlags returns the GCP storage configuration shared by all mirrored logs, using flags as the source
// of information.
// Exits if any of the required flags are not set.
func storageConfigFromFlags(ctx context.Context) gcp.Config {
	if *bucket == "" {
		slog.ErrorContext(ctx, "--bucket must be set")
		os.Exit(1)
	}
	if *spannerDB == "" {
		slog.ErrorContext(ctx, "--spanner must be set")
		os.Exit(1)
	}
	return gcp.Config{
		Bucket:  *bucket,
		Spanner: *spannerDB,
	}
}

// mirrorConfigFromLogs returns a slice of mirror.LogConfig structs for the provided logs, each with a GCP storage
// driver derived from the provided base storage configuration.
// Exits if the storage for any of the logs could not be configured.
func mirrorConfigFromLogs(ctx context.Context, base gcp.Config, logs []witnessConfig.Log) []mirror.LogConfig {
	tablePrefixOrigins := make(map[string]string, len(logs))
	ret := make([]mirror.LogConfig, 0, len(logs))
	for _, l := range logs {
		lCfg := logStorageConfig(base, l.Origin)
		// Logs sharing Spanner tables would corrupt each other's state, so refuse to start if that would happen.
		if other, ok := tablePrefixOrigins[lCfg.SpannerTablePrefix]; ok {
			slog.ErrorContext(ctx, "Spanner table prefix collision between mirrored logs", slog.String("origin", l.Origin), slog.String("other_origin", other), slog.String("spanner_table_prefix", lCfg.SpannerTablePrefix))
			os.Exit(1)
		}
		tablePrefixOrigins[lCfg.SpannerTablePrefix] = l.Origin

		d, err := gcp.New(ctx, lCfg)
		if err != nil {
			slog.ErrorContext(ctx, "Failed to create mirror target", slog.String("origin", l.Origin), slog.Any("error", err))
			os.Exit(1)
		}
		slog.InfoContext(ctx, "Configured mirror target storage", slog.String("origin", l.Origin), slog.String("bucket", lCfg.Bucket), slog.String("bucket_prefix", lCfg.BucketPrefix), slog.String("spanner_table_prefix", lCfg.SpannerTablePrefix))
		ret = append(ret, mirror.LogConfig{
			Log:    l,
			Driver: d,
		})
	}
	return ret
}

// logStorageConfig returns a copy of the provided base storage configuration, updated to store the state of the log
// with the provided origin separately from that of any other log.
//
// The log's data is stored in the bucket under its origin hash, so that the bucket root can be used as the mirror's
// monitoring prefix, and its coordination state is stored in Spanner tables named with a prefix derived from the same
// hash.
func logStorageConfig(base gcp.Config, origin string) gcp.Config {
	oh := originHash(origin)
	base.BucketPrefix = oh
	base.SpannerTablePrefix = fmt.Sprintf("mirror_%s_", oh[:spannerTablePrefixHashLen])
	return base
}

// originHash returns the lowercase hex-encoded SHA-256 hash of the provided log origin.
//
// SPEC: For each monitoring prefix, the mirror's copy of a log has a URL prefix of <monitoring prefix>/<origin hash>,
// where origin hash is the SHA-256 hash of the log's origin, hex encoded, in lowercase.
func originHash(origin string) string {
	h := sha256.Sum256([]byte(origin))
	return hex.EncodeToString(h[:])
}

// witnessFromFlags returns a witness instance whose state is stored in the Spanner database specified by flags, and
// which uses the provided signers to cosign checkpoints.
// Exits if the witness could not be created.
//
// The returned shutdown func should be called once the witness is no longer in use.
func witnessFromFlags(ctx context.Context, signers []note.Signer) (*witness.Witness, *wspanner.Persistence, func() error) {
	p, shutdown, err := wspanner.New(ctx, *spannerDB)
	if err != nil {
		slog.ErrorContext(ctx, "Failed to create witness persistence", slog.String("spanner", *spannerDB), slog.Any("error", err))
		os.Exit(1)
	}

	w, err := witness.New(ctx, witness.Opts{
		Persistence: p,
		Signers:     signers,
		VerifierForLog: func(ctx context.Context, origin string) (note.Verifier, bool, error) {
			log, ok, err := p.Log(ctx, origin)
			if err != nil || !ok {
				return nil, false, err
			}
			return log.Verifier, true, nil
		},
	})
	if err != nil {
		slog.ErrorContext(ctx, "Failed to create witness", slog.Any("error", err))
		os.Exit(1)
	}
	return w, p, shutdown
}

// cosignersFromFlags returns the witness and mirror cosigners, whose secret keys are read from Google Cloud Secret
// Manager as specified by flags.
// Exits if the cosigners could not be created.
func cosignersFromFlags(ctx context.Context) ([]note.Signer, fnote.SubtreeSigner) {
	if *mirrorCosignerSecretName == "" {
		slog.ErrorContext(ctx, "--mirror_cosigner_private_key_secret_name must be set")
		os.Exit(1)
	}

	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		slog.ErrorContext(ctx, "Failed to create Secret Manager client", slog.Any("error", err))
		os.Exit(1)
	}
	defer func() {
		if err := client.Close(); err != nil {
			slog.WarnContext(ctx, "Failed to close Secret Manager client", slog.Any("error", err))
		}
	}()
	access := func(ctx context.Context, req *secretmanagerpb.AccessSecretVersionRequest) (*secretmanagerpb.AccessSecretVersionResponse, error) {
		return client.AccessSecretVersion(ctx, req)
	}

	mirrorCosigner := mustCreateCosigner(ctx, access, *mirrorCosignerSecretName)
	if *witnessCosignerSecretName == "" {
		slog.WarnContext(ctx, "Witness cosigner not configured, add-checkpoint will not return cosigs")
		return []note.Signer{}, mirrorCosigner
	}
	return []note.Signer{mustCreateCosigner(ctx, access, *witnessCosignerSecretName)}, mirrorCosigner
}

// mustCreateCosigner returns a cosigner whose secret key is read from the named Secret Manager secret version.
// Exits if the cosigner could not be created.
func mustCreateCosigner(ctx context.Context, access accessSecretVersionFunc, secretName string) fnote.SubtreeSigner {
	s, err := newSecretManagerCosigner(ctx, access, secretName)
	if err != nil {
		slog.ErrorContext(ctx, "Failed to create cosigner", slog.String("secret_name", secretName), slog.Any("error", err))
		os.Exit(1)
	}
	return s
}
