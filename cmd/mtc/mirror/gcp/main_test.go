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

package main

import (
	"crypto/rand"
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/transparency-dev/tessera/storage/gcp"
	"golang.org/x/mod/sumdb/note"
)

func TestOriginHash(t *testing.T) {
	for _, test := range []struct {
		desc   string
		origin string
		want   string
	}{
		{
			desc:   "oid origin",
			origin: "oid/1.3.6.1.4.1.11129.11.99.1.0.1",
			want:   "12d74ca719a449e646f048b929c1723e2b80a0501bc588a9d689a80ee49c7e5a",
		},
		{
			desc:   "URL-style origin",
			origin: "example.com/log",
			want:   "4d3203c8f35cdf600e475f55fede6081a703d3d322f208865fca2ec4f0e030f8",
		},
	} {
		t.Run(test.desc, func(t *testing.T) {
			if got := originHash(test.origin); got != test.want {
				t.Errorf("originHash(%q) = %q, want %q", test.origin, got, test.want)
			}
		})
	}
}

func TestLogStorageConfig(t *testing.T) {
	base := gcp.Config{
		Bucket:  "mirror-bucket",
		Spanner: "projects/p/instances/i/databases/d",
	}
	for _, test := range []struct {
		desc             string
		origin           string
		wantBucketPrefix string
		wantTablePrefix  string
	}{
		{
			desc:             "oid origin",
			origin:           "oid/1.3.6.1.4.1.11129.11.99.1.0.1",
			wantBucketPrefix: "12d74ca719a449e646f048b929c1723e2b80a0501bc588a9d689a80ee49c7e5a",
			wantTablePrefix:  "mirror_12d74ca719a449e6_",
		},
		{
			desc:             "URL-style origin",
			origin:           "example.com/log",
			wantBucketPrefix: "4d3203c8f35cdf600e475f55fede6081a703d3d322f208865fca2ec4f0e030f8",
			wantTablePrefix:  "mirror_4d3203c8f35cdf60_",
		},
		{
			// The origin length is limited to 255 bytes by the handler.
			desc:             "max length origin",
			origin:           strings.Repeat("a", 255),
			wantBucketPrefix: "b0f3323e7a3cad8ae6778340cc2a17ae0cb31c818df3767cda7c3dd423725e90",
			wantTablePrefix:  "mirror_b0f3323e7a3cad8a_",
		},
	} {
		t.Run(test.desc, func(t *testing.T) {
			got := logStorageConfig(base, test.origin)
			// Compare fields individually, rather than the whole struct, so that this test doesn't depend on
			// gcp.Config remaining comparable.
			for _, f := range []struct {
				name      string
				got, want string
			}{
				{name: "Bucket", got: got.Bucket, want: base.Bucket},
				{name: "Spanner", got: got.Spanner, want: base.Spanner},
				{name: "BucketPrefix", got: got.BucketPrefix, want: test.wantBucketPrefix},
				{name: "SpannerTablePrefix", got: got.SpannerTablePrefix, want: test.wantTablePrefix},
			} {
				if f.got != f.want {
					t.Errorf("logStorageConfig(%q).%s = %q, want %q", test.origin, f.name, f.got, f.want)
				}
			}
			// Check that the GCP storage implementation accepts the derived config, in particular the table prefix.
			if _, err := gcp.New(t.Context(), got); err != nil {
				t.Errorf("gcp.New() rejected derived config: %v", err)
			}
		})
	}
}

func TestParseMirrorConfig(t *testing.T) {
	vkey := func(name string) string {
		t.Helper()
		_, v, err := note.GenerateKey(rand.Reader, name)
		if err != nil {
			t.Fatalf("GenerateKey(%q): %v", name, err)
		}
		return v
	}
	log1VKey := vkey("example.com/log1")
	log2VKey := vkey("example.com/log2")
	log3VKey := vkey("example.com/log3")

	for _, test := range []struct {
		desc        string
		config      string
		wantOrigins []string
		wantErr     bool
	}{
		{
			desc:        "no logs",
			config:      "logs/v0\n",
			wantOrigins: []string{},
		},
		{
			desc:        "origin defaults to vkey name",
			config:      fmt.Sprintf("logs/v0\nvkey %s\n", log1VKey),
			wantOrigins: []string{"example.com/log1"},
		},
		{
			desc:        "explicit origin",
			config:      fmt.Sprintf("logs/v0\nvkey %s\norigin oid/1.2.3\n", log1VKey),
			wantOrigins: []string{"oid/1.2.3"},
		},
		{
			desc:        "multiple logs",
			config:      fmt.Sprintf("logs/v0\n\n# First log\nvkey %s\n\n# Second log\nvkey %s\norigin oid/1.2.3\n", log1VKey, log2VKey),
			wantOrigins: []string{"example.com/log1", "oid/1.2.3"},
		},
		{
			desc:    "duplicate log",
			config:  fmt.Sprintf("logs/v0\nvkey %s\nvkey %s\n", log1VKey, log1VKey),
			wantErr: true,
		},
		{
			desc:    "duplicate origin with different keys",
			config:  fmt.Sprintf("logs/v0\nvkey %s\nvkey %s\norigin example.com/log1\n", log1VKey, log3VKey),
			wantErr: true,
		},
		{
			desc:    "missing header",
			config:  fmt.Sprintf("vkey %s\n", log1VKey),
			wantErr: true,
		},
		{
			desc:    "invalid vkey",
			config:  "logs/v0\nvkey not-a-valid-vkey\n",
			wantErr: true,
		},
	} {
		t.Run(test.desc, func(t *testing.T) {
			logs, err := parseMirrorConfig(strings.NewReader(test.config))
			if gotErr := err != nil; gotErr != test.wantErr {
				t.Fatalf("parseMirrorConfig() error = %v, wantErr %t", err, test.wantErr)
			}
			if test.wantErr {
				return
			}
			gotOrigins := make([]string, 0, len(logs))
			for _, l := range logs {
				gotOrigins = append(gotOrigins, l.Origin)
			}
			if diff := cmp.Diff(test.wantOrigins, gotOrigins); diff != "" {
				t.Errorf("parseMirrorConfig() origins mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
