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
	"context"
	"crypto/rand"
	"errors"
	"hash/crc32"
	"testing"

	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	fnote "github.com/transparency-dev/formats/note"
	"golang.org/x/mod/sumdb/note"
)

func TestNewSecretManagerCosigner(t *testing.T) {
	const (
		secretName = "projects/p/secrets/mirror-key/versions/1"
		keyName    = "mirror.example.com/test"
	)
	mldsaSKey, mldsaVKey, err := fnote.GenerateMLDSAKey(keyName)
	if err != nil {
		t.Fatalf("GenerateMLDSAKey(): %v", err)
	}
	v, err := fnote.NewVerifier(mldsaVKey)
	if err != nil {
		t.Fatalf("NewVerifier(): %v", err)
	}
	ed25519SKey, _, err := note.GenerateKey(rand.Reader, keyName)
	if err != nil {
		t.Fatalf("GenerateKey(): %v", err)
	}

	checksum := func(data string) *int64 {
		c := int64(crc32.Checksum([]byte(data), crc32.MakeTable(crc32.Castagnoli)))
		return &c
	}
	resp := func(name, data string, crc *int64) *secretmanagerpb.AccessSecretVersionResponse {
		return &secretmanagerpb.AccessSecretVersionResponse{
			Name: name,
			Payload: &secretmanagerpb.SecretPayload{
				Data:       []byte(data),
				DataCrc32C: crc,
			},
		}
	}
	badChecksum := *checksum(mldsaSKey) + 1

	for _, test := range []struct {
		desc       string
		secretName string
		resp       *secretmanagerpb.AccessSecretVersionResponse
		respErr    error
		wantErr    bool
	}{
		{
			desc:       "valid MLDSA key",
			secretName: secretName,
			resp:       resp(secretName, mldsaSKey, checksum(mldsaSKey)),
		},
		{
			desc:       "valid MLDSA key with latest alias",
			secretName: "projects/p/secrets/mirror-key/versions/latest",
			resp:       resp("projects/p/secrets/mirror-key/versions/2", mldsaSKey, checksum(mldsaSKey)),
		},
		{
			desc:       "checksum mismatch",
			secretName: secretName,
			resp:       resp(secretName, mldsaSKey, &badChecksum),
			wantErr:    true,
		},
		{
			desc:       "missing checksum",
			secretName: secretName,
			resp:       resp(secretName, mldsaSKey, nil),
			wantErr:    true,
		},
		{
			desc:       "missing payload",
			secretName: secretName,
			resp:       &secretmanagerpb.AccessSecretVersionResponse{Name: secretName},
			wantErr:    true,
		},
		{
			desc:       "access error",
			secretName: secretName,
			respErr:    errors.New("permission denied"),
			wantErr:    true,
		},
		{
			desc:       "not an MLDSA key",
			secretName: secretName,
			resp:       resp(secretName, ed25519SKey, checksum(ed25519SKey)),
			wantErr:    true,
		},
		{
			desc:       "not a key",
			secretName: secretName,
			resp:       resp(secretName, "not a key", checksum("not a key")),
			wantErr:    true,
		},
	} {
		t.Run(test.desc, func(t *testing.T) {
			access := func(_ context.Context, req *secretmanagerpb.AccessSecretVersionRequest) (*secretmanagerpb.AccessSecretVersionResponse, error) {
				if got, want := req.GetName(), test.secretName; got != want {
					t.Errorf("AccessSecretVersion() called with name %q, want %q", got, want)
				}
				return test.resp, test.respErr
			}

			s, err := newSecretManagerCosigner(t.Context(), access, test.secretName)
			if gotErr := err != nil; gotErr != test.wantErr {
				t.Fatalf("newSecretManagerCosigner() error = %v, wantErr %t", err, test.wantErr)
			}
			if test.wantErr {
				return
			}
			if got, want := s.Name(), v.Name(); got != want {
				t.Errorf("Name() = %q, want %q", got, want)
			}
			if got, want := s.KeyHash(), v.KeyHash(); got != want {
				t.Errorf("KeyHash() = %x, want %x", got, want)
			}
		})
	}
}
