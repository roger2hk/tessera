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
	"errors"
	"fmt"
	"hash/crc32"
	"log/slog"
	"strings"

	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	fnote "github.com/transparency-dev/formats/note"
)

// accessSecretVersionFunc fetches a secret version from Google Cloud Secret Manager.
//
// In production this wraps secretmanager.Client.AccessSecretVersion; it exists to allow tests to provide a fake.
type accessSecretVersionFunc func(context.Context, *secretmanagerpb.AccessSecretVersionRequest) (*secretmanagerpb.AccessSecretVersionResponse, error)

// newSecretManagerCosigner creates a new cosigner which uses a note-formatted MLDSA secret key stored in
// Google Cloud Secret Manager.
func newSecretManagerCosigner(ctx context.Context, access accessSecretVersionFunc, privateKeySecretName string) (fnote.SubtreeSigner, error) {
	if strings.HasSuffix(privateKeySecretName, "/latest") {
		slog.WarnContext(ctx, "Secret version configured to use 'latest' alias; cosigner key will change if a newer version is created", slog.String("secret_name", privateKeySecretName))
	}

	secK, err := secret(ctx, access, privateKeySecretName)
	if err != nil {
		return nil, fmt.Errorf("failed to access %q: %v", privateKeySecretName, err)
	}
	// Note that NewMLDSASigner only returns sentinel errors, so the key material is never included in the error.
	s, err := fnote.NewMLDSASigner(string(secK))
	if err != nil {
		return nil, fmt.Errorf("failed to create MLDSA cosigner from %q: %v", privateKeySecretName, err)
	}
	return s, nil
}

// secret returns the payload of the named Secret Manager secret version, after verifying its integrity.
func secret(ctx context.Context, access accessSecretVersionFunc, secretName string) ([]byte, error) {
	resp, err := access(ctx, &secretmanagerpb.AccessSecretVersionRequest{
		Name: secretName,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to access secret version: %w", err)
	}
	payload := resp.GetPayload()
	if payload == nil {
		return nil, errors.New("secret version has no payload")
	}
	// Verify the data checksum.
	if payload.DataCrc32C == nil {
		return nil, errors.New("secret payload has no checksum")
	}
	crc32c := crc32.MakeTable(crc32.Castagnoli)
	checksum := int64(crc32.Checksum(payload.Data, crc32c))
	if checksum != *payload.DataCrc32C {
		return nil, errors.New("data corruption detected")
	}

	return payload.Data, nil
}
