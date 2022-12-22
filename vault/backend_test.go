package vault

import (
	"context"
	"os"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	filestore "github.com/hashicorp/vault/sdk/physical/file"
	"github.com/stretchr/testify/require"
)

func TestBackend(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "vault-plugin-lndsigner")
	require.NoError(t, err)

	defer os.RemoveAll(tmpDir)

	logger := hclog.Default()

	pStorage, err := filestore.NewFileBackend(
		map[string]string{"path": tmpDir},
		logger,
	)

	storage := logical.NewLogicalStorage(pStorage)

	ctx := context.Background()

	b, err := Factory(ctx, &logical.BackendConfig{
		StorageView: storage,
		Logger:      logger,
	})
	require.NoError(t, err)

	backEnd := b.(*backend)

	testCases := []struct {
		name string
		path *framework.Path
		op   logical.Operation
		data *framework.FieldData
		resp *logical.Response
		err  error
	}{
		{
			name: ErrSeedPhraseWrongLength.Error(),
			path: backEnd.importPath(),
			op:   logical.CreateOperation,
			data: &framework.FieldData{},
			resp: nil,
			err:  ErrSeedPhraseWrongLength,
		},
		{
			name: ErrSeedPhraseNotBIP39.Error(),
			path: backEnd.importPath(),
			op:   logical.CreateOperation,
			data: &framework.FieldData{
				Raw: map[string]interface{}{
					"seedphrase": "absent weks slam olive squeeze cluster blame express asthma gym force warfare physical stuff unusual tiny endless patient again sound deny identify fall guard",
				},
			},
			resp: nil,
			err:  ErrSeedPhraseNotBIP39,
		},
		{
			name: ErrBadCipherSeedVer.Error(),
			path: backEnd.importPath(),
			op:   logical.CreateOperation,
			data: &framework.FieldData{
				Raw: map[string]interface{}{
					"seedphrase": "walnut absent slam olive squeeze cluster blame express asthma gym force warfare physical stuff unusual tiny endless patient again sound deny identify fall guard",
				},
			},
			resp: nil,
			err:  ErrBadCipherSeedVer,
		},
		{
			name: ErrChecksumMismatch.Error(),
			path: backEnd.importPath(),
			op:   logical.CreateOperation,
			data: &framework.FieldData{
				Raw: map[string]interface{}{
					"seedphrase": "absent walnut slam olive squeeze cluster blame express asthma gym force warfare physical stuff unusual tiny endless patient again sound deny identify fall fall",
				},
			},
			resp: nil,
			err:  ErrChecksumMismatch,
		},
		{
			name: "import without passphrase",
			path: backEnd.importPath(),
			op:   logical.CreateOperation,
			data: &framework.FieldData{
				Raw: map[string]interface{}{
					"network":    "regtest",
					"seedphrase": "absent walnut slam olive squeeze cluster blame express asthma gym force warfare physical stuff unusual tiny endless patient again sound deny identify fall guard",
					"passphrase": "",
					"node":       "023cf344b017a3c91bdb2c9c076da267555f0c0748099418ea1f558a624ced1ac6",
				},
			},
			resp: &logical.Response{
				Data: map[string]interface{}{
					"node": "023cf344b017a3c91bdb2c9c076da267555f0c0748099418ea1f558a624ced1ac6",
				},
			},
			err: nil,
		},
		{
			name: "import with passphrase",
			path: backEnd.importPath(),
			op:   logical.CreateOperation,
			data: &framework.FieldData{
				Raw: map[string]interface{}{
					"network":    "testnet",
					"seedphrase": "abstract inch live custom just tray hockey enroll upon friend mass author filter desert parrot network finger uniform alley artefact path palace chicken diet",
					"passphrase": "weks1234",
					"node":       "03c7926302ac72f51ef009dc169561734414b3c6bfd9fb0dc42cac93101c3c25bf",
				},
			},
			resp: &logical.Response{
				Data: map[string]interface{}{
					"node": "03c7926302ac72f51ef009dc169561734414b3c6bfd9fb0dc42cac93101c3c25bf",
				},
			},
			err: nil,
		},
		{
			name: ErrNodeAlreadyExists.Error(),
			path: backEnd.importPath(),
			op:   logical.CreateOperation,
			data: &framework.FieldData{
				Raw: map[string]interface{}{
					"network":    "regtest",
					"seedphrase": "abstract inch live custom just tray hockey enroll upon friend mass author filter desert parrot network finger uniform alley artefact path palace chicken diet",
					"passphrase": "weks1234",
					"node":       "03c7926302ac72f51ef009dc169561734414b3c6bfd9fb0dc42cac93101c3c25bf",
				},
			},
			resp: nil,
			err:  ErrNodeAlreadyExists,
		},
		{
			name: ErrInvalidPassphrase.Error(),
			path: backEnd.importPath(),
			op:   logical.CreateOperation,
			data: &framework.FieldData{
				Raw: map[string]interface{}{
					"network":    "regtest",
					"seedphrase": "abstract inch live custom just tray hockey enroll upon friend mass author filter desert parrot network finger uniform alley artefact path palace chicken diet",
					"node":       "03c7926302ac72f51ef009dc169561734414b3c6bfd9fb0dc42cac93101c3c25bf",
				},
			},
			resp: nil,
			err:  ErrInvalidPassphrase,
		},
		{
			name: ErrNodePubkeyMismatch.Error(),
			path: backEnd.importPath(),
			op:   logical.CreateOperation,
			data: &framework.FieldData{
				Raw: map[string]interface{}{
					"network":    "regtest",
					"seedphrase": "abstract inch live custom just tray hockey enroll upon friend mass author filter desert parrot network finger uniform alley artefact path palace chicken diet",
					"passphrase": "weks1234",
					"node":       "03c7926302ac72f51ef009dc169561734414b3c6bfd9fb0dc42cac93101c3c25ab",
				},
			},
			resp: nil,
			err:  ErrNodePubkeyMismatch,
		},
		{
			name: ErrInvalidNetwork.Error(),
			path: backEnd.importPath(),
			op:   logical.CreateOperation,
			data: &framework.FieldData{
				Raw: map[string]interface{}{
					"network":    "mainnet", // TODO(aakselrod): change this before going live on mainnet
					"seedphrase": "abstract inch live custom just tray hockey enroll upon friend mass author filter desert parrot network finger uniform alley artefact path palace chicken diet",
					"passphrase": "weks1234",
					"node":       "03c7926302ac72f51ef009dc169561734414b3c6bfd9fb0dc42cac93101c3c25ab",
				},
			},
			resp: nil,
			err:  ErrInvalidNetwork,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			testCase.data.Schema = testCase.path.Fields

			resp, err := testCase.path.Callbacks[testCase.op](
				ctx, &logical.Request{Storage: storage}, testCase.data,
			)
			require.Equal(t, testCase.err, err)

			if err != nil {
				return
			}

			require.Equal(t, testCase.resp, resp)

			return
		})
	}
}
