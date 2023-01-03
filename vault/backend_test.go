package vault

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
		{
			name: ErrInvalidPeerPubkey.Error(),
			path: backEnd.ecdhPath(),
			op:   logical.CreateOperation,
			data: &framework.FieldData{
				Raw: map[string]interface{}{
					"peer": "abcdef",
				},
			},
			resp: nil,
			err:  ErrInvalidPeerPubkey,
		},
		{
			name: ErrInvalidNodeID.Error(),
			path: backEnd.ecdhPath(),
			op:   logical.CreateOperation,
			data: &framework.FieldData{
				Raw: map[string]interface{}{
					"peer": "03c7926302ac72f51ef009dc169561734414b3c6bfd9fb0dc42cac93101c3c25bf",
					"node": "abcdef",
				},
			},
			resp: nil,
			err:  ErrInvalidNodeID,
		},
		{
			name: ErrNodeNotFound.Error(),
			path: backEnd.ecdhPath(),
			op:   logical.CreateOperation,
			data: &framework.FieldData{
				Raw: map[string]interface{}{
					"peer": "03c7926302ac72f51ef009dc169561734414b3c6bfd9fb0dc42cac93101c3c25bf",
					"node": "02252bb0fdf7f6e7c055c5419c6fa1c9799cf348b480603b9c0af61dbdea29149e",
				},
			},
			resp: nil,
			err:  ErrNodeNotFound,
		},
		{
			name: "ecdh",
			path: backEnd.ecdhPath(),
			op:   logical.CreateOperation,
			data: &framework.FieldData{
				Raw: map[string]interface{}{
					"node":   "03c7926302ac72f51ef009dc169561734414b3c6bfd9fb0dc42cac93101c3c25bf",
					"pubkey": "03c7926302ac72f51ef009dc169561734414b3c6bfd9fb0dc42cac93101c3c25bf",
					"peer":   "02252bb0fdf7f6e7c055c5419c6fa1c9799cf348b480603b9c0af61dbdea29149e",
					"path":   []int{2147484665, 2147483649, 2147483654, 0, 0},
				},
			},
			resp: &logical.Response{
				Data: map[string]interface{}{
					"sharedkey": "7895c217d4f1a33265c0122ce66dd16bcd0b86976198f1128e6dbaef86a2f327",
				},
			},
			err: nil,
		},
		{
			name: ErrPubkeyMismatch.Error(),
			path: backEnd.ecdhPath(),
			op:   logical.CreateOperation,
			data: &framework.FieldData{
				Raw: map[string]interface{}{
					"node":   "03c7926302ac72f51ef009dc169561734414b3c6bfd9fb0dc42cac93101c3c25bf",
					"pubkey": "03c7926302ac72f51ef009dc169561734414b3c6bfd9fb0dc42cac93101c3c25ef",
					"peer":   "02252bb0fdf7f6e7c055c5419c6fa1c9799cf348b480603b9c0af61dbdea29149e",
					"path":   []int{2147484665, 2147483649, 2147483654, 0, 0},
				},
			},
			resp: nil,
			err:  ErrPubkeyMismatch,
		},
		{
			name: ErrWrongLengthDerivationPath.Error(),
			path: backEnd.ecdhPath(),
			op:   logical.CreateOperation,
			data: &framework.FieldData{
				Raw: map[string]interface{}{
					"node": "03c7926302ac72f51ef009dc169561734414b3c6bfd9fb0dc42cac93101c3c25bf",
					"peer": "02252bb0fdf7f6e7c055c5419c6fa1c9799cf348b480603b9c0af61dbdea29149e",
					"path": []int{2147484665, 2147483649, 2147483654, 0, 0, 0},
				},
			},
			resp: nil,
			err:  ErrWrongLengthDerivationPath,
		},
		{
			name: ErrNegativeElement.Error(),
			path: backEnd.ecdhPath(),
			op:   logical.CreateOperation,
			data: &framework.FieldData{
				Raw: map[string]interface{}{
					"node": "03c7926302ac72f51ef009dc169561734414b3c6bfd9fb0dc42cac93101c3c25bf",
					"peer": "02252bb0fdf7f6e7c055c5419c6fa1c9799cf348b480603b9c0af61dbdea29149e",
					"path": []int{-1, 2147483649, 2147483654, 0, 0},
				},
			},
			resp: nil,
			err:  ErrNegativeElement,
		},
		{
			name: ErrElementOverflow.Error(),
			path: backEnd.ecdhPath(),
			op:   logical.CreateOperation,
			data: &framework.FieldData{
				Raw: map[string]interface{}{
					"node": "03c7926302ac72f51ef009dc169561734414b3c6bfd9fb0dc42cac93101c3c25bf",
					"peer": "02252bb0fdf7f6e7c055c5419c6fa1c9799cf348b480603b9c0af61dbdea29149e",
					"path": []int{22147484665, 2147483649, 2147483654, 0, 0},
				},
			},
			resp: nil,
			err:  ErrElementOverflow,
		},
		{
			name: ErrElementNotHardened.Error(),
			path: backEnd.ecdhPath(),
			op:   logical.CreateOperation,
			data: &framework.FieldData{
				Raw: map[string]interface{}{
					"node": "03c7926302ac72f51ef009dc169561734414b3c6bfd9fb0dc42cac93101c3c25bf",
					"peer": "02252bb0fdf7f6e7c055c5419c6fa1c9799cf348b480603b9c0af61dbdea29149e",
					"path": []int{1017, 2147483649, 2147483654, 0, 0},
				},
			},
			resp: nil,
			err:  ErrElementNotHardened,
		},
		{
			name: "list nodes",
			path: backEnd.basePath(),
			op:   logical.ReadOperation,
			data: &framework.FieldData{},
			resp: &logical.Response{
				Data: map[string]interface{}{
					"03c7926302ac72f51ef009dc169561734414b3c6bfd9fb0dc42cac93101c3c25bf": "testnet",
					"023cf344b017a3c91bdb2c9c076da267555f0c0748099418ea1f558a624ced1ac6": "regtest",
				},
			},
			err: nil,
		},
		{
			name: "sign ecdsa",
			path: backEnd.signPath(),
			op:   logical.CreateOperation,
			data: &framework.FieldData{
				Raw: map[string]interface{}{
					"node":   "023cf344b017a3c91bdb2c9c076da267555f0c0748099418ea1f558a624ced1ac6",
					"pubkey": "023cf344b017a3c91bdb2c9c076da267555f0c0748099418ea1f558a624ced1ac6",
					"digest": "9d3d4b1c81f2554200ccc05635f01c008f1be1fe7164bf39c1dd83a6a1eec7df",
					"method": "ecdsa",
					"path":   []int{2147484665, 2147483649, 2147483654, 0, 0},
				},
			},
			resp: &logical.Response{
				Data: map[string]interface{}{
					"pubkey":    "023cf344b017a3c91bdb2c9c076da267555f0c0748099418ea1f558a624ced1ac6",
					"signature": "3045022100d5e9e57012d5bcce055e17a1b467a7b00c9c29e33bcca2aaa23a991452f3d10b0220219595c988f0e3c3acccb4ccdd856c662a9f462ae02d82243306fb0f316ea872",
				},
			},
			err: nil,
		},
		{
			name: "sign ecdsa ignoring taptweak",
			path: backEnd.signPath(),
			op:   logical.CreateOperation,
			data: &framework.FieldData{
				Raw: map[string]interface{}{
					"node":     "023cf344b017a3c91bdb2c9c076da267555f0c0748099418ea1f558a624ced1ac6",
					"pubkey":   "023cf344b017a3c91bdb2c9c076da267555f0c0748099418ea1f558a624ced1ac6",
					"digest":   "9d3d4b1c81f2554200ccc05635f01c008f1be1fe7164bf39c1dd83a6a1eec7df",
					"taptweak": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
					"method":   "ecdsa",
					"path":     []int{2147484665, 2147483649, 2147483654, 0, 0},
				},
			},
			resp: &logical.Response{
				Data: map[string]interface{}{
					"pubkey":    "023cf344b017a3c91bdb2c9c076da267555f0c0748099418ea1f558a624ced1ac6",
					"signature": "3045022100d5e9e57012d5bcce055e17a1b467a7b00c9c29e33bcca2aaa23a991452f3d10b0220219595c988f0e3c3acccb4ccdd856c662a9f462ae02d82243306fb0f316ea872",
				},
			},
			err: nil,
		},
		{
			name: "sign ecdsa with single tweak",
			path: backEnd.signPath(),
			op:   logical.CreateOperation,
			data: &framework.FieldData{
				Raw: map[string]interface{}{
					"node":     "023cf344b017a3c91bdb2c9c076da267555f0c0748099418ea1f558a624ced1ac6",
					"pubkey":   "023cf344b017a3c91bdb2c9c076da267555f0c0748099418ea1f558a624ced1ac6",
					"digest":   "9d3d4b1c81f2554200ccc05635f01c008f1be1fe7164bf39c1dd83a6a1eec7df",
					"ln1tweak": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
					"method":   "ecdsa",
					"path":     []int{2147484665, 2147483649, 2147483654, 0, 0},
				},
			},
			resp: &logical.Response{
				Data: map[string]interface{}{
					"pubkey":    "023cf344b017a3c91bdb2c9c076da267555f0c0748099418ea1f558a624ced1ac6",
					"signature": "3045022100ac182be53be9ce5a94565bf21fffd640e56dc10631fbe6f7d75e1ef03f7e23ff022010f917056b002695f33281c6f569de0e2934be966f7d9c36669d93a56530ca9b",
				},
			},
			err: nil,
		},
		{
			name: "sign ecdsa with double tweak",
			path: backEnd.signPath(),
			op:   logical.CreateOperation,
			data: &framework.FieldData{
				Raw: map[string]interface{}{
					"node":     "023cf344b017a3c91bdb2c9c076da267555f0c0748099418ea1f558a624ced1ac6",
					"pubkey":   "023cf344b017a3c91bdb2c9c076da267555f0c0748099418ea1f558a624ced1ac6",
					"digest":   "9d3d4b1c81f2554200ccc05635f01c008f1be1fe7164bf39c1dd83a6a1eec7df",
					"ln2tweak": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
					"method":   "ecdsa",
					"path":     []int{2147484665, 2147483649, 2147483654, 0, 0},
				},
			},
			resp: &logical.Response{
				Data: map[string]interface{}{
					"pubkey":    "023cf344b017a3c91bdb2c9c076da267555f0c0748099418ea1f558a624ced1ac6",
					"signature": "3044022067e3a4a3b40592e10dc08e8b585e1b2a00c3f3e906f8d7959642102ebc977d4302202527213f7f795e2d45849c8a147cf39ed8f6246141c6f092f51b0bde53eb3d49",
				},
			},
			err: nil,
		},
		{
			name: ErrTooManyTweaks.Error(),
			path: backEnd.signPath(),
			op:   logical.CreateOperation,
			data: &framework.FieldData{
				Raw: map[string]interface{}{
					"node":     "023cf344b017a3c91bdb2c9c076da267555f0c0748099418ea1f558a624ced1ac6",
					"pubkey":   "023cf344b017a3c91bdb2c9c076da267555f0c0748099418ea1f558a624ced1ac6",
					"digest":   "9d3d4b1c81f2554200ccc05635f01c008f1be1fe7164bf39c1dd83a6a1eec7df",
					"ln1tweak": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
					"ln2tweak": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
					"method":   "ecdsa",
					"path":     []int{2147484665, 2147483649, 2147483654, 0, 0},
				},
			},
			resp: nil,
			err:  ErrTooManyTweaks,
		},
		{
			name: "single tweak bad hex",
			path: backEnd.signPath(),
			op:   logical.CreateOperation,
			data: &framework.FieldData{
				Raw: map[string]interface{}{
					"node":     "023cf344b017a3c91bdb2c9c076da267555f0c0748099418ea1f558a624ced1ac6",
					"pubkey":   "023cf344b017a3c91bdb2c9c076da267555f0c0748099418ea1f558a624ced1ac6",
					"digest":   "9d3d4b1c81f2554200ccc05635f01c008f1be1fe7164bf39c1dd83a6a1eec7df",
					"ln1tweak": "g123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
					"method":   "ecdsa",
					"path":     []int{2147484665, 2147483649, 2147483654, 0, 0},
				},
			},
			resp: nil,
			err:  hex.InvalidByteError(0x67),
		},
		{
			name: "double tweak bad hex",
			path: backEnd.signPath(),
			op:   logical.CreateOperation,
			data: &framework.FieldData{
				Raw: map[string]interface{}{
					"node":     "023cf344b017a3c91bdb2c9c076da267555f0c0748099418ea1f558a624ced1ac6",
					"pubkey":   "023cf344b017a3c91bdb2c9c076da267555f0c0748099418ea1f558a624ced1ac6",
					"digest":   "9d3d4b1c81f2554200ccc05635f01c008f1be1fe7164bf39c1dd83a6a1eec7df",
					"ln2tweak": "g123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
					"method":   "ecdsa",
					"path":     []int{2147484665, 2147483649, 2147483654, 0, 0},
				},
			},
			resp: nil,
			err:  hex.InvalidByteError(0x67),
		},
		{
			name: "sign ecdsa-compact",
			path: backEnd.signPath(),
			op:   logical.CreateOperation,
			data: &framework.FieldData{
				Raw: map[string]interface{}{
					"node":   "023cf344b017a3c91bdb2c9c076da267555f0c0748099418ea1f558a624ced1ac6",
					"pubkey": "023cf344b017a3c91bdb2c9c076da267555f0c0748099418ea1f558a624ced1ac6",
					"digest": "9d3d4b1c81f2554200ccc05635f01c008f1be1fe7164bf39c1dd83a6a1eec7df",
					"method": "ecdsa-compact",
					"path":   []int{2147484665, 2147483649, 2147483654, 0, 0},
				},
			},
			resp: &logical.Response{
				Data: map[string]interface{}{
					"pubkey":    "023cf344b017a3c91bdb2c9c076da267555f0c0748099418ea1f558a624ced1ac6",
					"signature": "20d5e9e57012d5bcce055e17a1b467a7b00c9c29e33bcca2aaa23a991452f3d10b219595c988f0e3c3acccb4ccdd856c662a9f462ae02d82243306fb0f316ea872",
				},
			},
			err: nil,
		},
		{
			name: "sign schnorr",
			path: backEnd.signPath(),
			op:   logical.CreateOperation,
			data: &framework.FieldData{
				Raw: map[string]interface{}{
					"node":   "023cf344b017a3c91bdb2c9c076da267555f0c0748099418ea1f558a624ced1ac6",
					"pubkey": "023cf344b017a3c91bdb2c9c076da267555f0c0748099418ea1f558a624ced1ac6",
					"digest": "9d3d4b1c81f2554200ccc05635f01c008f1be1fe7164bf39c1dd83a6a1eec7df",
					"method": "schnorr",
					"path":   []int{2147484665, 2147483649, 2147483654, 0, 0},
				},
			},
			resp: &logical.Response{
				Data: map[string]interface{}{
					"pubkey":    "023cf344b017a3c91bdb2c9c076da267555f0c0748099418ea1f558a624ced1ac6",
					"signature": "71b77d9c8a0badfa7c4eca3fbef5da2a552bf032f56b85fbc5c2f3500498fc20d5ab8505ae9733b1b756da7a5dba41dbe069dd0d86793618829c3077df0cd759",
				},
			},
			err: nil,
		},
		{
			name: "sign schnorr with taptweak",
			path: backEnd.signPath(),
			op:   logical.CreateOperation,
			data: &framework.FieldData{
				Raw: map[string]interface{}{
					"node":     "023cf344b017a3c91bdb2c9c076da267555f0c0748099418ea1f558a624ced1ac6",
					"pubkey":   "023cf344b017a3c91bdb2c9c076da267555f0c0748099418ea1f558a624ced1ac6",
					"digest":   "9d3d4b1c81f2554200ccc05635f01c008f1be1fe7164bf39c1dd83a6a1eec7df",
					"taptweak": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
					"method":   "schnorr",
					"path":     []int{2147484665, 2147483649, 2147483654, 0, 0},
				},
			},
			resp: &logical.Response{
				Data: map[string]interface{}{
					"pubkey":    "023cf344b017a3c91bdb2c9c076da267555f0c0748099418ea1f558a624ced1ac6",
					"signature": "e4112ae8f73f1d13a6128ddbde38f8bae00fbe9d6e1c3c330b5856e1587c593d9ed050c5f502ea80ab5bcc1a4ebcd4b3e0bfbbb5312591427d582613982c42a5",
				},
			},
			err: nil,
		},
		{
			name: "derive pubkey",
			path: backEnd.signPath(),
			op:   logical.ReadOperation,
			data: &framework.FieldData{
				Raw: map[string]interface{}{
					"node": "023cf344b017a3c91bdb2c9c076da267555f0c0748099418ea1f558a624ced1ac6",
					"path": []int{2147484665, 2147483649, 2147483654, 0, 0},
				},
			},
			resp: &logical.Response{
				Data: map[string]interface{}{
					"pubkey": "023cf344b017a3c91bdb2c9c076da267555f0c0748099418ea1f558a624ced1ac6",
				},
			},
			err: nil,
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

	state := struct {
		createdNode string
	}{}

	statefulTestCases := []struct {
		name  string
		path  *framework.Path
		op    logical.Operation
		data  *framework.FieldData
		check func(*testing.T, *logical.Response)
		err   error
	}{
		{
			name: "create node",
			path: backEnd.basePath(),
			op:   logical.CreateOperation,
			data: &framework.FieldData{
				Raw: map[string]interface{}{
					"network": "regtest",
				},
			},
			check: func(t *testing.T, resp *logical.Response) {
				state.createdNode = resp.Data["node"].(string)
				require.Equal(t, 66, len(state.createdNode))
			},
			err: nil,
		},
		{
			name: "stateful list nodes",
			path: backEnd.basePath(),
			op:   logical.ReadOperation,
			data: &framework.FieldData{},
			check: func(t *testing.T, resp *logical.Response) {
				require.Equal(t, resp, &logical.Response{
					Data: map[string]interface{}{
						state.createdNode: "regtest",
						"03c7926302ac72f51ef009dc169561734414b3c6bfd9fb0dc42cac93101c3c25bf": "testnet",
						"023cf344b017a3c91bdb2c9c076da267555f0c0748099418ea1f558a624ced1ac6": "regtest",
					},
				})
			},
			err: nil,
		},
		{
			name: "list accounts",
			path: backEnd.accountsPath(),
			op:   logical.ReadOperation,
			data: &framework.FieldData{
				Raw: map[string]interface{}{
					"node": "03c7926302ac72f51ef009dc169561734414b3c6bfd9fb0dc42cac93101c3c25bf",
				},
			},
			check: func(t *testing.T, resp *logical.Response) {
				acctList, ok := resp.Data["acctList"].(string)
				require.True(t, ok)
				digest := sha256.Sum256([]byte(acctList))
				digestHex := hex.EncodeToString(digest[:])
				require.Equal(t,
					"223b82c397cbccce80c5c5e33c993e332909e093bc5ca3398266f7a5e0f48806",
					digestHex,
				)
			},
			err: nil,
		},
	}

	for _, testCase := range statefulTestCases {
		t.Run(testCase.name, func(t *testing.T) {
			testCase.data.Schema = testCase.path.Fields

			resp, err := testCase.path.Callbacks[testCase.op](
				ctx, &logical.Request{Storage: storage}, testCase.data,
			)
			require.Equal(t, testCase.err, err)

			if err != nil {
				return
			}

			testCase.check(t, resp)

			return
		})
	}
}
