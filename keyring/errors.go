// Copyright (C) 2013-2017 The btcsuite developers
// Copyright (C) 2015-2016 The Decred developers
// Copyright (C) 2015-2022 Lightning Labs and The Lightning Network Developers
// Copyright (C) 2022 Bottlepay and The Lightning Network Developers

package keyring

import "errors"

var (
	ErrNoSharedKeyReturned = errors.New("vault returned no shared key")
	ErrBadSharedKey        = errors.New("vault returned bad shared key")
	ErrNoSignatureReturned = errors.New("vault returned no signature")
	ErrNoPubkeyReturned    = errors.New("vault returned no pubkey")
)
