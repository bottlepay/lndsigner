package vault

import (
	"errors"
)

var (
	ErrSeedPhraseWrongLength = errors.New("seed phrase must be 24 words")
	ErrNodeAlreadyExists     = errors.New("node already exists")
	ErrInvalidPassphrase     = errors.New("invalid passphrase")
	ErrNodePubkeyMismatch    = errors.New("node pubkey mismatch")
	ErrInvalidNetwork        = errors.New("invalid network")
	ErrSeedPhraseNotBIP39    = errors.New("seed phrase must use BIP39 word list")
	ErrBadCipherSeedVer      = errors.New("cipher seed version not recognized")
	ErrWrongLengthChecksum   = errors.New("wrong length checksum")
	ErrChecksumMismatch      = errors.New("checksum mismatch")
	ErrWrongInternalVersion  = errors.New("wrong internal version")
)
