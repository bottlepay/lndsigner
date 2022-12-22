package vault

import (
	"errors"
)

var (
	ErrSeedPhraseWrongLength     = errors.New("seed phrase must be 24 words")
	ErrNodeAlreadyExists         = errors.New("node already exists")
	ErrInvalidPassphrase         = errors.New("invalid passphrase")
	ErrNodePubkeyMismatch        = errors.New("node pubkey mismatch")
	ErrInvalidNetwork            = errors.New("invalid network")
	ErrSeedPhraseNotBIP39        = errors.New("seed phrase must use BIP39 word list")
	ErrBadCipherSeedVer          = errors.New("cipher seed version not recognized")
	ErrWrongLengthChecksum       = errors.New("wrong length checksum")
	ErrChecksumMismatch          = errors.New("checksum mismatch")
	ErrWrongInternalVersion      = errors.New("wrong internal version")
	ErrInvalidPeerPubkey         = errors.New("invalid peer pubkey")
	ErrInvalidNodeID             = errors.New("invalid node id")
	ErrNodeNotFound              = errors.New("node not found")
	ErrInvalidSeedFromStorage    = errors.New("invalid seed from storage")
	ErrElementNotHardened        = errors.New("derivation path element not hardened")
	ErrNegativeElement           = errors.New("negative derivation path element")
	ErrWrongLengthDerivationPath = errors.New("derivation path not 5 elements")
	ErrElementOverflow           = errors.New("derivation path element > MaxUint32")
	ErrPubkeyMismatch            = errors.New("pubkey mismatch")
	ErrTooManyTweaks             = errors.New("both single and double tweak specified")
)
