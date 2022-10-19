// Copyright (C) 2013-2017 The btcsuite developers
// Copyright (C) 2015-2016 The Decred developers
// Copyright (C) 2015-2022 Lightning Labs and The Lightning Network Developers
// Copyright (C) 2022 Bottlepay and The Lightning Network Developers

package lndsigner

import (
	"context"
	"sync"
	"time"

	"github.com/bottlepay/lndsigner/proto"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/wire"
	"google.golang.org/grpc"
)

var (
	// TODO(aakselrod): fix this and make it configurable before merging
	// this code, but this is good for a demo. We set it to 500 to make it
	// easy to use.
	//
	// MaxSpendRate is the sats per second rate allowed by the signer.
	MaxSpendRate = int64(500)
)

type policyEngine struct {
	sync.RWMutex

	r *rpcServer

	// TODO(aakselrod): populate initial node (wallet and channel) state
	// from watch-only lnd instance or own state storage.
	//
	// accounts is a mapping by derivation of the node's account extended
	// public keys. The path elements are all hardened.
	accounts map[[3]uint32]*hdkeychain.ExtendedKey

	// channels is a mapping by channel point of channel info structs.
	channels map[wire.OutPoint]*chanInfo

	// TODO(aakselrod): use a better means of calculating spend rate.
	channelBalance uint64
	lastSpend      time.Time
}

func (p *policyEngine) enforcePolicy(ctx context.Context, req interface{},
	handler grpc.UnaryHandler) (interface{}, error) {

	switch request := req.(type) {
	case *proto.SignPsbtRequest:
		return p.enforcePsbt(ctx, request, handler)
	}

	// Default allow.
	// TODO(aakselrod): change to default deny once all cases handled.
	return handler(ctx, req)
}
