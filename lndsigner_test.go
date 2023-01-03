//go:build itest
// +build itest

package lndsigner_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path"
	"testing"
	"time"

	"github.com/bottlepay/lndsigner"
	"github.com/bottlepay/lndsigner/itest"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var (
	lastPort = 20000 // Go past default ports for bitcoind, vault, and lnd
)

func newPort() *net.TCPAddr {
	lis, err := net.Listen("tcp", "127.0.0.1:")
	if err != nil {
		panic(err)
	}
	defer lis.Close()
	return lis.Addr().(*net.TCPAddr)
}

func newPortString() string {
	return fmt.Sprintf("%d", newPort().Port)
}

func killProc(t *testing.T, cmd *exec.Cmd, errPipe io.ReadCloser) {
	t.Helper()

	_ = cmd.Process.Signal(os.Interrupt)

	stderr, err := io.ReadAll(errPipe)
	require.NoError(t, err)

	err = cmd.Wait()
	require.NoError(t, err, string(stderr))
}

// This assumes we've got `lnd`, `lncli`, `vault`, `bitcoind`, `bitcoin-cli`,
// and the binaries produced by this package installed and available in the
// executable path.
//
// This function runs end-to-end tests but runs the lndsignerd component inside
// the tests themselves to get code coverage statistics for the top package.
func TestIntegration(t *testing.T) {
	vaultPath, err := exec.LookPath("vault")
	require.NoError(t, err)

	bitcoindPath, err := exec.LookPath("bitcoind")
	require.NoError(t, err)

	bitcoincliPath, err := exec.LookPath("bitcoin-cli")
	require.NoError(t, err)

	lndPath, err := exec.LookPath("lnd")
	require.NoError(t, err)

	lncliPath, err := exec.LookPath("lncli")
	require.NoError(t, err)

	pluginPath, err := exec.LookPath("vault-plugin-lndsigner")
	require.NoError(t, err)

	tmpRoot, err := os.MkdirTemp("", "lndsigner-itest")
	require.NoError(t, err)
	defer os.RemoveAll(tmpRoot)

	pluginDir := path.Join(tmpRoot, "vault_plugins")
	err = os.Mkdir(pluginDir, fs.ModeDir|0700)
	require.NoError(t, err)

	pluginBytes, err := os.ReadFile(pluginPath)
	require.NoError(t, err)

	pluginCmd := path.Join(pluginDir, "vault-plugin-lndsigner")
	err = os.WriteFile(pluginCmd, pluginBytes, 0700)
	require.NoError(t, err)

	ctx := context.Background()

	vaultPort := newPortString()
	vaultCmd := exec.CommandContext(ctx, vaultPath, "server", "-dev",
		"-dev-root-token-id=root", "-dev-plugin-dir="+pluginDir,
		"-dev-listen-address=127.0.0.1:"+vaultPort)

	vaultErrPipe, err := vaultCmd.StderrPipe()
	require.NoError(t, err)

	err = vaultCmd.Start()
	require.NoError(t, err)
	defer killProc(t, vaultCmd, vaultErrPipe)

	require.NoError(t, os.Setenv("VAULT_TOKEN", "root"))

	vaultClientConf := api.DefaultConfig()
	vaultClientConf.Address = "http://127.0.0.1:" + vaultPort

	vaultClient, err := api.NewClient(vaultClientConf)
	require.NoError(t, err)

	client := vaultClient.Logical()

	vaultSys := vaultClient.Sys()
	err = vaultSys.Mount("lndsigner", &api.MountInput{
		Type: "vault-plugin-lndsigner",
	})
	require.NoError(t, err)

	// Initial requests to the plugin for creating nodes for testing. We
	// import and also create a random node.
	var lnd1PK string
	lnd2PK := "023cf344b017a3c91bdb2c9c076da267555f0c0748099418ea1f558a624ced1ac6"
	lnd3PK := "03c7926302ac72f51ef009dc169561734414b3c6bfd9fb0dc42cac93101c3c25bf"

	initCases := []struct {
		name    string
		path    string
		reqData map[string]interface{}
		check   func(*testing.T, *api.Secret)
	}{
		{
			name: "create random node lnd1",
			path: "lndsigner/lnd-nodes",
			reqData: map[string]interface{}{
				"network": "regtest",
			},
			check: func(t *testing.T, resp *api.Secret) {
				var ok bool
				lnd1PK, ok = resp.Data["node"].(string)
				require.True(t, ok)
				require.Equal(t, 66, len(lnd1PK))
				t.Logf("Created randomly initialized node %s",
					lnd1PK)
			},
		},
		{
			name: "import node lnd2",
			path: "lndsigner/lnd-nodes/import",
			reqData: map[string]interface{}{
				"network":    "regtest",
				"seedphrase": "absent walnut slam olive squeeze cluster blame express asthma gym force warfare physical stuff unusual tiny endless patient again sound deny identify fall guard",
				"passphrase": "",
				"node":       "023cf344b017a3c91bdb2c9c076da267555f0c0748099418ea1f558a624ced1ac6",
			},
			check: func(t *testing.T, resp *api.Secret) {
				pubKey, ok := resp.Data["node"].(string)
				require.True(t, ok)
				require.Equal(t, lnd2PK, pubKey)
				t.Logf("Imported node %s", pubKey)
			},
		},
		{
			name: "import node lnd3",
			path: "lndsigner/lnd-nodes/import",
			reqData: map[string]interface{}{
				"network":    "testnet",
				"seedphrase": "abstract inch live custom just tray hockey enroll upon friend mass author filter desert parrot network finger uniform alley artefact path palace chicken diet",
				"passphrase": "weks1234",
				"node":       "03c7926302ac72f51ef009dc169561734414b3c6bfd9fb0dc42cac93101c3c25bf",
			},
			check: func(t *testing.T, resp *api.Secret) {
				pubKey, ok := resp.Data["node"].(string)
				require.True(t, ok)
				require.Equal(t, lnd3PK, pubKey)
				t.Logf("Imported node %s", pubKey)
			},
		},
	}

	for _, testCase := range initCases {
		t.Run(testCase.name, func(t *testing.T) {
			resp, err := client.Write(testCase.path,
				testCase.reqData)
			require.NoError(t, err)

			testCase.check(t, resp)
		})
	}

	err = os.Setenv("VAULT_TOKEN", "root")
	require.NoError(t, err)

	err = os.Setenv("VAULT_ADDR", "http://127.0.0.1:"+vaultPort)
	require.NoError(t, err)

	// Start bitcoind
	bitcoinDir := path.Join(tmpRoot, "bitcoin")
	err = os.Mkdir(bitcoinDir, fs.ModeDir|0700)
	require.NoError(t, err)

	bitcoinRPC := newPortString()
	bitcoinZB := newPort()
	bitcoinZT := newPort()

	bitcoindCmd := exec.CommandContext(ctx, bitcoindPath, "-server=1",
		"-datadir="+bitcoinDir, "-listen=0", "-txindex=1",
		"-regtest=1", "-rpcuser=user", "-rpcpassword=password",
		"-rpcport="+bitcoinRPC,
		"-zmqpubrawblock=tcp://"+bitcoinZB.String(),
		"-zmqpubrawtx=tcp://"+bitcoinZT.String())

	bitcoindErrPipe, err := bitcoindCmd.StderrPipe()
	require.NoError(t, err)

	err = bitcoindCmd.Start()
	require.NoError(t, err)
	defer killProc(t, bitcoindCmd, bitcoindErrPipe)

	// TODO(aakselrod): eliminate this
	time.Sleep(3 * time.Second)

	bitcoinCli := func(args ...string) {
		bitcoinCliCmd := exec.CommandContext(ctx, bitcoincliPath,
			append([]string{"-datadir=" + bitcoinDir,
				"-rpcport=" + bitcoinRPC, "-rpcuser=user",
				"-rpcpassword=password", "-rpcwaittimeout=5"},
				args...)...)

		stderrPipe, err := bitcoinCliCmd.StderrPipe()
		require.NoError(t, err)

		err = bitcoinCliCmd.Start()
		require.NoError(t, err)

		stderr, err := io.ReadAll(stderrPipe)
		require.NoError(t, err)

		err = bitcoinCliCmd.Wait()
		require.NoError(t, err, string(stderr))
	}

	bitcoinCli("createwallet", "default")
	bitcoinCli("-generate", "1000")

	// Start lnd
	lnds := []*lndHarness{
		&lndHarness{
			lnddir:    path.Join(tmpRoot, "lnd1"),
			lncliPath: lncliPath,
			vault:     client,
		},
		&lndHarness{
			lnddir:     path.Join(tmpRoot, "lnd2"),
			lncliPath:  lncliPath,
			vault:      client,
			unixSocket: true,
		},
		&lndHarness{
			lnddir:    path.Join(tmpRoot, "lnd3"),
			lncliPath: lncliPath,
			vault:     client,
		},
	}

	lndPubKeys := []string{lnd1PK, lnd2PK, lnd3PK}

	var resp map[string]interface{}
	for i, lnd := range lnds {
		var address string

		lnd.Start(t, ctx, lndPath, bitcoinRPC, bitcoinZB.String(),
			bitcoinZT.String(), lndPubKeys[i])
		defer lnd.Close(t)

		t.Run(lndPubKeys[i]+"/"+"getinfo", func(t *testing.T) {
			resp = lnd.Lncli(t, ctx, "getinfo")
			require.Equal(t, lndPubKeys[i],
				resp["identity_pubkey"].(string))

		})

		t.Run(lndPubKeys[i]+"/"+"p2traddress", func(t *testing.T) {
			resp = lnd.Lncli(t, ctx, "newaddress", "p2tr")
			address = resp["address"].(string)
		})

		bitcoinCli("-named", "sendtoaddress", "address="+address,
			"amount=1", "fee_rate=25")

		time.Sleep(300 * time.Millisecond)
		bitcoinCli("-generate")
		time.Sleep(300 * time.Millisecond)

		t.Run(lndPubKeys[i]+"/"+"p2wkhaddress", func(t *testing.T) {
			resp = lnd.Lncli(t, ctx, "newaddress", "p2wkh")
			address = resp["address"].(string)
		})

		t.Run(lndPubKeys[i]+"/"+"p2trspend", func(t *testing.T) {
			resp = lnd.Lncli(t, ctx, "sendcoins", "--sweepall",
				address)
			require.Equal(t, 64, len(resp["txid"].(string)))
		})

		time.Sleep(300 * time.Millisecond)
		bitcoinCli("-generate")
		time.Sleep(300 * time.Millisecond)

		t.Run(lndPubKeys[i]+"/"+"np2wkhaddress", func(t *testing.T) {
			resp = lnd.Lncli(t, ctx, "newaddress", "np2wkh")
			address = resp["address"].(string)
		})

		t.Run(lndPubKeys[i]+"/"+"p2wkhspend", func(t *testing.T) {
			resp = lnd.Lncli(t, ctx, "sendcoins", "--sweepall",
				address)
			require.Equal(t, 64, len(resp["txid"].(string)))
		})

		time.Sleep(300 * time.Millisecond)
		bitcoinCli("-generate")
		time.Sleep(300 * time.Millisecond)

		t.Run(lndPubKeys[i]+"/"+"np2wkhspend", func(t *testing.T) {
			resp = lnd.Lncli(t, ctx, "sendcoins", "--sweepall",
				address)
			require.Equal(t, 64, len(resp["txid"].(string)))
		})

		time.Sleep(300 * time.Millisecond)
		bitcoinCli("-generate")
		time.Sleep(300 * time.Millisecond)
	}

	t.Run("connect lnd1 to lnd2", func(t *testing.T) {
		_ = lnds[0].Lncli(t, ctx, "connect",
			lnd2PK+"@127.0.0.1:"+lnds[1].p2p)
	})

	t.Run("connect lnd2 to lnd3", func(t *testing.T) {
		_ = lnds[1].Lncli(t, ctx, "connect",
			lnd3PK+"@127.0.0.1:"+lnds[2].p2p)
	})

	t.Run("open channel lnd1 to lnd2", func(t *testing.T) {
		resp = lnds[0].Lncli(t, ctx, "openchannel", lnd2PK, "10000000",
			"5000000")
		require.Equal(t, 64, len(resp["funding_txid"].(string)))
	})

	t.Run("open channel lnd2 to lnd3", func(t *testing.T) {
		resp = lnds[1].Lncli(t, ctx, "openchannel", lnd3PK, "10000000",
			"5000000")
		require.Equal(t, 64, len(resp["funding_txid"].(string)))
	})

	time.Sleep(300 * time.Millisecond)
	bitcoinCli("-generate", "5")
	time.Sleep(300 * time.Millisecond)
	bitcoinCli("-generate")
	time.Sleep(3 * time.Second)

	var invoice string

	t.Run("get invoice from lnd1 for lnd2", func(t *testing.T) {
		resp = lnds[0].Lncli(t, ctx, "addinvoice", "5000")
		invoice = resp["payment_request"].(string)
	})

	t.Run("pay invoice from lnd2 to lnd1", func(t *testing.T) {
		resp = lnds[1].Lncli(t, ctx, "payinvoice", "-f", invoice)
	})

	t.Run("get invoice from lnd2 for lnd1", func(t *testing.T) {
		resp = lnds[1].Lncli(t, ctx, "addinvoice", "5000")
		invoice = resp["payment_request"].(string)
	})

	t.Run("pay invoice from lnd1 to lnd2", func(t *testing.T) {
		resp = lnds[0].Lncli(t, ctx, "payinvoice", "-f", invoice)
	})

	t.Run("get invoice from lnd3 for lnd2", func(t *testing.T) {
		resp = lnds[2].Lncli(t, ctx, "addinvoice", "5000")
		invoice = resp["payment_request"].(string)
	})

	t.Run("pay invoice from lnd2 to lnd3", func(t *testing.T) {
		resp = lnds[1].Lncli(t, ctx, "payinvoice", "-f", invoice)
	})

	t.Run("get invoice from lnd2 for lnd3", func(t *testing.T) {
		resp = lnds[1].Lncli(t, ctx, "addinvoice", "5000")
		invoice = resp["payment_request"].(string)
	})

	t.Run("pay invoice from lnd3 to lnd2", func(t *testing.T) {
		resp = lnds[2].Lncli(t, ctx, "payinvoice", "-f", invoice)
	})

	t.Run("get invoice from lnd3 for lnd1", func(t *testing.T) {
		resp = lnds[2].Lncli(t, ctx, "addinvoice", "5000")
		invoice = resp["payment_request"].(string)
	})

	t.Run("pay invoice from lnd1 to lnd3", func(t *testing.T) {
		resp = lnds[0].Lncli(t, ctx, "payinvoice", "-f", invoice)
	})

	t.Run("get invoice from lnd1 for lnd3", func(t *testing.T) {
		resp = lnds[0].Lncli(t, ctx, "addinvoice", "5000")
		invoice = resp["payment_request"].(string)
	})

	t.Run("pay invoice from lnd3 to lnd1", func(t *testing.T) {
		resp = lnds[2].Lncli(t, ctx, "payinvoice", "-f", invoice)
	})

}

type lndHarness struct {
	lnddir    string
	lncliPath string
	vault     *api.Logical

	unixSocket bool

	rpc     string
	p2p     string
	cmd     *exec.Cmd
	errPipe io.ReadCloser
}

func (l *lndHarness) Start(t *testing.T, ctx context.Context, lndPath,
	bitcoinRPC, zmqPubRawBlock, zmqPubRawTx, idPubKey string) {

	t.Helper()

	var signerAddr net.Addr = newPort()

	if l.unixSocket {
		signerAddr = &net.UnixAddr{
			Name: path.Join(l.lnddir, "signer.socket"),
			Net:  "unix",
		}
	}

	signerConfig := &lndsigner.Config{
		SignerDir:       "./testdata",
		TLSCertPath:     "./testdata/tls.cert",
		TLSKeyPath:      "./testdata/tls.key",
		RPCListeners:    []net.Addr{signerAddr},
		ActiveNetParams: chaincfg.RegressionNetParams,
		NodePubKey:      idPubKey,
	}

	go func() {
		err := lndsigner.Main(signerConfig, lndsigner.ListenerCfg{})
		require.NoError(t, err)
	}()

	err := os.Mkdir(l.lnddir, fs.ModeDir|0700)
	require.NoError(t, err)

	acctsResp, err := l.vault.ReadWithData(
		"lndsigner/lnd-nodes/accounts",
		map[string][]string{
			"node": []string{idPubKey},
		},
	)
	require.NoError(t, err)

	acctList, ok := acctsResp.Data["acctList"].(string)
	require.True(t, ok)

	accounts, err := lndsigner.GetAccounts(acctList)
	require.NoError(t, err)

	grpcAccounts := make([]*itest.WatchOnlyAccount, 0,
		len(accounts))

	for derPath, xPub := range accounts {
		grpcAccounts = append(grpcAccounts,
			&itest.WatchOnlyAccount{
				Purpose:  derPath[0],
				CoinType: derPath[1],
				Account:  derPath[2],
				Xpub:     xPub,
			})
	}

	l.rpc = newPortString()
	l.p2p = newPortString()

	strSignerAddr := signerAddr.String()
	if l.unixSocket {
		strSignerAddr = "unix://" + strSignerAddr
	}

	l.cmd = exec.CommandContext(ctx, lndPath, "--lnddir="+l.lnddir,
		"--norest", "--listen="+l.p2p, "--rpclisten="+l.rpc,
		"--trickledelay=10", "--bitcoin.active", "--bitcoin.regtest",
		"--bitcoin.node=bitcoind", "--bitcoind.rpcuser=user",
		"--bitcoind.rpcpass=password",
		"--bitcoind.rpchost=127.0.0.1:"+bitcoinRPC,
		"--bitcoind.zmqpubrawblock=tcp://"+zmqPubRawBlock,
		"--bitcoind.zmqpubrawtx=tcp://"+zmqPubRawTx,
		"--remotesigner.enable",
		"--remotesigner.rpchost="+strSignerAddr,
		"--remotesigner.tlscertpath=./testdata/tls.cert",
		"--remotesigner.macaroonpath=./testdata/signer.custom.macaroon",
	)

	l.errPipe, err = l.cmd.StderrPipe()
	require.NoError(t, err)

	err = l.cmd.Start()
	require.NoError(t, err)

	t.Logf("Running lnd %s", idPubKey)

	// TODO(aakselrod): eliminate this
	time.Sleep(3 * time.Second)

	// Initialize with the accounts information.
	tlsCreds, err := credentials.NewClientTLSFromFile(
		path.Join(l.lnddir, "tls.cert"), "")
	require.NoError(t, err)

	tlsCredsOption := grpc.WithTransportCredentials(tlsCreds)
	unlockerConn, err := grpc.Dial("127.0.0.1:"+l.rpc, tlsCredsOption)
	require.NoError(t, err)

	unlocker := itest.NewWalletUnlockerClient(unlockerConn)
	_, err = unlocker.InitWallet(ctx, &itest.InitWalletRequest{
		WalletPassword: []byte("weks1234"),
		WatchOnly: &itest.WatchOnly{
			Accounts: grpcAccounts,
		},
	})
	require.NoError(t, err)

	// TODO(aakselrod): eliminate this
	time.Sleep(3 * time.Second)
}

func (l *lndHarness) Close(t *testing.T) {
	t.Helper()

	killProc(t, l.cmd, l.errPipe)
}

func (l *lndHarness) Lncli(t *testing.T, ctx context.Context,
	args ...string) map[string]interface{} {

	t.Helper()

	lnCliCmd := exec.CommandContext(ctx, l.lncliPath,
		append([]string{"--lnddir=" + l.lnddir,
			"--rpcserver=127.0.0.1:" + l.rpc,
			"--network=regtest"}, args...)...)

	stderrPipe, err := lnCliCmd.StderrPipe()
	require.NoError(t, err)

	stdoutPipe, err := lnCliCmd.StdoutPipe()
	require.NoError(t, err)

	err = lnCliCmd.Start()
	require.NoError(t, err)

	stdout, err := io.ReadAll(stdoutPipe)
	require.NoError(t, err)

	stderr, err := io.ReadAll(stderrPipe)
	require.NoError(t, err)

	err = lnCliCmd.Wait()
	require.NoError(t, err, string(stderr))

	if len(args) != 0 && args[0] == "payinvoice" {
		return nil
	}

	resp := make(map[string]interface{})
	err = json.Unmarshal(stdout, &resp)
	require.NoError(t, err)

	return resp
}
