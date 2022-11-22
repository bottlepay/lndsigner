# lndsigner
`lndsigner` is a [remote signer](https://github.com/lightningnetwork/lnd/blob/master/docs/remote-signing.md) for [lnd](https://github.com/lightningnetwork/lnd). Currently, it can do the following:
- [x] store seeds for multiple nodes in [Hashicorp Vault](https://github.com/hashicorp/vault/)
- [x] perform derivation and signing operations in a Vault plugin
- [x] export account list for watch-only lnd instance on startup
- [x] sign messages for network announcements
- [x] derive shared keys for peer connections
- [x] sign PSBTs for on-chain transactions, channel openings/closes, HTLC updates, etc.
- [ ] perform musig2 ops
- [ ] track on-chain wallet state and enforce policy for on-chain transactions
- [ ] track channel state and enforce policy for channel updates
- [ ] allow preauthorizations for on-chain transactions, channel opens/closes, and channel updates
- [ ] allow an interceptor to determine whether or not to sign
- [ ] run unit tests and itests, do automated/reproducible builds
- [ ] log and gather metrics coherently
- [ ] enforce custom SELinux policy to harden plugin execution environment

## Usage

Ensure you have `bitcoind`, `lnd`, and `vault` installed. Build `signer` using Go 1.18+ from this directory:

```
$ go install ./cmd/...
```

Create a directory `~/vault_plugins` and then move the `vault-plugin-lndsigner` binary to it.

Start Vault from your home directory:

```
~$ vault server -dev -dev-root-token-id=root -dev-plugin-dir=./vault_plugins -log-level=trace
```

Enable the signer plugin:

```
$ VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root vault secrets enable --path=lndsigner vault-plugin-lndsigner
```

Create a new node:

```
$ VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root vault write lndsigner/lnd-nodes network=regtest

```

Note that this should return a pubkey for the new node:

```
Key     Value
---     -----
node    03dc60dce282bb96abb4328c3e19640aa4f87defc400458322b80f0b73c2b14263
```

You can also list the nodes as follows:

```
$ VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root vault read lndsigner/lnd-nodes
Key                                                                   Value
---                                                                   -----
03dc60dce282bb96abb4328c3e19640aa4f87defc400458322b80f0b73c2b14263    1
```

The value is the HDCoinType used for the wallet, derived from the network specified above. Note that the plugin and signer support multiple nodes, so you can add more nodes by writing as above.

Create a directory `~/.lndsigner` with a `signer.conf` similar to:

```
rpclisten=tcp://127.0.0.1:10021
regtest=true
nodepubkey=*pubkey*
```

Use the pubkey from the node you created above.

Run the signer binary as follows:

```
~/.lndsigner$ VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root \
              lndsignerd --outputaccounts=accounts.json --debuglevel=trace
```

You'll notice some new files created, such as `tls.key` and `tls.cert` for the signer's GRPC interface. You'll also notice a file called `accounts.json, which you'll need to pass to `lnd` in a future step.

Ensure you have a `bitcoind` instance running locally on regtest. Then, create a directory `~/.lnd-watchonly` with a `lnd.conf` similar to:

```
[bitcoin]
bitcoin.active=true
bitcoin.regtest=true
bitcoin.node=bitcoind

[remotesigner]
remotesigner.enable=true
remotesigner.rpchost=127.0.0.1:10021
remotesigner.tlscertpath=/home/*user*/.lndsigner/tls.cert
remotesigner.macaroonpath=any.macaroon
```

Note that `lnd` checks that the macaroon file deserializes correctly but lndsigner ignores the macaroon.

Now, run `lnd` in watch-only mode:

```
~/.lnd-watchonly$ lnd --lnddir=.
```

Create the watch-only wallet using the accounts exported by the signer:

```
~$ lncli createwatchonly .lndsigner/accounts.json
```

Now you can use your node as usual. Note that MuSig2 isn't supported yet. If you created multiple nodes in the vault, you can create a separate directory for each signer instance and each watch-only node and start it as above.
