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
03dc60dce282bb96abb4328c3e19640aa4f87defc400458322b80f0b73c2b14263    regtest
```

The value is the network specified above. Note that the Vault plugin is multi-tenant (supports multiple nodes), so you can add more nodes by writing as above.

Create a directory `~/.lndsigner` (Linux) with a `signer.conf` similar to:

```
rpclisten=tcp://127.0.0.1:10021
network=regtest
nodepubkey=*pubkey*
```

Use the pubkey from the node you created above. Note that on other platforms, the lndsigner directory you need to create may be different, such as:

- `C:\Users\<username>\AppData\Local\Lndsigner` on Windows
- `~/Library/Application Support/Lndsigner` on MacOS

The rest of this README assumes you're working on Linux. Additional documentation for other platforms welcome.

You'll need to provide a `tls.key` and `tls.cert` for the daemon. This allows it to accept TLS connections and lets `lnd` to authenticate that it's connecting to the correct signer, as configured below. For testing purposes, you can grab some that are auto-generated by a regtest instance of `lnd`. For deploy, you'll want your infrastructure to create these.

Run the signer binary as follows:

```
~/.lndsigner$ VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root lndsignerd
```

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

Next, get the account list for the node (this works on Linux with `jq` installed):

```
~/.lnd-watchonly$ VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root \
   vault read lndsigner/lnd-nodes/accounts node=*pubkey* | \
   tail -n 1 | sed s/acctList\\s*// | jq > accounts.json
```

You'll get an `accounts.json` file that starts like:

```
{
  "accounts": [
    {
      "name": "default",
      "address_type": "HYBRID_NESTED_WITNESS_PUBKEY_HASH",
      "extended_public_key": "upub...
```

Now, run `lnd` in watch-only mode:

```
~/.lnd-watchonly$ lnd --lnddir=.
```

Create the watch-only wallet using the accounts exported by the signer:

```
~$ lncli createwatchonly .lndsigner/accounts.json
```

Now you can use your node as usual. Note that MuSig2 isn't supported yet. If you created multiple nodes in the vault, you can create a separate directory for each signer instance (`.lndsigner`) and each watch-only node (`.lnd`) and start each as above.
