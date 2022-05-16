# ckb-taproot-deploy
A tool to deploy Taproot on CKB scripts (https://github.com/nervosnetwork/ckb-production-scripts/pull/57).


### Used Parameters

The parameters used in this deployment demo:


Alice's schnorr secret key: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

Alice's schnorr public key: 6a04ab98d9e4774ad806e302dddeb63bea16b5cb5f223ee77478e861bb583eb3
```bash
❯ ckb-taproot-deploy schnorr-operation --secret-key aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --mode pubkey
Public Key = 6a04ab98d9e4774ad806e302dddeb63bea16b5cb5f223ee77478e861bb583eb3
```
This is also served as taproot internal key.


Alice's lock script args: 06bc461fb583935be52e3d4295deeb9f7ef75e9bd2
```bash
ckb-taproot-deploy schnorr-operation --secret-key aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --mode lock-script-args
```


Bob's schnorr secret key: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb

Bob's schnorr public key: 68680737c76dabb801cb2204f57dbe4e4579e4f710cd67dc1b4227592c81e9b5
```
ckb-taproot-deploy schnorr-operation --secret-key bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  --mode pubkey
Public Key = 68680737c76dabb801cb2204f57dbe4e4579e4f710cd67dc1b4227592c81e9b5
```

Bob's lock script args: 06f359a7bd37b68c434b04b1129697e1378af5d143
```
ckb-taproot-deploy schnorr-operation --secret-key bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  --mode lock-script-args
Lock script args = 06f359a7bd37b68c434b04b1129697e1378af5d143
```

### Scenario

Alice wants to send some coins to Bob. She doesn't know whether Bob will accept
it. If Bob doesn't take the coin, Alice wants to get the coin back. The Taproot
on CKB can solve it by following steps:

1. Alice fetches the schnorr public key of Bob
2. Alice transfers some coin to cell locked by taproot lock script. The lock
   script args is a hash of taproot output key. Alice has already embedded Bob's
   schnorr public key into taproot output key. [An example transaction on
   testnet](https://pudge.explorer.nervos.org/transaction/0xa8067fac193537a4c80d5146a2e0cdfcb8254b9cec941480b56e581eccf0780a)

3. There are 2 possible results:
    - If Bob doesn't accept CKB in several weeks. Alice can reclaim coins by
      taproot output secret key. It uses key path spending.
    - Or Bob accepts the coin by script path spending. [An example transaction
      on
      testnet](https://pudge.explorer.nervos.org/transaction/0x6e1bc6ddf551d927b44f345ee3dcd3b7a126d02f4eb88100f008595f850801a4)

Check out [CKB Taproot Deploy Tool](https://github.com/XuJiandong/ckb-taproot-deploy) for more information.

### Shell Scripts Used

* Alice transfers CKB to Bob. [Script](scripts/transfer_taproot.sh)
* Bob Receives CKB by script path spending. [Script](scripts/transfer_secp256k1.sh)

If you want to configure your own transaction, please check out
[taproot-config.json](./taproot-config.json). If you want to deploy your own
taproot scripts, please check out [deploy-scripts](./deploy-scripts/). There
will be at least 2 scripts to deploy: One is taproot script itself and some
other one is taproot script. They are built from
[taproot_lock.c](https://github.com/nervosnetwork/ckb-production-scripts/blob/taproot-lock-audit/c/taproot_lock.c)
and
[example_script.c](https://github.com/nervosnetwork/ckb-production-scripts/blob/taproot-lock-audit/tests/taproot_lock/example_script.c).

