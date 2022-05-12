# ckb-taproot-deploy
A tool to deploy CKB Taproot scripts (https://github.com/nervosnetwork/ckb-production-scripts/pull/58).



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

Alice wants to send some coin to Bob. She don't know Bob will accept it. If Bob
doesn't take the coin, Alice want to get the coin back. The taproot on CKB can
solve it by following steps:


1. Alice get the schnorr public key of Bob
2. Alice transfer some CKB to cell locked by taproot lock script. The lock script args is a hash of taproot output key.
   Alice aso embed bob's schnorr public key  in taproot output key.
3. There are 2 possible results:
    - If Bob doesn't accept CKB in several weeks. Alice can reclaim CKB by taproot output secret key. It uses key path spending.
    - Or Bob accept the coin by script path spending.
