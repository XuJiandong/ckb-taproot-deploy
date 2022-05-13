#!/bin/bash
target/debug/ckb-taproot-deploy transfer-secp256k1  \
    --execscript-key bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
    --execscript-args 06f359a7bd37b68c434b04b1129697e1378af5d143 \
    --smt-root 4b1913da999e0050c1ff1a8425811d20db8c94f2f34b0b80084ac5dd1bea3366 \
    --smt-proof 4c4ffe51f647dbecdc20bfc265cdadfe95f7b5d077ff1fad9806a27e099deb14189653ea7500000000000000000000000000000000000000000000000000000000000000004f01 \
    --taproot-internal-key 6a04ab98d9e4774ad806e302dddeb63bea16b5cb5f223ee77478e861bb583eb3 \
    --receiver ckt1qyqwykscqz8y3cgwa4c5jytzjv3c8hwar7msja6u7r \
    --capacity 150
