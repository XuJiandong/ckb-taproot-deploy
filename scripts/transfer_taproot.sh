#!/bin/bash
target/debug/ckb-taproot-deploy --dry-run transfer-taproot  \
    --sender-key=$PRIVATE_KEY \
    --execscript-args=06f359a7bd37b68c434b04b1129697e1378af5d143 \
    --taproot-internal-key=6a04ab98d9e4774ad806e302dddeb63bea16b5cb5f223ee77478e861bb583eb3 \
    --capacity 517

