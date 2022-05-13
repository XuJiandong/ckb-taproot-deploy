#!/bin/bash

ckb-cli deploy sign-txs \
    --from-account ckt1qyqwykscqz8y3cgwa4c5jytzjv3c8hwar7msja6u7r \
    --add-signatures \
    --info-file info.json
