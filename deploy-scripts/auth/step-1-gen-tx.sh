#!/bin/bash

ckb-cli --url https://testnet.ckbapp.dev/rpc deploy gen-txs \
    --deployment-config ./deployment.toml \
    --migration-dir ./migrations \
    --from-address ckt1qyqwykscqz8y3cgwa4c5jytzjv3c8hwar7msja6u7r \
    --sign-now \
    --info-file info.json
