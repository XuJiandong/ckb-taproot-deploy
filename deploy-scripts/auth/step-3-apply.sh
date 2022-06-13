#!/bin/bash

ckb-cli --url https://testnet.ckbapp.dev/rpc deploy apply-txs --migration-dir ./migrations --info-file info.json

