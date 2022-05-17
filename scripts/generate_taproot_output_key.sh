#!/bin/bash

target/debug/ckb-taproot-deploy schnorr-operation \
    --secret-key aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    --tweak ffb76f4c53c2baf55acafbde9e2d2239c5c349f06537c8f61ae7adaa06a41c3c \
    --mode generate-taproot-output-key
