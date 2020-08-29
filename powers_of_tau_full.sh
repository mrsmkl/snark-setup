#!/bin/bash

rm -f challenge* response* new_challenge* processed* initial_ceremony* response_list* combined*

POWER=10
BATCH=64
MAX_CHUNK_INDEX=3 # we have 16 chunks, since we have a total of 2^11-1 powers
CURVE="bw6"
SEED=`tr -dc 'A-F0-9' < /dev/urandom | head -c32`

powersoftau="cargo run --release --bin powersoftau -- --curve-kind $CURVE --batch-size $BATCH --contribution-mode full --power $POWER --seed $SEED"

####### Phase 1

$powersoftau new --challenge-fname challenge
yes | $powersoftau contribute --challenge-fname challenge --response-fname response
$powersoftau verify-and-transform-pok-and-correctness --challenge-fname challenge --response-fname response --new-challenge-fname new_challenge
$powersoftau verify-and-transform-ratios --response-fname new_challenge

