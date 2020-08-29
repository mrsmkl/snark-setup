#!/bin/bash

rm -f challenge* response* new_challenge* processed* initial_ceremony* response_list* combined*

POWER=10
BATCH=64
CHUNK_SIZE=512
MAX_CHUNK_INDEX=3 # we have 16 chunks, since we have a total of 2^11-1 powers
CURVE="bw6"
SEED=`tr -dc 'A-F0-9' < /dev/urandom | head -c32`

powersoftau="cargo run --release --bin powersoftau -- --curve-kind $CURVE --batch-size $BATCH --contribution-mode chunked --chunk-size $CHUNK_SIZE --power $POWER --seed $SEED"
powersoftau_full="cargo run --release --bin powersoftau -- --curve-kind $CURVE --batch-size $BATCH --contribution-mode full --power $POWER --seed $SEED"

####### Phase 1

for i in $(seq 0 $MAX_CHUNK_INDEX); do
  $powersoftau --chunk-index $i new --challenge-fname challenge_$i
  yes | $powersoftau --chunk-index $i contribute --challenge-fname challenge_$i --response-fname response_$i
  $powersoftau --chunk-index $i verify-and-transform-pok-and-correctness --challenge-fname challenge_$i --response-fname response_$i --new-challenge-fname new_challenge_$i
  rm challenge_$i new_challenge_$i # no longer needed
  echo response_$i >> response_list
done

$powersoftau combine --response-list-fname response_list --combined-fname combined
$powersoftau_full beacon --challenge-fname combined --response-fname response_beacon --beacon-hash 0000000000000000000a558a61ddc8ee4e488d647a747fe4dcc362fe2026c620
$powersoftau_full verify-and-transform-pok-and-correctness --challenge-fname combined --response-fname response_beacon --new-challenge-fname response_beacon_new_challenge
$powersoftau verify-and-transform-ratios --response-fname response_beacon_new_challenge
