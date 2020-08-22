#!/bin/bash

rm -f challenge* response* new_challenge* processed* initial_ceremony* response_list* combined*

POWER=10
NUM_VALIDATORS=100
NUM_EPOCHS=30
BATCH=128
MAX_CHUNK_INDEX=15 # we have 16 chunks, since we have a total of 2^11-1 powers
CURVE="bw6"
SEED=`hexdump -n 16 -e '4/4 "%08X" 1 "\n"' /dev/random`

powersoftau="cargo run --release --bin powersoftau -- --curve-kind $CURVE --batch-size $BATCH --power $POWER --seed $SEED"
phase2="cargo run --release --bin prepare_phase2 -- --curve-kind $CURVE --batch-size $BATCH --power $POWER --phase2-size $POWER"
snark="cargo run --release --bin bls-snark-setup --"

####### Phase 1

for i in $(seq 0 $MAX_CHUNK_INDEX); do
  $powersoftau --chunk-index $i new --challenge-fname challenge_$i
  yes | $powersoftau --chunk-index $i contribute --challenge-fname challenge_$i --response-fname response_$i
  $powersoftau  --chunk-index $i verify-and-transform-chunk --challenge-fname challenge_$i --response-fname response_$i --new-challenge-fname new_challenge_$i
  rm challenge_$i # no longer needed
  echo response_$i >> response_list
done

$powersoftau combine --response-list-fname response_list --combined-fname combined
$powersoftau verify-and-transform-full --response-fname combined
