#!/usr/bin/env bash
set -e

N=${1:-3}

mkdir -p rethink_shards

for i in $(seq 1 $N); do
  export SHARD=$i
  export PORT_BASE=$((600 + i))
  envsubst < shard-template.yml > rethink_shards/shard_${i}_compose.yml
done
