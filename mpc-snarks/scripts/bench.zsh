#!/usr/bin/env zsh
trap "exit" INT TERM
trap "kill 0" EXIT

pkill mpc-test || true

n_parties=$1
if [[ -z $BIN ]]
then
    BIN=../target/debug/mpc-test
fi
if [[ -z $NETWORK_CONFIG ]]
then
    NETWORK_CONFIG=./data/$n_parties
fi
if [ $n_parties -ne 2 ]
then
    echo "n_parties must be 2"
    exit 1
fi


function usage {
  echo "Usage: $0 N_PARTIES" >&2
  exit 1
}

if [ "$#" -ne 1 ] ; then
    usage
fi

PROCS=()
for i in $(seq 0 $(($n_parties - 1)))
do
    if [ $i -eq 0 ]
    then
    $BIN mpc --hosts $NETWORK_CONFIG --party $i > logs_party_0.txt &
    pid=$!
    else
    $BIN mpc --hosts $NETWORK_CONFIG --party $i > logs_party_1.txt &
    pid=$!
    fi
    PROCS+=($pid)
done

for pid in ${PROCS}
do
    wait $pid
done

trap - INT TERM EXIT
