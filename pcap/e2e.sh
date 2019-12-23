#!/bin/bash
set -euo pipefail

NAME_SPACE="tcp-sniffer"
IN_NS="sudo ip netns exec $NAME_SPACE"
TIMEOUT="5s"
PAYLOAD="aimazing"

# Setup isolated network environment for testing
sudo ip netns add tcp-sniffer
function remove_netns() {
	sudo ip netns del tcp-sniffer
}
trap remove_netns EXIT

$IN_NS ip link set up lo

tmpfile=$(mktemp)
function remove_tmpfile() {
	rm $tmpfile
	remove_netns
}
trap remove_tmpfile EXIT

$IN_NS nc -v -l 127.0.0.1 -p 2222 >/dev/null &
$IN_NS timeout -s SIGINT 5s ./main.out lo $tmpfile &
pid=$!
sleep 0.1
# Generate some TCP traffic
printf "$PAYLOAD" | $IN_NS nc -q -v 127.0.0.1 2222

wait $pid || echo Timeout # Wait for packet capturing to finish or timeout

if [[ "$(cat $tmpfile)" == "$PAYLOAD" ]]; then
	echo "System Test Passed!"
	exit 0
else
	echo "System Test FAILED :("
	exit 1
fi
