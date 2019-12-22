#!/bin/bash
set -euo pipefail

NAME_SPACE="tcp-sniffer"
IN_NS="sudo ip netns exec $NAME_SPACE"
TIMEOUT="5s"
PAYLOAD="aimazing"

make

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

$IN_NS nc -v -l localhost -p 2222 &
$IN_NS ./main lo $tmpfile 1 &
sleep 1
# Generate some TCP traffic
printf $PAYLOAD | $IN_NS nc -v localhost 2222

for job in $(jobs -p); do
	echo $job
	wait $job # Wait for background jobs to finish
done

if [[ "$(cat $tmpfile)" == "$PAYLOAD" ]]; then
	echo "System Test Passed!"
	exit 0
else
	echo "System Test FAILED :("
	exit 1
fi
