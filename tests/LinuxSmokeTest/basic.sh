#!/bin/bash
set -eu

source "$(dirname "$0")/common.sh"

cp server.json client.json forward.json "$TMPDIR"
cd "$TMPDIR"

exec 2>> test.log

yes '' | openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 1 -nodes

mkdir true
cd true
echo true > whoami.txt
python3 -m http.server 10081 > server.log 2>&1 &
PID1="$!"
cd ..

mkdir fake
cd fake
echo fake > whoami.txt
python3 -m http.server 10080 > server.log 2>&1 &
PID2="$!"
cd ..

./trojan -v

./trojan -t server.json
./trojan server.json -l server.log &
PID3="$!"

./trojan -t client.json
./trojan client.json -l client.log &
PID4="$!"

./trojan -t forward.json
./trojan forward.json -l forward.log &
PID5="$!"

wait_port 10081
wait_port 10080
wait_port 10443
wait_port 11080
wait_port 20081

WHOAMI=$(curl -v --socks5 127.0.0.1:11080 http://127.0.0.1:10081/whoami.txt)
WHOAMI2=$(curl -v http://127.0.0.1:20081/whoami.txt)
kill -KILL "$PID1" "$PID2" "$PID3" "$PID4" "$PID5"
if [[ "$WHOAMI" = "true" && "$WHOAMI2" = "true" ]]; then
    exit 0
else
    exit 1
fi
