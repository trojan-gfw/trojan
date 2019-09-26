#!/bin/bash
set -u

source "$(dirname "$0")/common.sh"

cp server.json fake-client.json forward.json "$TMPDIR"
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

./trojan -t fake-client.json
./trojan fake-client.json -l fake-client.log &
PID4="$!"

wait_port 10081
wait_port 10080
wait_port 10443
wait_port 11080

WHOAMI=$(curl -v --socks5 127.0.0.1:11080 http://127.0.0.1:10081/whoami.txt)
WHOAMI2=$(curl -v --insecure https://127.0.0.1:10443/whoami.txt)
kill -KILL "$PID1" "$PID2" "$PID3" "$PID4"
if [[ "$WHOAMI" != "true" && "$WHOAMI2" = "fake" ]]; then
    exit 0
else
    exit 1
fi
