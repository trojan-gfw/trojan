#!/bin/sh
[ "$1" ] || exit 1 
trojan=`realpath $1`
tmpdir=`mktemp -d`
echo Test directory is $tmpdir.
cp server.json fake-client.json $tmpdir
cd $tmpdir
exec 2>>test.log 

yes '' | openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 1 -nodes

mkdir true fake
echo true >true/whoami.txt
echo fake >fake/whoami.txt
{ cd true; python2 -m SimpleHTTPServer 10081 >server.log 2>&1; } &
{ cd fake; python2 -m SimpleHTTPServer 10080 >server.log 2>&1; } &

$trojan server.json 2>server.log &
$trojan fake-client.json 2>client.log &

sleep 1

whoami=`curl -v --socks5 127.0.0.1:11080 http://127.0.0.3:10081/whoami.txt`
whoami2=`curl -v --insecure https://127.0.0.2:10443/whoami.txt`
if [ "$whoami" != true -a "$whoami2" = fake ]; then
  rm -rf $tmpdir
  echo PASS
else
  echo FAIL
fi

trap 'exit' INT TERM
kill 0
