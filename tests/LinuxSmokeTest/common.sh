function check_available() {
    if ! command -v "$1" > /dev/null; then
        echo "$1 is required."
        exit 1
    fi
}

function wait_port() {
    until nc -z 127.0.0.1 "$1"; do
        sleep 0.1
    done
}

if [[ "$#" != "1" ]]; then
    echo "usage: $0 path_to_trojan"
    exit 1
fi

check_available curl
check_available nc
check_available openssl
check_available python3

SCRIPTDIR="$(dirname "$0")"
TMPDIR="$(mktemp -d)"

echo "$TMPDIR"
cp "$1" "$TMPDIR/trojan"
cd "$SCRIPTDIR"
