# Config

In this page, we will look at the config file of trojan. Trojan uses [`JSON`](https://en.wikipedia.org/wiki/JSON) as the format of the config. A config generator can be found [here](https://trojan-gfw.github.io/trojan-config-gen/).

**Note: all "\\" in the paths under Windows MUST be replaced with "/".**

## A valid client.json

```json
{
    "run_type": "client",
    "local_addr": "127.0.0.1",
    "local_port": 1080,
    "remote_addr": "example.com",
    "remote_port": 443,
    "password": ["password1"],
    "append_payload": true,
    "log_level": 1,
    "ssl": {
        "verify": true,
        "verify_hostname": true,
        "cert": "",
        "cipher": "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA:AES128-SHA:AES256-SHA:DES-CBC3-SHA",
        "sni": "example.com",
        "alpn": [
            "h2",
            "http/1.1"
        ],
        "reuse_session": true,
        "curves": "",
        "sigalgs": ""
    },
    "tcp": {
        "keep_alive": true,
        "no_delay": true,
        "fast_open": true,
        "fast_open_qlen": 5
    }
}
```

- `run_type`: running trojan as `client`
- `local_addr`: a `SOCKS5` server interface will be bound to the specified interface. Feel free to change this to ``0.0.0.0``, ``::1``, ``::`` or other addresses, if you know what you are doing.
- `local_port`: a `SOCKS5` interface will be bound to this port
- `remote_addr`: server address (hostname)
- `remote_port`: server port
- `password`: password used for verification (only the first password in the array will be used)
- `append_payload`: whether to append the first packet to trojan request. It can reduce length patterns of sessions, but may cause stability issues, in which case set it to `false`.
- `log_level`: how much log to dump. 0: ALL; 1: INFO; 2: WARN; 3: ERROR; 4: FATAL; 5: OFF.
- `ssl`: `SSL` specific configurations
    - `verify`: whether to verify `SSL` certificate **STRONGLY RECOMMENDED**
    - `verify_hostname`: whether to verify `SSL` hostname (specified in the `sni` field) **STRONGLY RECOMMENDED**
    - `cert`: if `verify` is set to `true`, the same certificate used by the server or a collection of `CA` certificates could be provided. If you leave this field blank, `OpenSSL` will try to look for a system `CA` store and will be likely to fail.
    - `cipher`: a cipher list to send and use
    - `sni`: the Server Name Indication field in the `SSL` handshake
    - `alpn`: a list of `ALPN` protocols to send
    - `reuse_session`: whether to reuse `SSL` session
    - `curves`: `ECC` curves to send and use
    - `sigalgs`: signature algorithms to send and use
- `tcp`: `TCP` specific configurations
    - `keep_alive`: whether to enable TCP Keep Alive
    - `no_delay`: whether to disable Nagle's algorithm
    - `fast_open`: whether to enable TCP Fast Open (kernel support required)
    - `fast_open_qlen`: the server's limit on the size of the queue of TFO requests that have not yet completed the three-way handshake

## A valid server.json

```json
{
    "run_type": "server",
    "local_addr": "0.0.0.0",
    "local_port": 443,
    "remote_addr": "127.0.0.1",
    "remote_port": 80,
    "password": [
        "password1",
        "password2"
    ],
    "log_level": 1,
    "ssl": {
        "cert": "/path/to/certificate.crt",
        "key": "/path/to/private.key",
        "key_password": "",
        "cipher": "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:DES-CBC3-SHA:!DSS",
        "prefer_server_cipher": true,
        "alpn": [
            "http/1.1"
        ],
        "reuse_session": true,
        "session_timeout": 300,
        "curves": "",
        "sigalgs": "",
        "dhparam": ""
    },
    "tcp": {
        "keep_alive": true,
        "no_delay": true,
        "fast_open": true,
        "fast_open_qlen": 5
    }
}
```

- `run_type`: running trojan as `server`
- `local_addr`: trojan server will be bound to the specified interface. Feel free to change this to `::` or other addresses, if you know what you are doing.
- `local_port`: trojan server will be bound to this port
- `remote_addr`: the endpoint address that trojan server will connect to when encountering other protocols
- `remote_port`: the endpoint port that trojan server will connect when encountering other protocols
- `password`: an array of passwords used for verification
- `log_level`: how much log to dump. 0: ALL; 1: INFO; 2: WARN; 3: ERROR; 4: FATAL; 5: OFF.
- `ssl`: `SSL` specific configurations
    - `cert`: server certificate **STRONGLY RECOMMENDED TO BE SIGNED BY A CA**
    - `key`: private key file for encryption
    - `key_password`: password of the private key file
    - `cipher`: a cipher list to use
    - `prefer_server_cipher`: whether to prefer server cipher list in a connection
    - `alpn`: a list of `ALPN` protocols to reply
    - `reuse_session`: whether to reuse `SSL` session
    - `session_timeout`: if `reuse_session` is set to `true`, specify `SSL` session timeout
    - `curves`: `ECC` curves to use
    - `sigalgs`: signature algorithms to use
    - `dhparam`: if left blank, default (RFC 3526) dhparam will be used, otherwise the specified dhparam file will be used
- `tcp`: `TCP` specific configurations
    - `keep_alive`: whether to enable TCP Keep Alive
    - `no_delay`: whether to disable Nagle's algorithm
    - `fast_open`: whether to enable TCP Fast Open (kernel support required)
    - `fast_open_qlen`: the server's limit on the size of the queue of TFO requests that have not yet completed the three-way handshake

[Homepage](.) | [Prev Page](protocol) | [Next Page](build)
