# Config

In this page, we will look at the config file of trojan. Trojan uses [`JSON`](https://en.wikipedia.org/wiki/JSON) as the format of the config.

**Note: all "\\" in the paths under Windows MUST be replaced with "/".**

## A valid client.json

```json
{
    "run_type": "client",
    "local_addr": "127.0.0.1",
    "local_port": 1080,
    "remote_addr": "example.com",
    "remote_port": 443,
    "password": [
        "password1"
    ],
    "log_level": 1,
    "ssl": {
        "verify": true,
        "verify_hostname": true,
        "cert": "",
        "cipher": "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:RSA-AES128-GCM-SHA256:RSA-AES256-GCM-SHA384:RSA-AES128-SHA:RSA-AES256-SHA:RSA-3DES-EDE-SHA",
        "sni": "",
        "alpn": [
            "h2",
            "http/1.1"
        ],
        "reuse_session": true,
        "session_ticket": false,
        "curves": ""
    },
    "tcp": {
        "no_delay": true,
        "keep_alive": true,
        "fast_open": false,
        "fast_open_qlen": 20
    }
}
```

- `run_type`: running trojan as `client`
- `local_addr`: a `SOCKS5` server interface will be bound to the specified interface. Feel free to change this to ``0.0.0.0``, ``::1``, ``::`` or other addresses, if you know what you are doing.
- `local_port`: a `SOCKS5` interface will be bound to this port
- `remote_addr`: server address (hostname)
- `remote_port`: server port
- `password`: password used for verification (only the first password in the array will be used)
- `log_level`: how much log to dump. 0: ALL; 1: INFO; 2: WARN; 3: ERROR; 4: FATAL; 5: OFF.
- `ssl`: `SSL` specific configurations
    - `verify`: whether to verify `SSL` certificate **STRONGLY RECOMMENDED**
    - `verify_hostname`: whether to verify `SSL` hostname (specified in the `sni` field) **STRONGLY RECOMMENDED**
    - `cert`: if `verify` is set to `true`, the same certificate used by the server or a collection of `CA` certificates could be provided. If you leave this field blank, `OpenSSL` will try to look for a system `CA` store and will be likely to fail.
    - `cipher`: a cipher list to send and use
    - `sni`: the Server Name Indication field in the `SSL` handshake. If left blank, it will be set to `remote_addr`.
    - `alpn`: a list of `ALPN` protocols to send
    - `reuse_session`: whether to reuse `SSL` session
    - `session_ticket`: whether to use session tickets for session resumption
    - `curves`: `ECC` curves to send and use
- `tcp`: `TCP` specific configurations
    - `no_delay`: whether to disable Nagle's algorithm
    - `keep_alive`: whether to enable TCP Keep Alive
    - `fast_open`: whether to enable TCP Fast Open (kernel support required)
    - `fast_open_qlen`: the server's limit on the size of the queue of TFO requests that have not yet completed the three-way handshake

## A valid forward.json

This forward config is for port forwarding. Everything is the same as the client config, except for `target_addr` and `target_port`, which point to the destination endpoint, and `udp_timeout`, which controls how long (in seconds) a UDP session will last in idle.

```json
{
    "run_type": "forward",
    "local_addr": "127.0.0.1",
    "local_port": 5901,
    "remote_addr": "example.com",
    "remote_port": 443,
    "target_addr": "127.0.0.1",
    "target_port": 5901,
    "password": [
        "password1"
    ],
    "udp_timeout": 60,
    "log_level": 1,
    "ssl": {
        "verify": true,
        "verify_hostname": true,
        "cert": "",
        "cipher": "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:RSA-AES128-GCM-SHA256:RSA-AES256-GCM-SHA384:RSA-AES128-SHA:RSA-AES256-SHA:RSA-3DES-EDE-SHA",
        "sni": "",
        "alpn": [
            "h2",
            "http/1.1"
        ],
        "reuse_session": true,
        "session_ticket": false,
        "curves": ""
    },
    "tcp": {
        "no_delay": true,
        "keep_alive": true,
        "fast_open": false,
        "fast_open_qlen": 20
    }
}
```

## A valid nat.json

The NAT config is for transparent proxy. You'll need to [setup iptables rules](https://github.com/shadowsocks/shadowsocks-libev/tree/v3.3.1#transparent-proxy) to use it. Everything is the same as the client config.

```json
{
    "run_type": "nat",
    "local_addr": "127.0.0.1",
    "local_port": 12345,
    "remote_addr": "example.com",
    "remote_port": 443,
    "password": [
        "password1"
    ],
    "log_level": 1,
    "ssl": {
        "verify": true,
        "verify_hostname": true,
        "cert": "",
        "cipher": "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:RSA-AES128-GCM-SHA256:RSA-AES256-GCM-SHA384:RSA-AES128-SHA:RSA-AES256-SHA:RSA-3DES-EDE-SHA",
        "sni": "",
        "alpn": [
            "h2",
            "http/1.1"
        ],
        "reuse_session": true,
        "session_ticket": false,
        "curves": ""
    },
    "tcp": {
        "no_delay": true,
        "keep_alive": true,
        "fast_open": false,
        "fast_open_qlen": 20
    }
}
```

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
        "cipher": "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256",
        "prefer_server_cipher": true,
        "alpn": [
            "http/1.1"
        ],
        "reuse_session": true,
        "session_ticket": false,
        "session_timeout": 600,
        "plain_http_response": "",
        "curves": "",
        "dhparam": ""
    },
    "tcp": {
        "prefer_ipv4": false,
        "no_delay": true,
        "keep_alive": true,
        "fast_open": false,
        "fast_open_qlen": 20
    },
    "mysql": {
        "enabled": false,
        "server_addr": "127.0.0.1",
        "server_port": 3306,
        "database": "trojan",
        "username": "trojan",
        "password": ""
    }
}
```

- `run_type`: running trojan as `server`
- `local_addr`: trojan server will be bound to the specified interface. Feel free to change this to `::` or other addresses, if you know what you are doing.
- `local_port`: trojan server will be bound to this port
- `remote_addr`: the endpoint address that trojan server will connect to when encountering [other protocols](protocol#other-protocols)
- `remote_port`: the endpoint port that trojan server will connect when encountering [other protocols](protocol#other-protocols)
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
    - `session_ticket`: whether to use session tickets for session resumption
    - `session_timeout`: if `reuse_session` is set to `true`, specify `SSL` session timeout
    - `plain_http_response`: respond to plain http request with this file (raw TCP)
    - `curves`: `ECC` curves to use
    - `dhparam`: if left blank, default (RFC 3526) dhparam will be used, otherwise the specified dhparam file will be used
- `tcp`: `TCP` specific configurations
    - `prefer_ipv4`: whether to connect to the IPv4 address when there are both IPv6 and IPv4 addresses for a domain
    - `no_delay`: whether to disable Nagle's algorithm
    - `keep_alive`: whether to enable TCP Keep Alive
    - `fast_open`: whether to enable TCP Fast Open (kernel support required)
    - `fast_open_qlen`: the server's limit on the size of the queue of TFO requests that have not yet completed the three-way handshake
- `mysql`: see [Authenticator](authenticator)

[Homepage](.) | [Prev Page](protocol) | [Next Page](authenticator)
