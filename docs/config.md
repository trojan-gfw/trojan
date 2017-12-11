# Config

In this page we will look at the config file of trojan. Trojan uses [`JSON`](https://en.wikipedia.org/wiki/JSON) as the format of the config.

## A valid client.json

```json
{
    "run_type": "client",
    "local_addr": "127.0.0.1",
    "local_port": 1080,
    "remote_addr": "example.com",
    "remote_port": 443,
    "password": ["password1"],
    "log_level": 1,
    "ssl": {
        "sigalgs": "",
        "curves": "",
        "cipher": "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA:AES128-SHA:AES256-SHA:DES-CBC3-SHA",
        "verify": true,
        "verify_hostname": true,
        "cert": "/path/to/ca_certs.pem",
        "reuse_session": true,
        "alpn": [
            "h2",
            "http/1.1"
        ]
    }
}
```

- `run_type`: running trojan as `client`
- `local_addr`: a `SOCKS5` server interface will be bound to the specified interface. Feel free to change this to ``0.0.0.0``, ``::1``, ``::`` or other addresses, if you know what you are doing.
- `local_port`: a `SOCKS5` interface will be bound to this port
- `remote_addr`: server address (hostname)
- `remote_port`: server port
- `password`: password used for verification (only the first password in the array will be used)
- `log_level`: specify how much log to dump. 0: ALL; 1: INFO; 2: WARN; 3: ERROR; 4: FATAL; 5: OFF.
- `ssl`: `SSL` specific configurations
    - `sigalgs`: specify signature algorithms to send and use
    - `curves`: specify `ECC` curves to send and use
    - `cipher`: specify cipher list to send and use
    - `verify`: whether to verify `SSL` certificate **STRONGLY RECOMMENDED**
    - `verify_hostname`: whether to verify `SSL` hostname **STRONGLY RECOMMENDED**
    - `cert`: if `verify` is set to `true`, a collection of `CA` certificates should be provided. A client may also use the same certificate used by the server. Note that if you leave this field blank, `OpenSSL` will try to look for a system `CA` and will be likely to fail.
    - `reuse_session`: whether to reuse `SSL` session
    - `alpn`: specify a list of `ALPN` protocols to send

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
        "sigalgs": "",
        "curves": "",
        "cipher": "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:DES-CBC3-SHA:!DSS",
        "cert": "/path/to/certificate.crt",
        "key": "/path/to/private.key",
        "key_password": "key_password",
        "dhparam": "",
        "reuse_session": true,
        "alpn": [
            "http/1.1"
        ]
    }
}
```

- `run_type`: running trojan as `server`
- `local_addr`: trojan server will be bound to the specified interface. Feel free to change this to `::` or other addresses, if you know what you are doing.
- `local_port`: trojan server will be bound to this port
- `remote_addr`: the endpoint address that trojan server will connect to when encountering other protocols
- `remote_port`: the endpoint port to which trojan server connects when encountering other protocols
- `password`: an array of passwords used for verification
- `log_level`: specify how much log to dump. 0: ALL; 1: INFO; 2: WARN; 3: ERROR; 4: FATAL; 5: OFF.
- `ssl`: `SSL` specific configurations
    - `sigalgs`: specify signature algorithms to use
    - `curves`: specify `ECC` curves to use
    - `cipher`: specify cipher list to use
    - `cert`: server certificate **STRONGLY RECOMMENDED TO BE SIGNED BY A CA**
    - `key`: private key file for encryption
    - `key_password`: password of the private key file
    - `dhparam`: If left blank, default (RFC 3526) dhparam will be used, otherwise the specified dhparam file will be used.
    - `reuse_session`: whether to reuse `SSL` session
    - `alpn`: specify a list of `ALPN` protocols to reply

[Homepage](.) | [Prev Page](protocol) | [Next Page](compile)
