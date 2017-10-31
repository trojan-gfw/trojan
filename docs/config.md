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
    "password": "password",
    "ssl_verify": true,
    "ssl_verify_hostname": true,
    "ca_certs": "/path/to/ca_certs.pem",
    "log_level": 1
}
```

- `run_type`: running trojan as `client`
- `local_addr`: A `SOCKS5` server interface will be bound to the specified interface. Feel free to change this to ``0.0.0.0``, ``::1``, ``::`` or other addresses, if you know what you are doing.
- `local_port`: A `SOCKS5` interface will be bound to this port.
- `remote_addr`: server address
- `remote_port`: server port
- `password`: password used for verification
- `ssl_verify`: whether to verify `SSL` certificate. **STRONGLY RECOMMENDED**
- `ssl_verify_hostname`: whether to verify `SSL` hostname. **STRONGLY RECOMMENDED**
- `ca_certs`: if `ssl_verify` is set to `true`, a collection of `CA` certificates should be provided. A client may also use the same certificate used by the server. Note that if you leave this field blank, `OpenSSL` will try to look for a system `CA` and will likely to fail.
- `log_level`: specify how much log to dump. 0: ALL; 1: INFO; 2: WARN; 3: ERROR; 4: FATAL; 5: OFF.

## A valid server.json

```json
{
    "run_type": "server",
    "local_addr": "0.0.0.0",
    "local_port": 443,
    "remote_addr": "127.0.0.1",
    "remote_port": 80,
    "password": "password",
    "keyfile": "/path/to/private.key",
    "keyfile_password": "keyfile_password",
    "certfile": "/path/to/cert_chain.crt",
    "use_default_dhparam": true,
    "dhparamfile": "",
    "log_level": 1
}
```

- `run_type`: running trojan as `server`
- `local_addr`: trojan server will be bound to the specified interface. Feel free to change this to `::` or other addresses, if you know what you are doing.
- `local_port`: trojan server will be bound to this port.
- `remote_addr`: the endpoint address that trojan server will connect to when encountering other protocols.
- `remote_port`: the endpoint port to which trojan server connects when encountering other protocols.
- `password`: password used for verification
- `keyfile`: private key file for encryption
- `keyfile_password`: password of the keyfile
- `certfile`: server certificate **STRONGLY RECOMMENDED TO BE SIGNED BY A CA**
- `use_default_dhparam`: whether to use default (RFC 3526) dhparam.
- `dhparamfile`: if `use_default_dhparam` is set to false, specify the dhparam file.
- `log_level`: specify how much log to dump. 0: ALL; 1: INFO; 2: WARN; 3: ERROR; 4: FATAL; 5: OFF.

[Homepage](.) | [Prev Page](protocol) | [Next Page](compile)
