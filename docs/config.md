# Config

In this page we will look at the config file of trojan. Trojan uses [`JSON`](https://en.wikipedia.org/wiki/JSON) as the format of the config.

## Client

Example:

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
    "ca_certs": "/path/to/ca_certs.pem"
}
```

- `run_type`: we are running trojan as `client`.
- `local_addr`: the `SOCKS5` interface will be bound to this network interface. Feel free to change this to ``0.0.0.0``, ``::1``, ``::`` or other addresses if you know what you are doing.
- `local_port`: the `SOCKS5` interface will be bound to this port.
- `remote_addr`: the trojan server address.
- `remote_port`: the trojan server port.
- `password`: the trojan server password.
- `ssl_verify`: whether to verify `SSL` certificate. **STRONGLY RECOMMENDED**
- `ssl_verify_hostname`: whether to verify `SSL` hostname. **STRONGLY RECOMMENDED**
- `ca_certs`: if you choose to verify `SSL` certificate, which `CA` are you using? You can also choose the server certificate directly. Note that if you leave this field blank, `OpenSSL` will try to look for system `CA` and will usually fail.

## Server

Example:

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
    "certfile": "/path/to/cert_chain.crt"
}
```

- `run_type`: we are running trojan as `server`.
- `local_addr`: trojan server will be bound to this network interface. Feel free to change this to ``::`` or other addresses if you know what you are doing.
- `local_port`: trojan server will be bound to this port.
- `remote_addr`: the endpoint address that trojan server will connect to when encountering other protocols.
- `remote_port`: the endpoint port that trojan server will connect to when encountering other protocols.
- `password`: trojan server password.
- `keyfile`: private key file used to encrypt traffic.
- `keyfile_password`: private key file decrypt password.
- `certfile`: server certification. **STRONGLY RECOMMENDED TO BE SIGNED BY A CA**

[Homepage](.) | [Prev Page](protocol) | [Next Page](build)
