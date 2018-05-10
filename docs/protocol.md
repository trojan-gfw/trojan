# The Trojan Protocol

We will now show how a trojan server will react to a **valid Trojan Protocol** and **other protocols** (possibly `HTTPS` or any other probes).

## Valid Trojan Protocol

When a trojan client connects to a server, it first performs a **real** `TLS` handshake. If the handshake succeeds, all subsequent traffic will be protected by `TLS`; otherwise, the server will close the connection immediately as any `HTTPS` server would. Then the client sends the following structure:

```
+-----------------------+---------+----------------+---------+----------+
| hex(ssh224(password)) |  CRLF   | Trojan Request |  CRLF   | Payload  |
+-----------------------+---------+----------------+---------+----------+
|          56           | X'0D0A' |    Variable    | X'0D0A' | Variable |
+-----------------------+---------+----------------+---------+----------+

where Trojan Request is a SOCKS5-like request:

+-----+------+----------+----------+
| CMD | ATYP | DST.ADDR | DST.PORT |
+-----+------+----------+----------+
|  1  |  1   | Variable |    2     |
+-----+------+----------+----------+

where:

    o  CMD
        o  CONNECT X'01'
        o  UDP ASSOCIATE X'03'
    o  ATYP address type of following address
        o  IP V4 address: X'01'
        o  DOMAINNAME: X'03'
        o  IP V6 address: X'04'
    o  DST.ADDR desired destination address
    o  DST.PORT desired destination port in network octet order
```

More information on `SOCKS5` requests can be found [here](https://tools.ietf.org/html/rfc1928).

If the connection is a `UDP ASSOCIATE`, then each `UDP` packet has the following format:

```
+------+----------+----------+--------+---------+----------+
| ATYP | DST.ADDR | DST.PORT | Length |  CRLF   | Payload  |
+------+----------+----------+--------+---------+----------+
|  1   | Variable |    2     |   2    | X'0D0A' | Variable |
+------+----------+----------+--------+---------+----------+
```

When the server receives the first data packet, it checks if the hashed password is correct and the Trojan Request is valid. If not, the protocol is considered "other protocols" (see next section). Note that the first packet will have payload appended. This avoids length pattern detection and may reduce the number of packets to be sent.

If the request is valid, the trojan server connects to the endpoint indicated by the `DST.ADDR` and `DST.PORT` field and opens a direct tunnel between the endpoint and trojan client.

(Trojan client is simply a Trojan Protocol-`SOCKS5` converter. There is no detail worth illustrating.)

## Other Protocols

Because typically a trojan server is to be assumed to be an `HTTPS` server, the listening socket is always a `TLS` socket. After performing `TLS` handshake, if the trojan server decides that the traffic is "other protocols", it opens a tunnel between a preset endpoint (by default it is `127.0.0.1:80`, the local `HTTP` server) to the client so the preset endpoint takes the control of the decrypted `TLS` traffic.

## Anti-detection

### Active Detection

All connection without correct structure and password will be redirected to a preset endpoint, so the trojan server behaves exactly the same as that endpoint (by default `HTTP`) if a suspicious probe connects (or just a fan of you connecting to your blog XD).

### Passive Detection

Because the traffic is protected by `TLS` (it is users' responsibility to use a valid certificate), if you are visiting an `HTTP` site, the traffic looks the same as `HTTPS` (there is only one `RTT` after `TLS` handshake); if you are not visiting an `HTTP` site, then the traffic looks the same as `HTTPS` kept alive or `WebSocket`. Because of this, trojan can also bypass ISP `QoS` limitations.

For more information, go to [Issue #14](https://github.com/trojan-gfw/trojan/issues/14).

[Homepage](.) | [Prev Page](overview) | [Next Page](config)
