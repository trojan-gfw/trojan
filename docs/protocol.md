# The Trojan Protocol

We will now show how a trojan server will react to a **valid trojan protocol**, and **other protocols** (possibly **HTTPS** or any other probes).

## Valid Trojan Protocol

Basically, when a trojan client connects to a trojan server, they perform **real** TLS handshake first. If handshake succeeds, all subsequent traffic will be protected by TLS; otherwise, the server closes the connection immediately like any HTTPS servers would do when handshake fails. Afterwards, the trojan client sends the following structure:

```
+-----------------------+---------+----------------+---------+----------+
| hex(ssh224(password)) |  CRLF   | Trojan Request |  CRLF   | Payload  |
+-----------------------+---------+----------------+---------+----------+
|          56           | X'0D0A' |    Variable    | X'0D0A' | Variable |
+-----------------------+---------+----------------+---------+----------+

in which Trojan Request is a SOCKS5-like request:

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

More information about SOCKS5 requests can be found [here](https://tools.ietf.org/html/rfc1928).

**Note that UDP ASSOCIATE is not implemented in current version of trojan. The CMD field is reserved for future implementation if demanded.**

When the server receives the first data packet, it looks for the two CRLFs; then, it extracts the hashed password and Trojan Request to check the validity (password is correct and Trojan Request is well-formed). If any steps of the procedure fail, the protocol is considered "other protocols" which will be explained in the next section. Note that in the first packet, there is already payload appended to avoid length pattern detection and to reduce number of packets to be sent.

If the request is valid, the trojan server connects to the endpoint indicated by the DST.ADDR and DST.PORT field and opens a direct tunnel between the endpoint and trojan client.

(Trojan client is simply a SOCKS5-Trojan Protocol converter. There is no detail worth illustrating.)

## Other Protocols

Because typically a trojan server is to be assumed to be an HTTPS server, the listening socket is always a TLS socket. After performing TLS handshake, if the trojan server decides that the traffic is "other protocols", it opens a tunnel between a preset endpoint (by default it is 127.0.0.1:80, the local HTTP server) to the client so the preset endpoint takes the control of the decrypted TLS traffic.

## Anti-detection

### Active Detection

All connection without correct structure and password will be redirected to a preset endpoint, so the trojan server behaves exactly the same as that endpoint (by default HTTP) if a suspicious probe connects (or just a fan of you connecting to your blog XD).

### Passive Detection

Because the traffic is protected by TLS (it is the users' responsible to use a valid certificate) and if you are visiting an HTTP site, the traffic looks exactly the same as HTTPS (there is only one RTT after TLS handshake). If you are not visiting an HTTP site, then the traffic looks exactly the same as HTTPS kept alive or WebSocket.

[Homepage](.) | [Prev Page](overview) | [Next Page](config)
