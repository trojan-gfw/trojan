# Usage

```
usage: ./trojan [-htv] [-l LOG] [-k KEYLOG] [[-c] CONFIG]
options:
  -c [ --config ] CONFIG specify config file
  -h [ --help ]          print help message
  -k [ --keylog ] KEYLOG specify keylog file location (OpenSSL >= 1.1.1)
  -l [ --log ] LOG       specify log file location
  -t [ --test ]          test config file
  -v [ --version ]       print version and build info
```

The default value for CONFIG is where the default config is installed on Linux and other UNIX-like systems and `config.json` on Windows.

On Linux and other UNIX-like systems, the behavior of the handlers for the following signals are overridden:

- `SIGHUP`: Upon receiving `SIGHUP`, trojan will stop the service, reload the config, and restart the service. All existing connections are dropped. As a side effect, if trojan is left in the background of a shell, it will not exit when the shell exits.
- `SIGUSR1`: Upon receiving `SIGUSR1`, trojan will reload the certificate and private key of the `SSL` server. No existing connections are dropped, and the new certificate doesn't affect these connections.

Make sure your [config file](config) is valid. Configuring trojan is not trivial: there are several ideas you need to understand and several pitfalls you might fall into. Unless you are an expert, you shouldn't configure a trojan server all by yourself.

Here, we will present a list of things you should do before you start a trojan server:

- setup an `HTTP` server and make it useful in some sense (to deceive `GFW`).
- register a domain name for your server.
- Apply for or self-sign (**NOT RECOMMENDED**) an `SSL` certificate.
- Correctly write the [config file](config).

[Shadowsocks SIP003](https://shadowsocks.org/en/spec/Plugin.html) is supported by trojan, but it is added as an experimental feature and is not standard at all, so it will not be documented here.

[Homepage](.) | [Prev Page](build)
