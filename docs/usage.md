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

The default value for CONFIG is where the default config is installed in Linux and `config.json` in Windows. Trojan will not terminate if you leave it in the background.

Make sure your [config file](config) is valid. Configuring trojan is not trivial: there are several ideas you need to understand and several pitfalls you might fall into. Unless you are an expert, you shouldn't configure a trojan server all by yourself.

Here, we will present a list of things you should do before you start a trojan server:

- setup an `HTTP` server and make it useful in some sense (to deceive `GFW`).
- register a domain name for your server.
- Apply for or self-sign (**NOT RECOMMENDED**) an `SSL` certificate.
- Correctly write the [config file](config).

[Shadowsocks SIP003](https://shadowsocks.org/en/spec/Plugin.html) is supported by trojan, but it is added as an experimental feature and is not standard at all, so it will not be documented here.

[Homepage](.) | [Prev Page](build)
