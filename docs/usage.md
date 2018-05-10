# Usage

You can run trojan by typing in

```bash
trojan config_file 2> log_file
```

in your console. Trojan will not terminate if you leave it in the background.

Make sure your [config file](config) is valid. Configuring trojan is not trivial: there are several ideas you need to understand and several pitfalls you might fall into. Unless you are an expert, you shouldn't configure a trojan server all by yourself.

Here, we will present a list of things you should do before you start a trojan server:

- setup an `HTTP` server and make it useful in some sense (to deceive `GFW`).
- register a domain name for your server.
- Apply for or self-sign (**NOT RECOMMENDED**) an `SSL` certificate.
- Correctly write the [config file](config).

[Homepage](.) | [Prev Page](build)
