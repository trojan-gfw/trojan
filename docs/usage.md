# How to Use Trojan

There are two ways to start trojan. The first is to type in

```bash
trojan config_file 2> log
```

in your console, and the second is to double click the icon (if you are using `GUI`); trojan will prompt to ask for the path of your config file. In some operating systems you can also drag your config file to the executable to open.

Make sure your [config file](config) is valid. Configure trojan is not trivial: there are several ideas you need to understand and several pitfalls you might fall into. Unless you are an expert, you shouldn't configure a trojan server all by yourself.

Here, I will present a list of things you should do before you start trojan server:

- setup an `HTTP` server and make it useful in some sense (to deceive `GFW`)
- Apply for or self-sign (**NOT RECOMMENDED**) an `SSL` certificate.
- Correctly write the [config file](config).

[Homepage](.) | [Prev Page](build)
