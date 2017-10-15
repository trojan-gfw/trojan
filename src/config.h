#ifndef _CONFIG_H_
#define _CONFIG_H_

#include <string>
#include <cstdint>

struct Config {
    enum RunType {
        SERVER,
        CLIENT
    };
    RunType run_type;
    std::string local_addr;
    uint16_t local_port;
    std::string remote_addr;
    uint16_t remote_port;
    std::string password;
    std::string ca_certs;
    std::string keyfile;
    std::string certfile;
    Config();
    bool load(const std::string &filename);
};

#endif // _CONFIG_H_
