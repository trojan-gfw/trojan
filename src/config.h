#ifndef _CONFIG_H_
#define _CONFIG_H_

#include <string>
#include <cstdint>

class Config {
private:
    static std::string SHA224(const std::string &message);
public:
    enum RunType {
        SERVER,
        CLIENT
    } run_type;
    std::string local_addr;
    uint16_t local_port;
    std::string remote_addr;
    uint16_t remote_port;
    std::string password;
    std::string keyfile;
    std::string keyfile_password;
    std::string certfile;
    bool ssl_verify;
    std::string ca_certs;
    Config();
    void load(const std::string &filename);
};

#endif // _CONFIG_H_
