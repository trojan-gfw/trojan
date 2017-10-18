#ifndef _TROJANREQUEST_H_
#define _TROJANREQUEST_H_

#include <cstdint>
#include <string>

class TrojanRequest {
public:
    enum Command {
        CONNECT = 1,
        UDP_ASSOCIATE = 3
    } command;
    enum AddressType {
        IPv4 = 1,
        DOMAINNAME = 3,
        IPv6 = 4
    } address_type;
    std::string address;
    uint16_t port;
    TrojanRequest();
    bool parse(const std::string &data);
};

#endif // _TROJANREQUEST_H_
