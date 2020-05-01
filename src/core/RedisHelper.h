//
// Created by this on 5/1/20.
//

#ifndef TROJAN_REDISHELPER_H
#define TROJAN_REDISHELPER_H

#include <hiredis.h>
#include <string>
#include <stdexcept>
#include "log.h"

class RedisHelper {
private:
    redisContext* client;
public:
    RedisHelper(const std::string& server_addr, uint16_t server_port);
    bool exists(const std::string& key);
    bool increaseValue(const std::string& key, const std::string& subkey, uint64_t val);
    bool ping();
    ~RedisHelper();
};


#endif //TROJAN_REDISHELPER_H
