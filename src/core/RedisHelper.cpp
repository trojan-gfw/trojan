//
// Created by this on 5/1/20.
//

#include "RedisHelper.h"

inline bool isRedisErrorNil(redisReply* r) {
    if(nullptr == r) {
        return true;
    } else if (r->type == REDIS_REPLY_ERROR || r->type == REDIS_REPLY_NIL) {
        freeReplyObject(r);
        return true;
    } else {
        return false;
    }
}

RedisHelper::RedisHelper(const std::string& server_addr, uint16_t server_port) {
    Log::log("[Redis] Connection created");
    client = redisConnect(server_addr.c_str(), server_port);
    if(client == nullptr || client->err) {
        if(client) {
            redisFree(client);
        }
        throw std::runtime_error("[Redis] Cannot connect to server.");
    }
}

bool RedisHelper::exists(const std::string& key) {
    auto* r = static_cast<redisReply *>(redisCommand(client, "EXISTS %s", key.c_str()));
    if (isRedisErrorNil(r)) {
        return false;
    } else {
        freeReplyObject(r);
        return true;
    }
}

bool RedisHelper::increaseValue(const std::string& key, const std::string& subkey, uint64_t val) {
    if(isRedisErrorNil(static_cast<redisReply *>(redisCommand(client, "EXISTS %s", key.c_str())))) {
        return false;
    }
    auto* r = static_cast<redisReply *>(redisCommand(client, "HINCRBY %s %s %lld", key.c_str(), subkey.c_str(), val));
    if (isRedisErrorNil(r)) {
        return false;
    } else {
        freeReplyObject(r);
        return true;
    }
}

RedisHelper::~RedisHelper() {
    redisFree(client);
}

bool RedisHelper::ping() {
    auto* r = static_cast<redisReply *>(redisCommand(client, "PING"));
    if (isRedisErrorNil(r)) {
        return false;
    } else {
        freeReplyObject(r);
        return true;
    }
}
