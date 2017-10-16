#include "config.h"
#include <string>
#include <cstdint>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <openssl/sha.h>
#include "log.h"
using namespace std;
using namespace boost::property_tree;

Config::Config() : run_type(CLIENT),
                   local_addr("127.0.0.1"),
                   local_port(1080),
                   remote_addr("example.com"),
                   remote_port(443),
                   password("password"),
                   ca_certs(),
                   keyfile(),
                   certfile() {}

void Config::load(const string &filename) {
    ptree tree;
    read_json(filename, tree);
    run_type = (tree.get("run_type", string("client")) == "server") ? SERVER : CLIENT;
    local_addr = tree.get("local_addr", string("127.0.0.1"));
    local_port = tree.get("local_port", uint16_t(1080));
    remote_addr = tree.get("remote_addr", string("example.com"));
    remote_port = tree.get("remote_port", uint16_t(443));
    password = tree.get("password", string("password"));
    password = Config::SHA224(password);
    ca_certs = tree.get("ca_certs", string());
    keyfile = tree.get("keyfile", string());
    certfile = tree.get("certfile", string());
}

string Config::SHA224(const string &message) {
    uint8_t digest[SHA224_DIGEST_LENGTH];
    SHA256_CTX ctx;
    SHA224_Init(&ctx);
    SHA224_Update(&ctx, message.c_str(), message.length());
    SHA224_Final(digest, &ctx);
    char mdString[(SHA224_DIGEST_LENGTH << 1) + 1];
    for (int i = 0; i < SHA224_DIGEST_LENGTH; ++i) {
        sprintf(mdString + (i << 1), "%02x", (unsigned int)digest[i]);
    }
    return string(mdString);
}
