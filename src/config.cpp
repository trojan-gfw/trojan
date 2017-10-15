#include "config.h"
#include <string>
#include <cstdint>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include "log.h"
using namespace std;
using namespace boost::property_tree;

Config::Config() : run_type(CLIENT),
                   local_addr("127.0.0.1"),
                   local_port(1080),
                   remote_addr(),
                   remote_port(443),
                   password(),
                   ca_certs(),
                   keyfile(),
                   certfile() {}

bool Config::load(const string &filename) {
    ptree tree;
    try {
        read_json(filename, tree);
    } catch (const std::exception&) {
        return false;
    }
    run_type = (tree.get("run_type", string("client")) == "server") ? SERVER : CLIENT;
    local_addr = tree.get("local_addr", string("127.0.0.1"));
    local_port = tree.get("local_port", uint16_t(1080));
    remote_addr = tree.get("remote_addr", string());
    remote_port = tree.get("remote_port", uint16_t(443));
    password = tree.get("password", string());
    ca_certs = tree.get("ca_certs", string());
    keyfile = tree.get("keyfile", string());
    certfile = tree.get("certfile", string());
    return true;
}
