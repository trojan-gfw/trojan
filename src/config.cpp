/*
 * This file is part of the trojan project.
 * Trojan is an unidentifiable mechanism that helps you bypass GFW.
 * Copyright (C) 2018  GreaterFire
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "config.h"
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <openssl/sha.h>
using namespace std;
using namespace boost::property_tree;

void Config::load(const string &filename) {
    ptree tree;
    read_json(filename, tree);
    run_type = (tree.get("run_type", string("client")) == "server") ? SERVER : CLIENT;
    local_addr = tree.get("local_addr", string());
    local_port = tree.get("local_port", uint16_t());
    remote_addr = tree.get("remote_addr", string());
    remote_port = tree.get("remote_port", uint16_t());
    map<string, string>().swap(password);
    for (auto& item: tree.get_child("password")) {
        string p = item.second.get_value<string>();
        password[SHA224(p)] = p;
    }
    append_payload = tree.get("append_payload", true);
    log_level = static_cast<Log::Level>(tree.get("log_level", 1));
    ssl.verify = tree.get("ssl.verify", true);
    ssl.verify_hostname = tree.get("ssl.verify_hostname", true);
    ssl.cert = tree.get("ssl.cert", string());
    ssl.key = tree.get("ssl.key", string());
    ssl.key_password = tree.get("ssl.key_password", string());
    ssl.cipher = tree.get("ssl.cipher", string());
    ssl.prefer_server_cipher = tree.get("ssl.prefer_server_cipher", true);
    ssl.sni = tree.get("ssl.sni", string());
    ssl.alpn = "";
    for (auto& item: tree.get_child("ssl.alpn")) {
        string proto = item.second.get_value<string>();
        ssl.alpn += (char)((unsigned char)(proto.length()));
        ssl.alpn += proto;
    }
    ssl.reuse_session = tree.get("ssl.reuse_session", true);
    ssl.session_timeout = tree.get("ssl.session_timeout", long(300));
    ssl.curves = tree.get("ssl.curves", string());
    ssl.sigalgs = tree.get("ssl.sigalgs", string());
    ssl.dhparam = tree.get("ssl.dhparam", string());
    tcp.keep_alive = tree.get("tcp.keep_alive", true);
    tcp.no_delay = tree.get("tcp.no_delay", true);
    tcp.fast_open = tree.get("tcp.fast_open", true);
    tcp.fast_open_qlen = tree.get("tcp.fast_open_qlen", 5);
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
