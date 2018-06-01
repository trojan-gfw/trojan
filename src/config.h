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

#ifndef _CONFIG_H_
#define _CONFIG_H_

#include <cstdint>
#include <map>
#include "log.h"

class Config {
public:
    enum RunType {
        SERVER,
        CLIENT
    } run_type;
    std::string local_addr;
    uint16_t local_port;
    std::string remote_addr;
    uint16_t remote_port;
    std::map<std::string, std::string> password;
    bool append_payload;
    Log::Level log_level;
    class SSLConfig {
    public:
        bool verify;
        bool verify_hostname;
        std::string cert;
        std::string key;
        std::string key_password;
        std::string cipher;
        bool prefer_server_cipher;
        std::string sni;
        std::string alpn;
        bool reuse_session;
        long session_timeout;
        std::string curves;
        std::string sigalgs;
        std::string dhparam;
    } ssl;
    class TCPConfig {
    public:
        bool keep_alive;
        bool no_delay;
        bool fast_open;
        int fast_open_qlen;
    } tcp;
    void load(const std::string &filename);
    static std::string SHA224(const std::string &message);
};

#endif // _CONFIG_H_
