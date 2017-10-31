/*
 * This file is part of the trojan project.
 * Trojan is an unidentifiable mechanism that helps you bypass GFW.
 * Copyright (C) 2017  GreaterFire
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

#include <string>
#include <cstdint>
#include "log.h"

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
    bool ssl_verify_hostname;
    std::string ca_certs;
    Log::Level log_level;
    void load(const std::string &filename);
};

#endif // _CONFIG_H_
