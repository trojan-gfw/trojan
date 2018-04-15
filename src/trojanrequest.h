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

#ifndef _TROJANREQUEST_H_
#define _TROJANREQUEST_H_

#include "socks5address.h"
#include <map>

class TrojanRequest {
public:
    std::string password;
    enum Command {
        CONNECT = 1,
        UDP_ASSOCIATE = 3
    } command;
    SOCKS5Address address;
    std::string payload;
    int parse(const std::string &data, const std::map<std::string, std::string> &valid_passwords);
};

#endif // _TROJANREQUEST_H_
