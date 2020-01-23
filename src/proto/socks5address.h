/*
 * This file is part of the trojan project.
 * Trojan is an unidentifiable mechanism that helps you bypass GFW.
 * Copyright (C) 2017-2020  The Trojan Authors.
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

#ifndef _SOCKS5ADDRESS_H_
#define _SOCKS5ADDRESS_H_

#include <cstdint>
#include <string>
#include <boost/asio/ip/udp.hpp>

class SOCKS5Address {
public:
    enum AddressType {
        IPv4 = 1,
        DOMAINNAME = 3,
        IPv6 = 4
    } address_type;
    std::string address;
    uint16_t port;
    bool parse(const std::string &data, size_t &address_len);
    static std::string generate(const boost::asio::ip::udp::endpoint &endpoint);
};

#endif // _SOCKS5ADDRESS_H_
