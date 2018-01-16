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

#ifndef _SESSION_H_
#define _SESSION_H_

#include <cstdint>
#include <string>
#include <memory>
#include <boost/asio.hpp>

class Config;

class Session : public std::enable_shared_from_this<Session> {
protected:
    enum {
        MAX_LENGTH = 8192
    };
    const Config &config;
    uint8_t in_read_buf[MAX_LENGTH];
    uint8_t out_read_buf[MAX_LENGTH];
    std::string out_write_buf;
    boost::asio::ip::tcp::resolver resolver;
    boost::asio::ip::tcp::endpoint in_endpoint;
public:
    Session(const Config &config, boost::asio::io_service &io_service);
    virtual boost::asio::ip::tcp::socket& accept_socket() = 0;
    virtual void start() = 0;
};

#include "config.h"

#endif // _SESSION_H_
