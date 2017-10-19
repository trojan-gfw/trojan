/*
 * This file is part of the trojan project.
 * Trojan is an unidentifiable mechanism to bypass GFW.
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

#ifndef _SESSION_H_
#define _SESSION_H_

#include <cstdint>
#include <queue>
#include <boost/asio.hpp>

class Config;

class Session {
protected:
    enum {
        MAX_LENGTH = 8192
    };
    const Config &config;
    uint8_t in_read_buf[MAX_LENGTH];
    std::queue<std::string>in_write_queue;
    uint8_t out_read_buf[MAX_LENGTH];
    std::queue<std::string>out_write_queue;
    bool closing, destroying;
    boost::asio::ip::tcp::resolver resolver;
    boost::asio::ip::tcp::endpoint in_endpoint;
public:
    Session(const Config &config, boost::asio::io_service &io_service);
    virtual boost::asio::basic_socket<boost::asio::ip::tcp, boost::asio::stream_socket_service<boost::asio::ip::tcp> >& accept_socket() = 0;
    virtual void start() = 0;
};

#include "config.h"

#endif // _SESSION_H_
