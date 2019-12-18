/*
 * This file is part of the trojan project.
 * Trojan is an unidentifiable mechanism that helps you bypass GFW.
 * Copyright (C) 2017-2019  GreaterFire
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

#ifndef _SERVICE_H_
#define _SERVICE_H_

#include <list>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/ip/udp.hpp>
#include "authenticator.h"
#include "session/udpforwardsession.h"
#include "session/session.h"
#include<deque>

using io_context_ptr =  std::shared_ptr<boost::asio::io_context>;
using io_context_deque = std::deque<io_context_ptr>;
class Service {
private:
    enum {
        MAX_LENGTH = 8192
    };
    io_context_deque io_contexts_;
    boost::asio::io_context& io_context;
    const Config &config;
    boost::asio::ip::tcp::acceptor socket_acceptor;
    boost::asio::ssl::context ssl_context;
    Authenticator *auth;
    std::string plain_http_response;
    boost::asio::ip::udp::socket udp_socket;
    std::list<std::weak_ptr<UDPForwardSession> > udp_sessions;
    uint8_t udp_read_buf[MAX_LENGTH];
    boost::asio::ip::udp::endpoint udp_recv_endpoint;
    void async_accept();
    void udp_async_read();
public:
    Service(const io_context_deque& iocontexts, Config &config, bool test = false);
    void run();
    void stop();
    boost::asio::io_context &service();
    void reload_cert();
    ~Service();
};

#endif // _SERVICE_H_
