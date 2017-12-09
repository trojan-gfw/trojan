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

#include "service.h"
#include <cstring>
#include <string>
#include <memory>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include "config.h"
#include "log.h"
#include "session.h"
#include "serversession.h"
#include "clientsession.h"
#include "ssldefaults.h"
using namespace std;
using namespace boost::asio::ip;
using namespace boost::asio::ssl;

Service::Service(const Config &config) :
    config(config),
    socket_acceptor(io_service, tcp::endpoint(address::from_string(config.local_addr), config.local_port)),
    ssl_context(context::sslv23) {
    auto native_context = ssl_context.native_handle();
    ssl_context.set_options(context::default_workarounds | context::no_sslv2 | context::no_sslv3 | context::single_dh_use);
    if (config.run_type == Config::SERVER) {
        ssl_context.use_certificate_chain_file(config.ssl.cert);
        ssl_context.use_private_key_file(config.ssl.key, context::pem);
    } else {
        ssl_context.set_verify_mode(verify_none);
    }
}

int Service::run() {
    async_accept();
    Log::log_with_date_time(string("trojan service (") + (config.run_type == Config::SERVER ? "server" : "client") + ") started at " + config.local_addr + ':' + to_string(config.local_port), Log::FATAL);
    io_service.run();
    return 0;
}

void Service::async_accept() {
    shared_ptr<Session>session(nullptr);
    if (config.run_type == Config::SERVER) {
        session = make_shared<ServerSession>(config, io_service, ssl_context);
    } else {
        session = make_shared<ClientSession>(config, io_service, ssl_context);
    }
    socket_acceptor.async_accept(session->accept_socket(), [this, session](boost::system::error_code error) {
        if (!error) {
            boost::system::error_code ec;
            auto endpoint = session->accept_socket().remote_endpoint(ec);
            if (!ec) {
                Log::log_with_endpoint(endpoint, "incoming connection");
                session->start();
            }
        }
        async_accept();
    });
}
