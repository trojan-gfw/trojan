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

#include "serversession.h"
#include <string>
#include <memory>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include "trojanrequest.h"
#include "log.h"
using namespace std;
using namespace boost::asio::ip;
using namespace boost::asio::ssl;

ServerSession::ServerSession(const Config &config, boost::asio::io_service &io_service, context &ssl_context) :
    Session(config, io_service),
    in_socket(io_service, ssl_context),
    out_socket(io_service),
    status(HANDSHAKE) {}

boost::asio::basic_socket<tcp, boost::asio::stream_socket_service<tcp> >& ServerSession::accept_socket() {
    return in_socket.lowest_layer();
}

void ServerSession::start() {

}

void ServerSession::in_async_read() {

}

void ServerSession::in_async_write(const string &data) {

}

void ServerSession::in_recv(const string &data) {

}

void ServerSession::in_sent() {

}

void ServerSession::out_async_read() {

}

void ServerSession::out_async_write(const string &data) {

}

void ServerSession::out_recv(const string &data) {

}

void ServerSession::out_sent() {

}

void ServerSession::destroy() {

}
