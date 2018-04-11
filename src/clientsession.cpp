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

#include "clientsession.h"
#include <string>
#include <memory>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include "socks5address.h"
#include "trojanrequest.h"
#include "udpheader.h"
#include "log.h"
using namespace std;
using namespace boost::asio::ip;
using namespace boost::asio::ssl;

SSL_SESSION *ClientSession::ssl_session(NULL);

ClientSession::ClientSession(const Config &config, boost::asio::io_service &io_service, context &ssl_context) :
    Session(config, io_service),
    in_socket(io_service),
    out_socket(io_service, ssl_context),
    status(HANDSHAKE) {}

tcp::socket& ClientSession::accept_socket() {
    return in_socket;
}

void ClientSession::start() {
    in_endpoint = in_socket.remote_endpoint();
    auto ssl = out_socket.native_handle();
    if (config.ssl.sni != "") {
        SSL_set_tlsext_host_name(ssl, config.ssl.sni.c_str());
    }
    if (config.ssl.reuse_session && ssl_session) {
        SSL_set_session(ssl, ssl_session);
    }
    in_async_read();
}

void ClientSession::in_async_read() {
    auto self = shared_from_this();
    in_socket.async_read_some(boost::asio::buffer(in_read_buf, MAX_LENGTH), [this, self](const boost::system::error_code error, size_t length) {
        if (error && error != boost::asio::error::operation_aborted) {
            destroy();
            return;
        }
        in_recv(string((const char*)in_read_buf, length));
    });
}

void ClientSession::in_async_write(const string &data) {
    auto self = shared_from_this();
    boost::asio::async_write(in_socket, boost::asio::buffer(data), [this, self](const boost::system::error_code error, size_t) {
        if (error) {
            destroy();
            return;
        }
        in_sent();
    });
}

void ClientSession::out_async_read() {
    auto self = shared_from_this();
    out_socket.async_read_some(boost::asio::buffer(out_read_buf, MAX_LENGTH), [this, self](const boost::system::error_code error, size_t length) {
        if (error) {
            destroy();
            return;
        }
        out_recv(string((const char*)out_read_buf, length));
    });
}

void ClientSession::out_async_write(const string &data) {
    auto self = shared_from_this();
    boost::asio::async_write(out_socket, boost::asio::buffer(data), [this, self](const boost::system::error_code error, size_t) {
        if (error) {
            destroy();
            return;
        }
        out_sent();
    });
}

void ClientSession::udp_async_read() {
    auto self = shared_from_this();
    udp_socket.async_receive_from(boost::asio::buffer(udp_read_buf, MAX_LENGTH), recv_endpoint, [this, self](const boost::system::error_code error, size_t length) {
        if (error && error != boost::asio::error::operation_aborted) {
            destroy();
            return;
        }
        udp_recv(string((const char*)udp_read_buf, length), recv_endpoint);
    });
}

void ClientSession::udp_async_write(const string &data, const udp::endpoint &endpoint) {
    auto self = shared_from_this();
    udp_socket.async_send_to(boost::asio::buffer(data), endpoint, [this, self](const boost::system::error_code error, size_t) {
        if (error) {
            destroy();
            return;
        }
        udp_sent();
    });
}

void ClientSession::in_recv(const string &data) {
    switch (status) {
        case HANDSHAKE: {
            break;
        }
        case REQUEST: {
            break;
        }
        case CONNECT: {
            break;
        }
        case FORWARD: {
            break;
        }
        case UDP_FORWARD: {
            break;
        }
        case INVALID: {
            break;
        }
        case DESTROY: {
            break;
        }
    }
}

void ClientSession::in_sent() {
    switch (status) {
        case HANDSHAKE: {
            break;
        }
        case REQUEST: {
            break;
        }
        case CONNECT: {
            break;
        }
        case FORWARD: {
            break;
        }
        case UDP_FORWARD: {
            break;
        }
        case INVALID: {
            break;
        }
        case DESTROY: {
            break;
        }
    }
}

void ClientSession::out_recv(const string &data) {
    switch (status) {
        case HANDSHAKE: {
            break;
        }
        case REQUEST: {
            break;
        }
        case CONNECT: {
            break;
        }
        case FORWARD: {
            break;
        }
        case UDP_FORWARD: {
            break;
        }
        case INVALID: {
            break;
        }
        case DESTROY: {
            break;
        }
    }
}

void ClientSession::out_sent() {
    switch (status) {
        case HANDSHAKE: {
            break;
        }
        case REQUEST: {
            break;
        }
        case CONNECT: {
            break;
        }
        case FORWARD: {
            break;
        }
        case UDP_FORWARD: {
            break;
        }
        case INVALID: {
            break;
        }
        case DESTROY: {
            break;
        }
    }
}

void ClientSession::udp_recv(const string &data, const udp::endpoint &endpoint) {
    switch (status) {
        case HANDSHAKE: {
            break;
        }
        case REQUEST: {
            break;
        }
        case CONNECT: {
            break;
        }
        case FORWARD: {
            break;
        }
        case UDP_FORWARD: {
            break;
        }
        case INVALID: {
            break;
        }
        case DESTROY: {
            break;
        }
    }
}

void ClientSession::udp_sent() {
    switch (status) {
        case HANDSHAKE: {
            break;
        }
        case REQUEST: {
            break;
        }
        case CONNECT: {
            break;
        }
        case FORWARD: {
            break;
        }
        case UDP_FORWARD: {
            break;
        }
        case INVALID: {
            break;
        }
        case DESTROY: {
            break;
        }
    }
}

void ClientSession::destroy() {
    if (status == DESTROY) {
        return;
    }
    status = DESTROY;
    resolver.cancel();
    in_socket.close();
    udp_socket.close();
    auto self = shared_from_this();
    out_socket.async_shutdown([this, self](const boost::system::error_code){});
}
