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

#include "serversession.h"
#include "trojanrequest.h"
#include "udpheader.h"
using namespace std;
using namespace boost::asio::ip;
using namespace boost::asio::ssl;

ServerSession::ServerSession(const Config &config, boost::asio::io_service &io_service, context &ssl_context) :
    Session(config, io_service),
    in_socket(io_service, ssl_context),
    out_socket(io_service),
    status(HANDSHAKE),
    udp_resolver(io_service) {}

tcp::socket& ServerSession::accept_socket() {
    return (tcp::socket&)in_socket.lowest_layer();
}

void ServerSession::start() {
    in_endpoint = in_socket.lowest_layer().remote_endpoint();
    auto self = shared_from_this();
    in_socket.async_handshake(stream_base::server, [this, self](const boost::system::error_code error) {
        if (error) {
            destroy();
            return;
        }
        in_async_read();
    });
}

void ServerSession::in_async_read() {
    auto self = shared_from_this();
    in_socket.async_read_some(boost::asio::buffer(in_read_buf, MAX_LENGTH), [this, self](const boost::system::error_code error, size_t length) {
        if (error) {
            destroy();
            return;
        }
        in_recv(string((const char*)in_read_buf, length));
    });
}

void ServerSession::in_async_write(const string &data) {
    auto self = shared_from_this();
    boost::asio::async_write(in_socket, boost::asio::buffer(data), [this, self](const boost::system::error_code error, size_t) {
        if (error) {
            destroy();
            return;
        }
        in_sent();
    });
}

void ServerSession::out_async_read() {
    auto self = shared_from_this();
    out_socket.async_read_some(boost::asio::buffer(out_read_buf, MAX_LENGTH), [this, self](const boost::system::error_code error, size_t length) {
        if (error) {
            destroy();
            return;
        }
        out_recv(string((const char*)out_read_buf, length));
    });
}

void ServerSession::out_async_write(const string &data) {
    auto self = shared_from_this();
    boost::asio::async_write(out_socket, boost::asio::buffer(data), [this, self](const boost::system::error_code error, size_t) {
        if (error) {
            destroy();
            return;
        }
        out_sent();
    });
}

void ServerSession::udp_async_read() {
    auto self = shared_from_this();
    udp_socket.async_receive_from(boost::asio::buffer(udp_read_buf, MAX_LENGTH), udp_recv_endpoint, [this, self](const boost::system::error_code error, size_t length) {
        if (error) {
            destroy();
            return;
        }
        udp_recv(string((const char*)udp_read_buf, length), udp_recv_endpoint);
    });
}

void ServerSession::udp_async_write(const string &data, const udp::endpoint &endpoint) {
    auto self = shared_from_this();
    udp_socket.async_send_to(boost::asio::buffer(data), endpoint, [this, self](const boost::system::error_code error, size_t) {
        if (error) {
            destroy();
            return;
        }
        udp_sent();
    });
}

void ServerSession::in_recv(const string &data) {
    switch (status) {
        case HANDSHAKE: {
            break;
        }
        case FORWARD: {
            out_async_write(data);
            break;
        }
        case UDP_FORWARD: {
            // TODO
            break;
        }
        default: break;
    }
}

void ServerSession::in_sent() {
    switch (status) {
        case FORWARD: {
            out_async_read();
            break;
        }
        case UDP_FORWARD: {
            udp_async_read();
            break;
        }
        default: break;
    }
}

void ServerSession::out_recv(const string &data) {
    switch (status) {
        case FORWARD: {
            in_async_write(data);
            break;
        }
        default: break;
    }
}

void ServerSession::out_sent() {
    switch (status) {
        case FORWARD: {
            in_async_read();
            break;
        }
        default: break;
    }
}

void ServerSession::udp_recv(const string &data, const udp::endpoint &endpoint) {
    switch (status) {
        case UDP_FORWARD: {
            // TODO
            break;
        }
        default: break;
    }
}

void ServerSession::udp_sent() {
    switch (status) {
        case UDP_FORWARD: {
            // TODO
            break;
        }
        default: break;
    }
}

void ServerSession::destroy() {
    if (status == DESTROY) {
        return;
    }
    status = DESTROY;
    resolver.cancel();
    out_socket.close();
    udp_socket.close();
    auto self = shared_from_this();
    in_socket.async_shutdown([this, self](const boost::system::error_code){});
}
