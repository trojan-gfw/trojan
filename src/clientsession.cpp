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

#include "clientsession.h"
#include <string>
#include <memory>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include "trojanrequest.h"
#include "log.h"
using namespace std;
using namespace boost::asio::ip;
using namespace boost::asio::ssl;

ClientSession::ClientSession(const Config &config, boost::asio::io_service &io_service, context &ssl_context) :
    Session(config, io_service),
    in_socket(io_service),
    out_socket(io_service, ssl_context),
    status(HANDSHAKE) {}

boost::asio::basic_socket<tcp, boost::asio::stream_socket_service<tcp> >& ClientSession::accept_socket() {
    return in_socket;
}

void ClientSession::start() {
    in_endpoint = in_socket.remote_endpoint();
    if (config.ssl_verify_hostname) {
        auto ssl = out_socket.native_handle();
        SSL_set_tlsext_host_name(ssl, config.remote_addr.c_str());
    }
    in_async_read();
}

void ClientSession::in_async_read() {
    auto self = shared_from_this();
    in_socket.async_read_some(boost::asio::buffer(in_read_buf, MAX_LENGTH), [this, self](const boost::system::error_code error, size_t length) {
        if (!error) {
            in_recv(string((const char*)in_read_buf, length));
        } else if (error != boost::asio::error::operation_aborted) {
            destroy();
        }
    });
}

void ClientSession::in_async_write(const string &data) {
    auto self = shared_from_this();
    boost::asio::async_write(in_socket, boost::asio::buffer(data), [this, self](const boost::system::error_code error, size_t) {
        if (!error) {
            in_sent();
        } else {
            destroy();
        }
    });
}

void ClientSession::in_recv(const string &data) {
    switch (status) {
        case HANDSHAKE: {
            if (data.length() < 2 || data[0] != 5) {
                Log::log_with_endpoint(in_endpoint, "unknown protocol");
                destroy();
                return;
            }
            bool ok = false;
            for (int i = 2; i < 2 + data[1] && i < data.length(); ++i) {
                if (data[i] == 0) {
                    ok = true;
                    break;
                }
            }
            if (!ok) {
                Log::log_with_endpoint(in_endpoint, "unsupported auth method");
                status = INVALID;
                in_async_write(string("\x05\xff", 2));
                return;
            }
            in_async_write(string("\x05\x00", 2));
            break;
        }
        case REQUEST: {
            if (data.length() >= 3 && data[0] == 5 && data[2] == 0) {
                string req_str = data[1] + data.substr(3);
                TrojanRequest req;
                if (req.parse(req_str)) {
                    Log::log_with_endpoint(in_endpoint, "requested connection to " + req.address + ':' + to_string(req.port));
                    status = CONNECTING_REMOTE;
                    in_async_write(string("\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00", 10));
                    out_write_buf = config.password + "\r\n" + req_str + "\r\n";
                    tcp::resolver::query query(config.remote_addr, to_string(config.remote_port));
                    auto self = shared_from_this();
                    resolver.async_resolve(query, [this, self](const boost::system::error_code error, tcp::resolver::iterator iterator) {
                        if (!error) {
                            out_socket.lowest_layer().async_connect(*iterator, [this, self](const boost::system::error_code error) {
                                if (!error) {
                                    out_socket.async_handshake(stream_base::client, [this, self](const boost::system::error_code error) {
                                        if (!error) {
                                            Log::log_with_endpoint(in_endpoint, "tunnel established");
                                            if (status == CONNECTING_REMOTE) {
                                                status = FIRST_PACKET_RECEIVED;
                                                in_socket.cancel();
                                            }
                                            out_async_write(out_write_buf);
                                            out_async_read();
                                        } else {
                                            Log::log_with_endpoint(in_endpoint, "SSL handshake failed with " + config.remote_addr + ':' + to_string(config.remote_port));
                                            destroy();
                                        }
                                    });
                                } else {
                                    Log::log_with_endpoint(in_endpoint, "cannot establish connection to remote server " + config.remote_addr + ':' + to_string(config.remote_port));
                                    destroy();
                                }
                            });
                        } else {
                            Log::log_with_endpoint(in_endpoint, "cannot resolve remote server hostname " + config.remote_addr);
                            destroy();
                        }
                    });
                    return;
                } else {
                    Log::log_with_endpoint(in_endpoint, "bad request");
                }
            } else {
                Log::log_with_endpoint(in_endpoint, "unsupported command");
            }
            status = INVALID;
            in_async_write(string("\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00", 10));
            break;
        }
        case CONNECTING_REMOTE: {
            out_write_buf += data;
            status = FIRST_PACKET_RECEIVED;
            break;
        }
        case FIRST_PACKET_RECEIVED: {
            break;
        }
        case FORWARDING: {
            out_async_write(data);
            break;
        }
        case INVALID: {
            break;
        }
        case DESTROYING: {
            break;
        }
    }
}

void ClientSession::in_sent() {
    switch (status) {
        case HANDSHAKE: {
            status = REQUEST;
            in_async_read();
            break;
        }
        case REQUEST: {
            break;
        }
        case CONNECTING_REMOTE: {
            in_async_read();
            break;
        }
        case FIRST_PACKET_RECEIVED: {
            break;
        }
        case FORWARDING: {
            out_async_read();
            break;
        }
        case INVALID: {
            destroy();
            break;
        }
        case DESTROYING: {
            break;
        }
    }
}

void ClientSession::out_async_read() {
    auto self = shared_from_this();
    out_socket.async_read_some(boost::asio::buffer(out_read_buf, MAX_LENGTH), [this, self](const boost::system::error_code error, size_t length) {
        if (!error) {
            out_recv(string((const char*)out_read_buf, length));
        } else {
            destroy();
        }
    });
}

void ClientSession::out_async_write(const string &data) {
    auto self = shared_from_this();
    boost::asio::async_write(out_socket, boost::asio::buffer(data), [this, self](const boost::system::error_code error, size_t) {
        if (!error) {
            out_sent();
        } else {
            destroy();
        }
    });
}

void ClientSession::out_recv(const string &data) {
    switch (status) {
        case HANDSHAKE: {
            break;
        }
        case REQUEST: {
            break;
        }
        case CONNECTING_REMOTE: {
            break;
        }
        case FIRST_PACKET_RECEIVED: {
            break;
        }
        case FORWARDING: {
            in_async_write(data);
            break;
        }
        case INVALID: {
            break;
        }
        case DESTROYING: {
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
        case CONNECTING_REMOTE: {
            break;
        }
        case FIRST_PACKET_RECEIVED: {
            status = FORWARDING;
            in_async_read();
            break;
        }
        case FORWARDING: {
            in_async_read();
            break;
        }
        case INVALID: {
            break;
        }
        case DESTROYING: {
            break;
        }
    }
}

void ClientSession::destroy() {
    if (status == DESTROYING) {
        return;
    }
    Log::log_with_endpoint(in_endpoint, "disconnected");
    status = DESTROYING;
    resolver.cancel();
    in_socket.close();
    auto self = shared_from_this();
    out_socket.async_shutdown([this, self](const boost::system::error_code){});
}
