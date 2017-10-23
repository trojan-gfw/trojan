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
    in_endpoint = in_socket.lowest_layer().remote_endpoint();
    auto self = shared_from_this();
    in_socket.async_handshake(boost::asio::ssl::stream_base::server, [this, self](const boost::system::error_code error) {
        if (!error) {
            in_async_read();
        } else {
            Log::log_with_endpoint(in_endpoint, "SSL handshake failed");
            destroy();
        }
    });
}

void ServerSession::in_async_read() {
    auto self = shared_from_this();
    in_socket.async_read_some(boost::asio::buffer(in_read_buf, MAX_LENGTH), [this, self](const boost::system::error_code error, size_t length) {
        if (!error) {
            in_recv(string((const char*)in_read_buf, length));
            in_async_read();
        } else {
            if (out_write_queue.empty()) {
                destroy();
            } else {
                closing = true;
            }
        }
    });
}

void ServerSession::in_async_write() {
    auto self = shared_from_this();
    boost::asio::async_write(in_socket, boost::asio::buffer(in_write_queue.front()), [this, self](boost::system::error_code error, std::size_t) {
        if (!error) {
            in_write_queue.pop();
            if (in_write_queue.size() > 0) {
                in_async_write();
            } else if (closing) {
                destroy();
            }
        } else {
            destroy();
        }
    });
}

void ServerSession::in_recv(const string &data) {
    auto self = shared_from_this();
    switch (status) {
        case HANDSHAKE: {
            size_t first = data.find("\r\n");
            if (first != string::npos) {
                if (config.password == data.substr(0, first)) {
                    size_t second = data.find("\r\n", first + 2);
                    if (second != string::npos) {
                        string req_str = data.substr(first + 2, second - first - 2);
                        TrojanRequest req;
                        if (!req.parse(req_str)) {
                            Log::log_with_endpoint(in_endpoint, "bad request");
                            destroy();
                            return;
                        };
                        Log::log_with_endpoint(in_endpoint, "requested connection to " + req.address + ':' + to_string(req.port));
                        out_write_queue.push(data.substr(second + 2));
                        status = CONNECTING_REMOTE;
                        tcp::resolver::query query(req.address, to_string(req.port));
                        resolver.async_resolve(query, [this, self](const boost::system::error_code error, tcp::resolver::iterator iterator) {
                            if (!error) {
                                out_socket.async_connect(*iterator, [this, self](const boost::system::error_code error) {
                                    if (!error) {
                                        Log::log_with_endpoint(in_endpoint, "tunnel established");
                                        status = FORWARD;
                                        out_async_read();
                                        out_async_write();
                                    } else {
                                        Log::log_with_endpoint(in_endpoint, "cannot establish connection to remote server");
                                        destroy();
                                    }
                                });
                            } else {
                                Log::log_with_endpoint(in_endpoint, "cannot resolve remote server hostname");
                                destroy();
                            }
                        });
                        return;
                    }
                }
            }
            Log::log_with_endpoint(in_endpoint, "not trojan request, connecting to " + config.remote_addr + ':' + to_string(config.remote_port));
            out_write_queue.push(data);
            status = CONNECTING_REMOTE;
            tcp::resolver::query query(config.remote_addr, to_string(config.remote_port));
            resolver.async_resolve(query, [this, self](const boost::system::error_code error, tcp::resolver::iterator iterator) {
                if (!error) {
                    out_socket.async_connect(*iterator, [this, self](const boost::system::error_code error) {
                        if (!error) {
                            Log::log_with_endpoint(in_endpoint, "tunnel established");
                            status = FORWARD;
                            out_async_read();
                            out_async_write();
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
            break;
        }
        case CONNECTING_REMOTE: {
            out_write_queue.push(data);
            break;
        }
        case FORWARD: {
            out_send(data);
            break;
        }
    }
}

void ServerSession::in_send(const string &data) {
    in_write_queue.push(data);
    if (in_write_queue.size() == 1) {
        in_async_write();
    }
}

void ServerSession::out_async_read() {
    auto self = shared_from_this();
    out_socket.async_read_some(boost::asio::buffer(out_read_buf, MAX_LENGTH), [this, self](const boost::system::error_code error, size_t length) {
        if (!error) {
            out_recv(string((const char*)out_read_buf, length));
            out_async_read();
        } else {
            if (in_write_queue.empty()) {
                destroy();
            } else {
                closing = true;
            }
        }
    });
}

void ServerSession::out_async_write() {
    auto self = shared_from_this();
    boost::asio::async_write(out_socket, boost::asio::buffer(out_write_queue.front()), [this, self](boost::system::error_code error, std::size_t) {
        if (!error) {
            out_write_queue.pop();
            if (out_write_queue.size() > 0) {
                out_async_write();
            } else if (closing) {
                destroy();
            }
        } else {
            destroy();
        }
    });
}

void ServerSession::out_recv(const std::string &data) {
    in_send(data);
}

void ServerSession::out_send(const std::string &data) {
    out_write_queue.push(data);
    if (out_write_queue.size() == 1) {
        out_async_write();
    }
}

void ServerSession::destroy() {
    if (destroying) {
        return;
    }
    destroying = true;
    Log::log_with_endpoint(in_endpoint, "disconnected");
    resolver.cancel();
    out_socket.close();
    auto self = shared_from_this();
    in_socket.async_shutdown([this, self](boost::system::error_code error) {});
}
