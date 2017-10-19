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

#include "clientsession.h"
#include <string>
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
    in_async_read();
}

void ClientSession::in_async_read() {
    in_socket.async_read_some(boost::asio::buffer(in_read_buf, MAX_LENGTH), [this](const boost::system::error_code error, size_t length) {
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

void ClientSession::in_async_write() {
    boost::asio::async_write(in_socket, boost::asio::buffer(in_write_queue.front()), [this](boost::system::error_code error, std::size_t) {
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

void ClientSession::in_recv(const string &data) {
    switch (status) {
        case HANDSHAKE: {
            if (data[0] != 5) {
                Log::log_with_endpoint(in_endpoint, "unknown protocol");
                destroy();
                return;
            }
            bool ok = false;
            for (char i = 0; i < data[1]; ++i) {
                if (data[i + 2] == 0) {
                    ok = true;
                    break;
                }
            }
            if (!ok) {
                closing = true;
                Log::log_with_endpoint(in_endpoint, "unsupported auth method");
                in_send(string("\x05\xff", 2));
                return;
            }
            in_send(string("\x05\x00", 2));
            status = REQUEST;
            break;
        }
        case REQUEST: {
            if (data[0] != 5 or data[1] != 1 or data[2] != 0) {
                closing = true;
                Log::log_with_endpoint(in_endpoint, "unsupported command");
                in_send(string("\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00", 10));
                return;
            }
            in_send(string("\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00", 10));
            string req_str = data[1] + data.substr(3);
            TrojanRequest req;
            if (!req.parse(req_str)) {
                Log::log_with_endpoint(in_endpoint, "bad request");
                destroy();
                return;
            }
            Log::log_with_endpoint(in_endpoint, "requested connection to " + req.address + ':' + to_string(req.port));
            out_write_queue.push(config.password + "\r\n" + req_str + "\r\n");
            status = CONNECTING_REMOTE;
            tcp::resolver::query query(config.remote_addr, to_string(config.remote_port));
            resolver.async_resolve(query, [this](const boost::system::error_code error, tcp::resolver::iterator iterator) {
                if (!error) {
                    out_socket.lowest_layer().async_connect(*iterator, [this](const boost::system::error_code error) {
                        if (!error) {
                            out_socket.async_handshake(boost::asio::ssl::stream_base::client, [this](const boost::system::error_code error) {
                                if (!error) {
                                    Log::log_with_endpoint(in_endpoint, "tunnel established");
                                    status = FORWARD;
                                    out_async_read();
                                    out_async_write();
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
            break;
        }
        case CONNECTING_REMOTE: {
            out_write_queue.front() += data;
            break;
        }
        case FORWARD: {
            out_send(data);
            break;
        }
    }
}

void ClientSession::in_send(const string &data) {
    in_write_queue.push(data);
    if (in_write_queue.size() == 1) {
        in_async_write();
    }
}

void ClientSession::out_async_read() {
    out_socket.async_read_some(boost::asio::buffer(out_read_buf, MAX_LENGTH), [this](const boost::system::error_code error, size_t length) {
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

void ClientSession::out_async_write() {
    boost::asio::async_write(out_socket, boost::asio::buffer(out_write_queue.front()), [this](boost::system::error_code error, std::size_t) {
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

void ClientSession::out_recv(const std::string &data) {
    in_send(data);
}

void ClientSession::out_send(const std::string &data) {
    out_write_queue.push(data);
    if (out_write_queue.size() == 1) {
        out_async_write();
    }
}

void ClientSession::destroy() {
    if (destroying) {
        return;
    }
    destroying = true;
    Log::log_with_endpoint(in_endpoint, "disconnected");
    resolver.cancel();
    if (in_socket.is_open()) {
        in_socket.cancel();
        boost::system::error_code error;
        in_socket.shutdown(tcp::socket::shutdown_both, error);
        in_socket.close();
    }
    if (out_socket.lowest_layer().is_open()) {
        out_socket.lowest_layer().cancel();
        out_socket.async_shutdown([this](boost::system::error_code error) {
            delete this;
        });
        return;
    }
    delete this;
}
