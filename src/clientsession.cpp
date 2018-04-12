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
#include "trojanrequest.h"
#include "udppacket.h"
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
    udp_socket.async_receive_from(boost::asio::buffer(udp_read_buf, MAX_LENGTH), udp_recv_endpoint, [this, self](const boost::system::error_code error, size_t length) {
        if (error && error != boost::asio::error::operation_aborted) {
            destroy();
            return;
        }
        udp_recv(string((const char*)udp_read_buf, length), udp_recv_endpoint);
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
            if (data.length() < 2 || data[0] != 5 || data.length() != data[1] + 2) {
                destroy();
                return;
            }
            bool has_method = false;
            for (int i = 2; i < data[1] + 2; ++i) {
                if (data[i] == 0) {
                    has_method = true;
                    break;
                }
            }
            if (!has_method) {
                in_async_write(string("\x05\xff", 2));
                status = INVALID;
                return;
            }
            in_async_write(string("\x05\x00", 2));
            break;
        }
        case REQUEST: {
            if (data.length() < 7 || data[0] != 5 || data[2] != 0) {
                destroy();
                return;
            }
            out_write_buf = data[1] + data.substr(3);
            TrojanRequest req;
            if (req.parse(out_write_buf) != out_write_buf.length()) {
                in_async_write(string("\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00", 10));
                status = INVALID;
                return;
            }
            out_write_buf = config.password[0] + "\r\n" + out_write_buf + "\r\n";
            is_udp = req.command == TrojanRequest::UDP_ASSOCIATE;
            if (is_udp) {
                udp_socket.bind(udp::endpoint(in_socket.local_endpoint().address(), 0));
                in_async_write(string("\x05\x00\x00", 3) + SOCKS5Address::generate(udp_socket.local_endpoint()));
            } else {
                in_async_write(string("\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00", 10));
            }
            break;
        }
        case CONNECT: {
            out_write_buf += data;
            break;
        }
        case FORWARD: {
            out_async_write(data);
            break;
        }
        case UDP_FORWARD: {
            destroy();
            break;
        }
        default: break;
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
            status = CONNECT;
            if (is_udp) {
                udp_async_read();
            }
            in_async_read();
            tcp::resolver::query query(config.remote_addr, to_string(config.remote_port));
            auto self = shared_from_this();
            resolver.async_resolve(query, [this, self](const boost::system::error_code error, tcp::resolver::iterator iterator) {
                if (error) {
                    destroy();
                    return;
                }
                out_socket.lowest_layer().async_connect(*iterator, [this, self](const boost::system::error_code error) {
                    if (error) {
                        destroy();
                        return;
                    }
                    out_socket.async_handshake(stream_base::client, [this, self](const boost::system::error_code error) {
                        if (error) {
                            destroy();
                            return;
                        }
                        if (is_udp) {
                            udp_socket.cancel();
                            status = UDP_FORWARD;
                        } else {
                            in_socket.cancel();
                            status = FORWARD;
                        }
                        if (config.ssl.reuse_session) {
                            auto ssl = out_socket.native_handle();
                            if (!SSL_session_reused(ssl)) {
                                if (ssl_session) {
                                    SSL_SESSION_free(ssl_session);
                                }
                                ssl_session = SSL_get1_session(ssl);
                            }
                        }
                        out_async_read();
                        out_async_write(out_write_buf);
                    });
                });
            });
            break;
        }
        case FORWARD: {
            out_async_read();
            break;
        }
        case INVALID: {
            destroy();
            break;
        }
        default: break;
    }
}

void ClientSession::out_recv(const string &data) {
    if (status == FORWARD) {
        in_async_write(data);
    } else if (status == UDP_FORWARD) {
        udp_data_buf += data;
        udp_sent();
    }
}

void ClientSession::out_sent() {
    if (status == FORWARD) {
        in_async_read();
    } else if (status == UDP_FORWARD) {
        udp_async_read();
    }
}

void ClientSession::udp_recv(const string &data, const udp::endpoint &endpoint) {
    if (data[0] || data[1] || data[2]) {
        destroy();
        return;
    }
    SOCKS5Address address;
    int address_len = address.parse(data.substr(3));
    if (address_len == -1) {
        destroy();
        return;
    }
    uint16_t length = data.length() - 3 - address_len;
    string packet = data.substr(3, address_len) + char(uint8_t(length >> 8)) + char(uint8_t(length & 0xFF)) + "\r\n" + data.substr(address_len + 3);
    if (status == CONNECT) {
        out_write_buf += packet;
    } else if (status == UDP_FORWARD) {
        out_async_write(packet);
    }
}

void ClientSession::udp_sent() {
    if (status == UDP_FORWARD) {
        UDPPacket packet;
        int packet_len = packet.parse(udp_data_buf);
        if (packet_len == -1) {
            out_async_read();
            return;
        }
        SOCKS5Address address;
        int address_len = address.parse(udp_data_buf);
        string reply = string("\x00\x00\x00", 3) + udp_data_buf.substr(0, address_len) + packet.payload;
        udp_data_buf = udp_data_buf.substr(packet_len);
        udp_async_write(reply, udp_recv_endpoint);
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
