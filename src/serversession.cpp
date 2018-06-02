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
#include "udppacket.h"
using namespace std;
using namespace boost::asio::ip;
using namespace boost::asio::ssl;

ServerSession::ServerSession(const Config &config, boost::asio::io_service &io_service, context &ssl_context) :
    Session(config, io_service),
    status(HANDSHAKE),
    in_socket(io_service, ssl_context),
    out_socket(io_service),
    udp_resolver(io_service) {}

tcp::socket& ServerSession::accept_socket() {
    return (tcp::socket&)in_socket.lowest_layer();
}

void ServerSession::start() {
    in_endpoint = in_socket.lowest_layer().remote_endpoint();
    auto self = shared_from_this();
    in_socket.async_handshake(stream_base::server, [this, self](const boost::system::error_code error) {
        if (error) {
            Log::log_with_endpoint(in_endpoint, "SSL handshake failed: " + error.message(), Log::ERROR);
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
    if (status == HANDSHAKE) {
        TrojanRequest req;
        bool valid = req.parse(data, config.password) != -1;
        tcp::resolver::query query(valid ? req.address.address : config.remote_addr,
                                   to_string(valid ? req.address.port : config.remote_port));
        if (valid) {
            Log::log_with_endpoint(in_endpoint, "authenticated as " + req.password, Log::INFO);
            out_write_buf = req.payload;
            if (req.command == TrojanRequest::UDP_ASSOCIATE) {
                Log::log_with_endpoint(in_endpoint, "requested UDP associate to " + req.address.address + ':' + to_string(req.address.port), Log::INFO);
                status = UDP_FORWARD;
                udp_data_buf = out_write_buf;
                udp_sent();
                return;
            } else {
                Log::log_with_endpoint(in_endpoint, "requested connection to " + req.address.address + ':' + to_string(req.address.port), Log::INFO);
            }
        } else {
            Log::log_with_endpoint(in_endpoint, "not trojan request, connecting to " + config.remote_addr + ':' + to_string(config.remote_port), Log::WARN);
            out_write_buf = data;
        }
        sent_len += out_write_buf.length();
        auto self = shared_from_this();
        resolver.async_resolve(query, [this, self](const boost::system::error_code error, tcp::resolver::iterator iterator) {
            if (error) {
                Log::log_with_endpoint(in_endpoint, "cannot resolve remote server hostname: " + error.message(), Log::ERROR);
                destroy();
                return;
            }
            out_socket.open(iterator->endpoint().protocol());
            if (config.tcp.keep_alive) {
                out_socket.set_option(boost::asio::socket_base::keep_alive(true));
            }
            if (config.tcp.no_delay) {
                out_socket.set_option(tcp::no_delay(true));
            }
#ifdef TCP_FASTOPEN_CONNECT
            if (config.tcp.fast_open) {
                using fastopen_connect = boost::asio::detail::socket_option::boolean<IPPROTO_TCP, TCP_FASTOPEN_CONNECT>;
                boost::system::error_code ec;
                out_socket.set_option(fastopen_connect(true), ec);
            }
#endif // TCP_FASTOPEN_CONNECT
            out_socket.async_connect(*iterator, [this, self](const boost::system::error_code error) {
                if (error) {
                    Log::log_with_endpoint(in_endpoint, "cannot establish connection to remote server: " + error.message(), Log::ERROR);
                    destroy();
                    return;
                }
                Log::log_with_endpoint(in_endpoint, "tunnel established");
                status = FORWARD;
                out_async_read();
                if (out_write_buf != "") {
                    out_async_write(out_write_buf);
                } else {
                    in_async_read();
                }
            });
        });
    } else if (status == FORWARD) {
        sent_len += data.length();
        out_async_write(data);
    } else if (status == UDP_FORWARD) {
        udp_data_buf += data;
        udp_sent();
    }
}

void ServerSession::in_sent() {
    if (status == FORWARD) {
        out_async_read();
    } else if (status == UDP_FORWARD) {
        udp_async_read();
    }
}

void ServerSession::out_recv(const string &data) {
    if (status == FORWARD) {
        recv_len += data.length();
        in_async_write(data);
    }
}

void ServerSession::out_sent() {
    if (status == FORWARD) {
        in_async_read();
    }
}

void ServerSession::udp_recv(const string &data, const udp::endpoint &endpoint) {
    if (status == UDP_FORWARD) {
        uint16_t length = data.length();
        Log::log_with_endpoint(in_endpoint, "received a UDP packet of length " + to_string(length) + " bytes from " + endpoint.address().to_string() + ':' + to_string(endpoint.port()));
        recv_len += length;
        in_async_write(UDPPacket::generate(endpoint, data));
    }
}

void ServerSession::udp_sent() {
    if (status == UDP_FORWARD) {
        UDPPacket packet;
        int packet_len = packet.parse(udp_data_buf);
        if (packet_len == -1) {
            if (udp_data_buf.length() > MAX_LENGTH) {
                Log::log_with_endpoint(in_endpoint, "UDP packet too long", Log::ERROR);
                destroy();
                return;
            }
            in_async_read();
            return;
        }
        Log::log_with_endpoint(in_endpoint, "sent a UDP packet of length " + to_string(packet.length) + " bytes to " + packet.address.address + ':' + to_string(packet.address.port));
        if (!udp_socket.is_open()) {
            udp::endpoint endpoint(address::from_string(packet.address.address), packet.address.port);
            udp_socket.open(endpoint.protocol());
            udp_socket.bind(udp::endpoint(endpoint.protocol(), 0));
            udp_async_read();
        }
        udp_data_buf = udp_data_buf.substr(packet_len);
        udp::resolver::query query(packet.address.address, to_string(packet.address.port));
        auto self = shared_from_this();
        udp_resolver.async_resolve(query, [this, self, packet](const boost::system::error_code error, udp::resolver::iterator iterator) {
            if (error) {
                Log::log_with_endpoint(in_endpoint, "cannot resolve remote server hostname: " + error.message(), Log::ERROR);
                destroy();
                return;
            }
            sent_len += packet.length;
            udp_async_write(packet.payload, *iterator);
        });
    }
}

void ServerSession::destroy() {
    if (status == DESTROY) {
        return;
    }
    status = DESTROY;
    Log::log_with_endpoint(in_endpoint, "disconnected, " + to_string(recv_len) + " bytes received, " + to_string(sent_len) + " bytes sent, lasted for " + to_string(time(NULL) - start_time) + " seconds", Log::INFO);
    boost::system::error_code ec;
    resolver.cancel();
    udp_resolver.cancel();
    if (out_socket.is_open()) {
        out_socket.cancel(ec);
        out_socket.shutdown(tcp::socket::shutdown_both, ec);
        out_socket.close(ec);
    }
    if (udp_socket.is_open()) {
        udp_socket.cancel(ec);
        udp_socket.close(ec);
    }
    if (in_socket.lowest_layer().is_open()) {
        in_socket.lowest_layer().cancel(ec);
        auto self = shared_from_this();
        in_socket.async_shutdown([this, self](const boost::system::error_code) {
            boost::system::error_code ec;
            in_socket.lowest_layer().shutdown(tcp::socket::shutdown_both, ec);
            in_socket.lowest_layer().close(ec);
        });
    }
}
