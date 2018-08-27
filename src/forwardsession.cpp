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

#include "forwardsession.h"
#include "trojanrequest.h"
using namespace std;
using namespace boost::asio::ip;
using namespace boost::asio::ssl;

SSL_SESSION *ForwardSession::ssl_session(NULL);

ForwardSession::ForwardSession(const Config &config, boost::asio::io_service &io_service, context &ssl_context) :
    Session(config, io_service),
    status(CONNECT),
    first_packet_recv(false),
    in_socket(io_service),
    out_socket(io_service, ssl_context) {}

tcp::socket& ForwardSession::accept_socket() {
    return in_socket;
}

void ForwardSession::start() {
    start_time = time(NULL);
    in_endpoint = in_socket.remote_endpoint();
    auto ssl = out_socket.native_handle();
    if (config.ssl.sni != "") {
        SSL_set_tlsext_host_name(ssl, config.ssl.sni.c_str());
    }
    if (config.ssl.reuse_session && ssl_session) {
        SSL_set_session(ssl, ssl_session);
    }
    out_write_buf = TrojanRequest::generate(config.password.cbegin()->first, config.target_addr, config.target_port);
    if (config.append_payload) {
        in_async_read();
    } else {
        first_packet_recv = true;
    }
    tcp::resolver::query query(config.remote_addr, to_string(config.remote_port));
    auto self = shared_from_this();
    resolver.async_resolve(query, [this, self](const boost::system::error_code error, tcp::resolver::iterator iterator) {
        if (error) {
            Log::log_with_endpoint(in_endpoint, "cannot resolve remote server hostname " + config.remote_addr + ": " + error.message(), Log::ERROR);
            destroy();
            return;
        }
        out_socket.lowest_layer().open(iterator->endpoint().protocol());
        if (config.tcp.no_delay) {
            out_socket.lowest_layer().set_option(tcp::no_delay(true));
        }
        if (config.tcp.keep_alive) {
            out_socket.lowest_layer().set_option(boost::asio::socket_base::keep_alive(true));
        }
#ifdef TCP_FASTOPEN_CONNECT
        if (config.tcp.fast_open) {
            using fastopen_connect = boost::asio::detail::socket_option::boolean<IPPROTO_TCP, TCP_FASTOPEN_CONNECT>;
            boost::system::error_code ec;
            out_socket.lowest_layer().set_option(fastopen_connect(true), ec);
        }
#endif // TCP_FASTOPEN_CONNECT
        out_socket.lowest_layer().async_connect(*iterator, [this, self](const boost::system::error_code error) {
            if (error) {
                Log::log_with_endpoint(in_endpoint, "cannot establish connection to remote server " + config.remote_addr + ':' + to_string(config.remote_port) + ": " + error.message(), Log::ERROR);
                destroy();
                return;
            }
            out_socket.async_handshake(stream_base::client, [this, self](const boost::system::error_code error) {
                if (error) {
                    Log::log_with_endpoint(in_endpoint, "SSL handshake failed with " + config.remote_addr + ':' + to_string(config.remote_port) + ": " + error.message(), Log::ERROR);
                    destroy();
                    return;
                }
                Log::log_with_endpoint(in_endpoint, "tunnel established");
                if (config.ssl.reuse_session) {
                    auto ssl = out_socket.native_handle();
                    if (!SSL_session_reused(ssl)) {
                        Log::log_with_endpoint(in_endpoint, "SSL session not reused");
                        if (ssl_session) {
                            SSL_SESSION_free(ssl_session);
                        }
                        ssl_session = SSL_get1_session(ssl);
                    } else {
                        Log::log_with_endpoint(in_endpoint, "SSL session reused");
                    }
                }
                boost::system::error_code ec;
                if (!first_packet_recv) {
                    in_socket.cancel(ec);
                }
                status = FORWARD;
                out_async_read();
                out_async_write(out_write_buf);
            });
        });
    });
}

void ForwardSession::in_async_read() {
    auto self = shared_from_this();
    in_socket.async_read_some(boost::asio::buffer(in_read_buf, MAX_LENGTH), [this, self](const boost::system::error_code error, size_t length) {
        if (error && error != boost::asio::error::operation_aborted) {
            destroy();
            return;
        }
        in_recv(string((const char*)in_read_buf, length));
    });
}

void ForwardSession::in_async_write(const string &data) {
    auto self = shared_from_this();
    boost::asio::async_write(in_socket, boost::asio::buffer(data), [this, self](const boost::system::error_code error, size_t) {
        if (error) {
            destroy();
            return;
        }
        in_sent();
    });
}

void ForwardSession::out_async_read() {
    auto self = shared_from_this();
    out_socket.async_read_some(boost::asio::buffer(out_read_buf, MAX_LENGTH), [this, self](const boost::system::error_code error, size_t length) {
        if (error) {
            destroy();
            return;
        }
        out_recv(string((const char*)out_read_buf, length));
    });
}

void ForwardSession::out_async_write(const string &data) {
    auto self = shared_from_this();
    boost::asio::async_write(out_socket, boost::asio::buffer(data), [this, self](const boost::system::error_code error, size_t) {
        if (error) {
            destroy();
            return;
        }
        out_sent();
    });
}

void ForwardSession::in_recv(const string &data) {
    if (status == CONNECT) {
        sent_len += data.length();
        first_packet_recv = true;
        out_write_buf += data;
    } else if (status == FORWARD) {
        sent_len += data.length();
        out_async_write(data);
    }
}

void ForwardSession::in_sent() {
    if (status == FORWARD) {
        out_async_read();
    }
}

void ForwardSession::out_recv(const string &data) {
    if (status == FORWARD) {
        recv_len += data.length();
        in_async_write(data);
    }
}

void ForwardSession::out_sent() {
    if (status == FORWARD) {
        in_async_read();
    }
}

void ForwardSession::destroy() {
    if (status == DESTROY) {
        return;
    }
    status = DESTROY;
    Log::log_with_endpoint(in_endpoint, "disconnected, " + to_string(recv_len) + " bytes received, " + to_string(sent_len) + " bytes sent, lasted for " + to_string(time(NULL) - start_time) + " seconds", Log::INFO);
    boost::system::error_code ec;
    resolver.cancel();
    if (in_socket.is_open()) {
        in_socket.cancel(ec);
        in_socket.shutdown(tcp::socket::shutdown_both, ec);
        in_socket.close(ec);
    }
    if (out_socket.lowest_layer().is_open()) {
        out_socket.lowest_layer().cancel(ec);
        auto self = shared_from_this();
        out_socket.async_shutdown([this, self](const boost::system::error_code) {
            boost::system::error_code ec;
            out_socket.lowest_layer().shutdown(tcp::socket::shutdown_both, ec);
            out_socket.lowest_layer().close(ec);
        });
    }
}
