/*
 * This file is part of the trojan project.
 * Trojan is an unidentifiable mechanism that helps you bypass GFW.
 * Copyright (C) 2017-2020  The Trojan Authors.
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

#include "natsession.h"
#include "proto/trojanrequest.h"
#include "ssl/sslsession.h"
using namespace std;
using namespace boost::asio::ip;
using namespace boost::asio::ssl;

// These 2 definitions are respectively from linux/netfilter_ipv4.h and
// linux/netfilter_ipv6/ip6_tables.h. Including them will 1) cause linux-headers
// to be one of trojan's dependencies, which is not good, and 2) prevent trojan
// from even compiling.
#ifndef SO_ORIGINAL_DST
#define SO_ORIGINAL_DST 80
#endif // SO_ORIGINAL_DST
#ifndef IP6T_SO_ORIGINAL_DST
#define IP6T_SO_ORIGINAL_DST 80
#endif // IP6T_SO_ORIGINAL_DST

NATSession::NATSession(const Config &config, boost::asio::io_context &io_context, context &ssl_context) :
    Session(config, io_context),
    status(CONNECT),
    first_packet_recv(false),
    in_socket(io_context),
    out_socket(io_context, ssl_context) {}

tcp::socket& NATSession::accept_socket() {
    return in_socket;
}

pair<string, uint16_t> NATSession::get_target_endpoint() {
#ifdef ENABLE_NAT
    int fd = in_socket.native_handle();
    // Taken from https://github.com/shadowsocks/shadowsocks-libev/blob/v3.3.1/src/redir.c.
    sockaddr_storage destaddr;
    memset(&destaddr, 0, sizeof(sockaddr_storage));
    socklen_t socklen = sizeof(destaddr);
    int error = getsockopt(fd, SOL_IPV6, IP6T_SO_ORIGINAL_DST, &destaddr, &socklen);
    if (error) {
        error = getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, &destaddr, &socklen);
        if (error) {
            return make_pair("", 0);
        }
    }
    char ipstr[INET6_ADDRSTRLEN];
    uint16_t port;
    if (destaddr.ss_family == AF_INET) {
        auto *sa = (sockaddr_in*) &destaddr;
        inet_ntop(AF_INET, &(sa->sin_addr), ipstr, INET_ADDRSTRLEN);
        port = ntohs(sa->sin_port);
    } else {
        auto *sa = (sockaddr_in6*) &destaddr;
        inet_ntop(AF_INET6, &(sa->sin6_addr), ipstr, INET6_ADDRSTRLEN);
        port = ntohs(sa->sin6_port);
    }
    return make_pair(ipstr, port);
#else // ENABLE_NAT
    return make_pair("", 0);
#endif // ENABLE_NAT
}

void NATSession::start() {
    boost::system::error_code ec;
    start_time = time(nullptr);
    in_endpoint = in_socket.remote_endpoint(ec);
    if (ec) {
        destroy();
        return;
    }
    auto ssl = out_socket.native_handle();
    if (!config.ssl.sni.empty()) {
        SSL_set_tlsext_host_name(ssl, config.ssl.sni.c_str());
    }
    if (config.ssl.reuse_session) {
        SSL_SESSION *session = SSLSession::get_session();
        if (session) {
            SSL_set_session(ssl, session);
        }
    }
    auto target_endpoint = get_target_endpoint();
    string &target_addr = target_endpoint.first;
    uint16_t target_port = target_endpoint.second;
    if (target_port == 0) {
        destroy();
        return;
    }
    out_write_buf = TrojanRequest::generate(config.password.cbegin()->first, target_addr, target_port, true);
    in_async_read();
    Log::log_with_endpoint(in_endpoint, "forwarding to " + target_addr + ':' + to_string(target_port) + " via " + config.remote_addr + ':' + to_string(config.remote_port), Log::INFO);
    auto self = shared_from_this();
    resolver.async_resolve(config.remote_addr, to_string(config.remote_port), [this, self](const boost::system::error_code error, const tcp::resolver::results_type& results) {
        if (error || results.empty()) {
            Log::log_with_endpoint(in_endpoint, "cannot resolve remote server hostname " + config.remote_addr + ": " + error.message(), Log::ERROR);
            destroy();
            return;
        }
        auto iterator = results.begin();
        Log::log_with_endpoint(in_endpoint, config.remote_addr + " is resolved to " + iterator->endpoint().address().to_string(), Log::ALL);
        boost::system::error_code ec;
        out_socket.next_layer().open(iterator->endpoint().protocol(), ec);
        if (ec) {
            destroy();
            return;
        }
        if (config.tcp.no_delay) {
            out_socket.next_layer().set_option(tcp::no_delay(true));
        }
        if (config.tcp.keep_alive) {
            out_socket.next_layer().set_option(boost::asio::socket_base::keep_alive(true));
        }
#ifdef TCP_FASTOPEN_CONNECT
        if (config.tcp.fast_open) {
            using fastopen_connect = boost::asio::detail::socket_option::boolean<IPPROTO_TCP, TCP_FASTOPEN_CONNECT>;
            boost::system::error_code ec;
            out_socket.next_layer().set_option(fastopen_connect(true), ec);
        }
#endif // TCP_FASTOPEN_CONNECT
        out_socket.next_layer().async_connect(*iterator, [this, self](const boost::system::error_code error) {
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

void NATSession::in_async_read() {
    auto self = shared_from_this();
    in_socket.async_read_some(boost::asio::buffer(in_read_buf, MAX_LENGTH), [this, self](const boost::system::error_code error, size_t length) {
        if (error == boost::asio::error::operation_aborted) {
            return;
        }
        if (error) {
            destroy();
            return;
        }
        in_recv(string((const char*)in_read_buf, length));
    });
}

void NATSession::in_async_write(const string &data) {
    auto self = shared_from_this();
    auto data_copy = make_shared<string>(data);
    boost::asio::async_write(in_socket, boost::asio::buffer(*data_copy), [this, self, data_copy](const boost::system::error_code error, size_t) {
        if (error) {
            destroy();
            return;
        }
        in_sent();
    });
}

void NATSession::out_async_read() {
    auto self = shared_from_this();
    out_socket.async_read_some(boost::asio::buffer(out_read_buf, MAX_LENGTH), [this, self](const boost::system::error_code error, size_t length) {
        if (error) {
            destroy();
            return;
        }
        out_recv(string((const char*)out_read_buf, length));
    });
}

void NATSession::out_async_write(const string &data) {
    auto self = shared_from_this();
    auto data_copy = make_shared<string>(data);
    boost::asio::async_write(out_socket, boost::asio::buffer(*data_copy), [this, self, data_copy](const boost::system::error_code error, size_t) {
        if (error) {
            destroy();
            return;
        }
        out_sent();
    });
}

void NATSession::in_recv(const string &data) {
    if (status == CONNECT) {
        sent_len += data.length();
        first_packet_recv = true;
        out_write_buf += data;
    } else if (status == FORWARD) {
        sent_len += data.length();
        out_async_write(data);
    }
}

void NATSession::in_sent() {
    if (status == FORWARD) {
        out_async_read();
    }
}

void NATSession::out_recv(const string &data) {
    if (status == FORWARD) {
        recv_len += data.length();
        in_async_write(data);
    }
}

void NATSession::out_sent() {
    if (status == FORWARD) {
        in_async_read();
    }
}

void NATSession::destroy() {
    if (status == DESTROY) {
        return;
    }
    status = DESTROY;
    Log::log_with_endpoint(in_endpoint, "disconnected, " + to_string(recv_len) + " bytes received, " + to_string(sent_len) + " bytes sent, lasted for " + to_string(time(nullptr) - start_time) + " seconds", Log::INFO);
    boost::system::error_code ec;
    resolver.cancel();
    if (in_socket.is_open()) {
        in_socket.cancel(ec);
        in_socket.shutdown(tcp::socket::shutdown_both, ec);
        in_socket.close(ec);
    }
    if (out_socket.next_layer().is_open()) {
        auto self = shared_from_this();
        auto ssl_shutdown_cb = [this, self](const boost::system::error_code error) {
            if (error == boost::asio::error::operation_aborted) {
                return;
            }
            boost::system::error_code ec;
            ssl_shutdown_timer.cancel();
            out_socket.next_layer().cancel(ec);
            out_socket.next_layer().shutdown(tcp::socket::shutdown_both, ec);
            out_socket.next_layer().close(ec);
        };
        out_socket.next_layer().cancel(ec);
        out_socket.async_shutdown(ssl_shutdown_cb);
        ssl_shutdown_timer.expires_after(chrono::seconds(SSL_SHUTDOWN_TIMEOUT));
        ssl_shutdown_timer.async_wait(ssl_shutdown_cb);
    }
}
