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

#include "udpforwardsession.h"
#include <stdexcept>
#include <utility>
#include "ssl/sslsession.h"
#include "proto/trojanrequest.h"
#include "proto/udppacket.h"
using namespace std;
using namespace boost::asio::ip;
using namespace boost::asio::ssl;

UDPForwardSession::UDPForwardSession(const Config &config, boost::asio::io_context &io_context, context &ssl_context, const udp::endpoint &endpoint, UDPWrite in_write) :
    Session(config, io_context),
    status(CONNECT),
    in_write(move(in_write)),
    out_socket(io_context, ssl_context),
    gc_timer(io_context) {
    udp_recv_endpoint = endpoint;
    in_endpoint = tcp::endpoint(endpoint.address(), endpoint.port());
}

tcp::socket& UDPForwardSession::accept_socket() {
    throw logic_error("accept_socket does not exist in UDPForwardSession");
}

void UDPForwardSession::start() {
    timer_async_wait();
    start_time = time(nullptr);
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
    out_write_buf = TrojanRequest::generate(config.password.cbegin()->first, config.target_addr, config.target_port, false);
    Log::log_with_endpoint(in_endpoint, "forwarding UDP packets to " + config.target_addr + ':' + to_string(config.target_port) + " via " + config.remote_addr + ':' + to_string(config.remote_port), Log::INFO);
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
                status = FORWARDING;
                out_async_read();
                out_async_write(out_write_buf);
                out_write_buf.clear();
            });
        });
    });
}

bool UDPForwardSession::process(const udp::endpoint &endpoint, const string &data) {
    if (endpoint != udp_recv_endpoint) {
        return false;
    }
    in_recv(data);
    return true;
}

void UDPForwardSession::out_async_read() {
    auto self = shared_from_this();
    out_socket.async_read_some(boost::asio::buffer(out_read_buf, MAX_LENGTH), [this, self](const boost::system::error_code error, size_t length) {
        if (error) {
            destroy();
            return;
        }
        out_recv(string((const char*)out_read_buf, length));
    });
}

void UDPForwardSession::out_async_write(const string &data) {
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

void UDPForwardSession::timer_async_wait()
{
    gc_timer.expires_after(chrono::seconds(config.udp_timeout));
    auto self = shared_from_this();
    gc_timer.async_wait([this, self](const boost::system::error_code error) {
        if (!error) {
            Log::log_with_endpoint(in_endpoint, "UDP session timeout");
            destroy();
        }
    });
}

void UDPForwardSession::in_recv(const string &data) {
    if (status == DESTROY) {
        return;
    }
    gc_timer.cancel();
    timer_async_wait();
    string packet = UDPPacket::generate(config.target_addr, config.target_port, data);
    size_t length = data.length();
    Log::log_with_endpoint(in_endpoint, "sent a UDP packet of length " + to_string(length) + " bytes to " + config.target_addr + ':' + to_string(config.target_port));
    sent_len += length;
    if (status == FORWARD) {
        status = FORWARDING;
        out_async_write(packet);
    } else {
        out_write_buf += packet;
    }
}

void UDPForwardSession::out_recv(const string &data) {
    if (status == FORWARD || status == FORWARDING) {
        gc_timer.cancel();
        timer_async_wait();
        udp_data_buf += data;
        for (;;) {
            UDPPacket packet;
            size_t packet_len;
            bool is_packet_valid = packet.parse(udp_data_buf, packet_len);
            if (!is_packet_valid) {
                if (udp_data_buf.length() > MAX_LENGTH) {
                    Log::log_with_endpoint(in_endpoint, "UDP packet too long", Log::ERROR);
                    destroy();
                    return;
                }
                break;
            }
            Log::log_with_endpoint(in_endpoint, "received a UDP packet of length " + to_string(packet.length) + " bytes from " + packet.address.address + ':' + to_string(packet.address.port));
            udp_data_buf = udp_data_buf.substr(packet_len);
            recv_len += packet.length;
            in_write(udp_recv_endpoint, packet.payload);
        }
        out_async_read();
    }
}

void UDPForwardSession::out_sent() {
    if (status == FORWARDING) {
        if (out_write_buf.length() == 0) {
            status = FORWARD;
        } else {
            out_async_write(out_write_buf);
            out_write_buf.clear();
        }
    }
}

void UDPForwardSession::destroy() {
    if (status == DESTROY) {
        return;
    }
    status = DESTROY;
    Log::log_with_endpoint(in_endpoint, "disconnected, " + to_string(recv_len) + " bytes received, " + to_string(sent_len) + " bytes sent, lasted for " + to_string(time(nullptr) - start_time) + " seconds", Log::INFO);
    resolver.cancel();
    gc_timer.cancel();
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
        boost::system::error_code ec;
        out_socket.next_layer().cancel(ec);
        out_socket.async_shutdown(ssl_shutdown_cb);
        ssl_shutdown_timer.expires_after(chrono::seconds(SSL_SHUTDOWN_TIMEOUT));
        ssl_shutdown_timer.async_wait(ssl_shutdown_cb);
    }
}
