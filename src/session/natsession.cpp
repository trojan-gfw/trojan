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
    ClientSession(config, io_context, ssl_context){
    status = CONNECT;
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
    if (prepare_session()) {
        auto target_endpoint = get_target_endpoint();
        string &target_addr = target_endpoint.first;
        uint16_t target_port = target_endpoint.second;
        if (target_port == 0) {
            destroy();
            return;
        }
        _log_with_endpoint(in_endpoint, "forwarding to " + target_addr + ':' + to_string(target_port) + " via " + config.remote_addr + ':' + to_string(config.remote_port), Log::INFO);
        out_write_buf = TrojanRequest::generate(config.password.cbegin()->first, target_addr, target_port, true);
        
        request_remote();
    }
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
