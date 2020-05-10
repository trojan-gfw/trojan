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

#include "utils.h"
#include "log.h"

using namespace std;

#ifndef _WIN32  // nat mode does not support in windows platform
// copied from shadowsocks-libev udpreplay.c
static int get_dstaddr(struct msghdr *msg, struct sockaddr_storage *dstaddr) {
    struct cmsghdr *cmsg;

    for (cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
        if (cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_RECVORIGDSTADDR) {
            memcpy(dstaddr, CMSG_DATA(cmsg), sizeof(struct sockaddr_in));
            dstaddr->ss_family = AF_INET;
            return 0;
        } else if (cmsg->cmsg_level == SOL_IPV6 && cmsg->cmsg_type == IPV6_RECVORIGDSTADDR) {
            memcpy(dstaddr, CMSG_DATA(cmsg), sizeof(struct sockaddr_in6));
            dstaddr->ss_family = AF_INET6;
            return 0;
        }
    }

    return 1;
}

static int get_ttl(struct msghdr *msg) {
    struct cmsghdr *cmsg;
    for (cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
        if (cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_TTL) {
            return *(int *)CMSG_DATA(cmsg);
        } else if (cmsg->cmsg_level == SOL_IPV6 && cmsg->cmsg_type == IPV6_HOPLIMIT) {
            return *(int *)CMSG_DATA(cmsg);
        }
    }

    return -1;
}

static pair<string, uint16_t> get_addr(struct sockaddr_storage addr) {
    const int buf_size = 256;
    char buf[256];

    if (addr.ss_family == AF_INET) {
        sockaddr_in *sa = (sockaddr_in *)&addr;
        if (inet_ntop(AF_INET, &(sa->sin_addr), buf, buf_size)) {
            return make_pair(buf, ntohs(sa->sin_port));
        }
    } else {
        sockaddr_in6 *sa = (sockaddr_in6 *)&addr;
        if (inet_ntop(AF_INET6, &(sa->sin6_addr), buf, buf_size)) {
            return make_pair(buf, ntohs(sa->sin6_port));
        }
    }

    return make_pair("", 0);
}

// copied from shadowsocks-libev udpreplay.c
// it works if in NAT mode
pair<string, uint16_t> recv_tproxy_udp_msg(int fd, boost::asio::ip::udp::endpoint &recv_endpoint, char *buf, int &buf_len, int &ttl) {
    struct sockaddr_storage src_addr;
    memset(&src_addr, 0, sizeof(struct sockaddr_storage));

    char control_buffer[64] = {0};
    struct msghdr msg;
    memset(&msg, 0, sizeof(struct msghdr));
    struct iovec iov[1];
    struct sockaddr_storage dst_addr;
    memset(&dst_addr, 0, sizeof(struct sockaddr_storage));

    msg.msg_name = &src_addr;
    msg.msg_namelen = sizeof(struct sockaddr_storage);
    ;
    msg.msg_control = control_buffer;
    msg.msg_controllen = sizeof(control_buffer);

    const int packet_size = DEFAULT_PACKET_SIZE;
    const int buf_size = DEFAULT_PACKET_SIZE * 2;

    iov[0].iov_base = buf;
    iov[0].iov_len = buf_size;
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    buf_len = recvmsg(fd, &msg, 0);
    if (buf_len == -1) {
        _log_with_date_time("[udp] server_recvmsg failed!", Log::FATAL);
    } else {
        if (buf_len > packet_size) {
            _log_with_date_time(string("[udp] UDP server_recv_recvmsg fragmentation, MTU at least be: ") + to_string(buf_len + PACKET_HEADER_SIZE), Log::INFO);
        }

        ttl = get_ttl(&msg);
        if (get_dstaddr(&msg, &dst_addr)) {
            _log_with_date_time("[udp] unable to get dest addr!", Log::FATAL);
        } else {
            auto target_dst = get_addr(dst_addr);
            auto src_dst = get_addr(src_addr);
            recv_endpoint.address(boost::asio::ip::make_address(src_dst.first));
            recv_endpoint.port(src_dst.second);
            return target_dst;
        }
    }

    return make_pair("", 0);
}

bool prepare_nat_udp_bind(int fd, bool is_ipv4, bool recv_ttl) {
    
    int opt = 1;
    int sol;
    int ip_recv;

    if (is_ipv4) {
        sol = SOL_IP;
        ip_recv = IP_RECVORIGDSTADDR;
    } else{
        sol = SOL_IPV6;
        ip_recv = IPV6_RECVORIGDSTADDR;
    } 

    if (setsockopt(fd, sol, IP_TRANSPARENT, &opt, sizeof(opt))) {
        _log_with_date_time("[udp] setsockopt IP_TRANSPARENT failed!", Log::FATAL);
        return false;
    }

    if (setsockopt(fd, sol, ip_recv, &opt, sizeof(opt))) {
        _log_with_date_time("[udp] setsockopt IP_RECVORIGDSTADDR failed!", Log::FATAL);
        return false;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        _log_with_date_time("[udp] setsockopt SO_REUSEADDR failed!", Log::FATAL);
        return false;
    }

    if (recv_ttl) {
        if (setsockopt(fd, sol, is_ipv4 ? IP_RECVTTL : IPV6_RECVHOPLIMIT, &opt, sizeof(opt))) {
            _log_with_date_time("[udp] setsockopt IP_RECVOPTS/IPV6_RECVHOPLIMIT failed!", Log::ERROR);
        }
    }

    return true;
}

bool prepare_nat_udp_target_bind(int fd, bool is_ipv4, const boost::asio::ip::udp::endpoint &udp_target_endpoint) {
    int opt = 1;
    int sol = is_ipv4 ? SOL_IPV6 : SOL_IP;
    if (setsockopt(fd, sol, IP_TRANSPARENT, &opt, sizeof(opt))) {
        _log_with_endpoint(udp_target_endpoint, "[udp] setsockopt IP_TRANSPARENT failed!", Log::FATAL);
        return false;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        _log_with_endpoint(udp_target_endpoint, "[udp] setsockopt SO_REUSEADDR failed!", Log::FATAL);
        return false;
    }

    return true;
}

#else

std::pair<std::string, uint16_t> recv_tproxy_udp_msg(int fd, boost::asio::ip::udp::endpoint& recv_endpoint, char* buf, int& buf_len, int& ttl){
    throw runtime_error("NAT is not supported in Windows");
}

bool prepare_nat_udp_bind(int fd, bool is_ipv4, bool recv_ttl){
    throw runtime_error("NAT is not supported in Windows");
}

bool prepare_nat_udp_target_bind(int fd, bool is_ipv4, const boost::asio::ip::udp::endpoint& udp_target_endpoint) {
    throw runtime_error("NAT is not supported in Windows");
}

#endif  // _WIN32