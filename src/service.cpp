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

#include "service.h"
#include <cstring>
#include <string>
#include <memory>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include "config.h"
#include "log.h"
#include "session.h"
#include "serversession.h"
#include "clientsession.h"
using namespace std;
using namespace boost::asio::ip;
using namespace boost::asio::ssl;

const unsigned char Service::alpn[] = {
    8, 'h', 't', 't', 'p', '/', '1', '.', '1'
};

const char Service::g_dh2048_sz[] =
    "-----BEGIN DH PARAMETERS-----\n"
    "MIIBCAKCAQEA///////////JD9qiIWjCNMTGYouA3BzRKQJOCIpnzHQCC76mOxOb\n"
    "IlFKCHmONATd75UZs806QxswKwpt8l8UN0/hNW1tUcJF5IW1dmJefsb0TELppjft\n"
    "awv/XLb0Brft7jhr+1qJn6WunyQRfEsf5kkoZlHs5Fs9wgB8uKFjvwWY2kg2HFXT\n"
    "mmkWP6j9JM9fg2VdI9yjrZYcYvNWIIVSu57VKQdwlpZtZww1Tkq8mATxdGwIyhgh\n"
    "fDKQXkYuNs474553LBgOhgObJ4Oi7Aeij7XFXfBvTFLJ3ivL9pVYFxg5lUl86pVq\n"
    "5RXSJhiY+gUQFXKOWoqsqmj//////////wIBAg==\n"
    "-----END DH PARAMETERS-----";

Service::Service(const Config &config) :
    config(config),
    socket_acceptor(io_service, tcp::endpoint(address::from_string(config.local_addr), config.local_port)),
    ssl_context(context::sslv23) {
    auto native_context = ssl_context.native_handle();
    if (config.run_type == Config::SERVER) {
        ssl_context.set_options(context::default_workarounds | context::no_sslv2 | boost::asio::ssl::context::single_dh_use);
        SSL_CTX_set_ecdh_auto(native_context, 1);
        if (config.use_default_dhparam) {
            ssl_context.use_tmp_dh(boost::asio::const_buffer(g_dh2048_sz, strlen(g_dh2048_sz)));
        } else {
            ssl_context.use_tmp_dh_file(config.dhparamfile);
        }
        ssl_context.set_password_callback([this](size_t, context_base::password_purpose) {
            return this->config.keyfile_password;
        });
        ssl_context.use_certificate_chain_file(config.certfile);
        ssl_context.use_private_key_file(config.keyfile, context::pem);
        SSL_CTX_set_alpn_select_cb(native_context, [](SSL*, const unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void*) -> int {
            if (SSL_select_next_proto((unsigned char**)out, outlen, Service::alpn, sizeof(Service::alpn), in, inlen) != OPENSSL_NPN_NEGOTIATED) {
                return SSL_TLSEXT_ERR_NOACK;
            }
            return SSL_TLSEXT_ERR_OK;
        }, NULL);
    } else {
        if (config.ssl_verify) {
            ssl_context.set_verify_mode(verify_peer);
            if (config.ca_certs == "") {
                ssl_context.set_default_verify_paths();
            } else {
                ssl_context.load_verify_file(config.ca_certs);
            }
            if (config.ssl_verify_hostname) {
                ssl_context.set_verify_callback(rfc2818_verification(config.remote_addr));
            }
        } else {
            ssl_context.set_verify_mode(verify_none);
        }
        SSL_CTX_set_alpn_protos(native_context, Service::alpn, sizeof(Service::alpn));
    }
}

int Service::run() {
    async_accept();
    Log::log_with_date_time(string("trojan service (") + (config.run_type == Config::SERVER ? "server" : "client") + ") started at " + config.local_addr + ':' + to_string(config.local_port), Log::FATAL);
    io_service.run();
    return 0;
}

void Service::async_accept() {
    shared_ptr<Session>session(nullptr);
    if (config.run_type == Config::SERVER) {
        session = make_shared<ServerSession>(config, io_service, ssl_context);
    } else {
        session = make_shared<ClientSession>(config, io_service, ssl_context);
    }
    socket_acceptor.async_accept(session->accept_socket(), [this, session](boost::system::error_code error) {
        if (!error) {
            Log::log_with_endpoint(session->accept_socket().remote_endpoint(), "incoming connection");
            session->start();
        }
        async_accept();
    });
}
