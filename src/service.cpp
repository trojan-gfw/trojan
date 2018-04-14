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

#include "service.h"
#include "serversession.h"
#include "clientsession.h"
#include "ssldefaults.h"
using namespace std;
using namespace boost::asio::ip;
using namespace boost::asio::ssl;

Service::Service(Config &config) :
    config(config),
    socket_acceptor(io_service, tcp::endpoint(address::from_string(config.local_addr), config.local_port)),
    ssl_context(context::sslv23) {
    Log::level = config.log_level;
    auto native_context = ssl_context.native_handle();
    if (config.ssl.sigalgs != "") {
        SSL_CONF_CTX *cctx = SSL_CONF_CTX_new();
        SSL_CONF_CTX_set_ssl_ctx(cctx, native_context);
        SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_CMDLINE);
        if (config.run_type == Config::SERVER) {
            SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_SERVER);
        } else {
            SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_CLIENT);
        }
        SSL_CONF_cmd(cctx, "-sigalgs", config.ssl.sigalgs.c_str());
        SSL_CONF_CTX_finish(cctx);
        SSL_CONF_CTX_free(cctx);
    }
    ssl_context.set_options(context::default_workarounds | context::no_sslv2 | context::no_sslv3 | context::single_dh_use);
    if (config.ssl.curves != "") {
        SSL_CTX_set1_curves_list(native_context, config.ssl.curves.c_str());
    }
    if (config.run_type == Config::SERVER) {
        ssl_context.use_certificate_chain_file(config.ssl.cert);
        ssl_context.set_password_callback([this](size_t, context_base::password_purpose) {
            return this->config.ssl.key_password;
        });
        ssl_context.use_private_key_file(config.ssl.key, context::pem);
        if (config.ssl.prefer_server_cipher) {
            SSL_CTX_set_options(native_context, SSL_OP_CIPHER_SERVER_PREFERENCE);
        }
        if (config.ssl.alpn != "") {
            SSL_CTX_set_alpn_select_cb(native_context, [](SSL*, const unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *config) -> int {
                if (SSL_select_next_proto((unsigned char**)out, outlen, (unsigned char*)(((Config*)config)->ssl.alpn.c_str()), ((Config*)config)->ssl.alpn.length(), in, inlen) != OPENSSL_NPN_NEGOTIATED) {
                    return SSL_TLSEXT_ERR_NOACK;
                }
                return SSL_TLSEXT_ERR_OK;
            }, &config);
        }
        if (config.ssl.reuse_session) {
            SSL_CTX_set_timeout(native_context, config.ssl.session_timeout);
        } else {
            SSL_CTX_set_session_cache_mode(native_context, SSL_SESS_CACHE_OFF);
            SSL_CTX_set_options(native_context, SSL_OP_NO_TICKET);
        }
        if (config.ssl.dhparam == "") {
            ssl_context.use_tmp_dh(boost::asio::const_buffer(SSLDefaults::g_dh2048_sz, SSLDefaults::g_dh2048_sz_size));
        } else {
            ssl_context.use_tmp_dh_file(config.ssl.dhparam);
        }
        SSL_CTX_set_ecdh_auto(native_context, 1);
    } else {
        if (config.ssl.verify) {
            ssl_context.set_verify_mode(verify_peer);
            if (config.ssl.cert == "") {
                ssl_context.set_default_verify_paths();
            } else {
                ssl_context.load_verify_file(config.ssl.cert);
            }
            if (config.ssl.verify_hostname) {
                ssl_context.set_verify_callback(rfc2818_verification(config.ssl.sni));
            }
        } else {
            ssl_context.set_verify_mode(verify_none);
        }
        if (config.ssl.alpn != "") {
            SSL_CTX_set_alpn_protos(native_context, (unsigned char*)(config.ssl.alpn.c_str()), config.ssl.alpn.length());
        }
    }
    if (config.ssl.cipher != "") {
        SSL_CTX_set_cipher_list(native_context, config.ssl.cipher.c_str());
    }
}

void Service::run() {
    async_accept();
    tcp::endpoint local_endpoint = socket_acceptor.local_endpoint();
    Log::log_with_date_time(string("trojan service (") + (config.run_type == Config::SERVER ? "server" : "client") + ") started at " + local_endpoint.address().to_string() + ':' + to_string(local_endpoint.port()), Log::FATAL);
    io_service.run();
    Log::log_with_date_time("trojan service stopped", Log::FATAL);
}

void Service::stop() {
    io_service.stop();
}

void Service::async_accept() {
    shared_ptr<Session>session(nullptr);
    if (config.run_type == Config::SERVER) {
        session = make_shared<ServerSession>(config, io_service, ssl_context);
    } else {
        session = make_shared<ClientSession>(config, io_service, ssl_context);
    }
    socket_acceptor.async_accept(session->accept_socket(), [this, session](const boost::system::error_code error) {
        if (!error) {
            boost::system::error_code ec;
            auto endpoint = session->accept_socket().remote_endpoint(ec);
            if (!ec) {
                Log::log_with_endpoint(endpoint, "incoming connection");
                session->start_time = time(NULL);
                session->start();
            }
        }
        async_accept();
    });
}
