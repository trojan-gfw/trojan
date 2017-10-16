#include "service.h"
#include <string>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include "config.h"
#include "log.h"
#include "session.h"
#include "serversession.h"
#include "clientsession.h"
using namespace boost::asio::ip;
using boost::asio::ip::tcp;
using namespace boost::asio::ssl;
using namespace std;

Service::Service(const Config &config) : config(config),
                                         socket_acceptor(io_service, tcp::endpoint(address::from_string(config.local_addr), config.local_port)),
                                         ssl_context(context::sslv23) {
    if (config.run_type == Config::SERVER) {
        ssl_context.set_options(context::default_workarounds |
                                context::no_sslv2);
        ssl_context.set_password_callback([this](size_t, context_base::password_purpose) {
            return this->config.keyfile_password;
        });
        ssl_context.use_certificate_chain_file(config.certfile);
        ssl_context.use_private_key_file(config.keyfile, context::pem);
    } else {
        if (config.ssl_verify) {
            ssl_context.set_verify_mode(verify_peer);
            ssl_context.set_default_verify_paths();
            if (config.ca_certs != "") {
                ssl_context.load_verify_file(config.ca_certs);
            }
        } else {
            ssl_context.set_verify_mode(verify_none);
        }
    }
}

int Service::run() {
    async_accept();
    Log::log_with_date_time(string("trojan service (") + (config.run_type == Config::SERVER ? "server" : "client") + ") started at " + config.local_addr + ':' + to_string(config.local_port));
    io_service.run();
    return 0;
}

void Service::async_accept() {
    Session *session = nullptr;
    if (config.run_type == Config::SERVER) {
        session = new ServerSession(config, io_service, ssl_context);
    } else {
        session = new ClientSession(config, io_service, ssl_context);
    }
    socket_acceptor.async_accept(session->accept_socket(), [this, session](boost::system::error_code error) {
        if (!error) {
            auto endpoint = session->accept_socket().remote_endpoint();
            Log::log_with_date_time("incoming connection from " + endpoint.address().to_string() + ':' + to_string(endpoint.port()));
            session->start();
        } else {
            delete session;
        }
        async_accept();
    });
}
