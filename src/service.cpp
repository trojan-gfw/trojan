#include "service.h"
#include <string>
#include <boost/asio.hpp>
#include "config.h"
#include "log.h"
#include "session.h"
#include "serversession.h"
#include "clientsession.h"
using namespace boost::asio::ip;
using boost::asio::ip::tcp;
using namespace std;

Service::Service(const Config &config) : config(config),
                                         socket_acceptor(io_service, tcp::endpoint(address::from_string(config.local_addr), config.local_port)) {}

int Service::run() {
    async_accept();
    Log::log_with_date_time(string("trojan service (") + (config.run_type == Config::SERVER ? "server" : "client") + ") started at " + config.local_addr + ':' + to_string(config.local_port));
    io_service.run();
    return 0;
}

void Service::async_accept() {
    Session *session = nullptr;
    if (config.run_type == Config::SERVER) {
        session = new ServerSession(config, io_service);
    } else {
        session = new ClientSession(config, io_service);
    }
    socket_acceptor.async_accept(session->socket(), [this, session](boost::system::error_code error) {
        if (!error) {
            session->start();
        } else {
            delete session;
        }
        async_accept();
    });
}
