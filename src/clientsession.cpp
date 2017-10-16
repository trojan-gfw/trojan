#include "clientsession.h"
#include <string>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include "log.h"
using namespace boost::asio::ip;
using namespace boost::asio::ssl;

ClientSession::ClientSession(const Config &config, boost::asio::io_service &io_service, context &ssl_context) :
    Session(config),
    in_socket(io_service),
    out_socket(io_service, ssl_context) {}

boost::asio::basic_socket<tcp, boost::asio::stream_socket_service<tcp> >& ClientSession::accept_socket() {
    return in_socket;
}

void ClientSession::start() {
    delete this;
}
