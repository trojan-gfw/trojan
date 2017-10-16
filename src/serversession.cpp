#include "serversession.h"
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
using namespace boost::asio::ip;
using boost::asio::ip::tcp;
using namespace boost::asio::ssl;

ServerSession::ServerSession(const Config &config, boost::asio::io_service &io_service, context &ssl_context) : Session(config, io_service),
                                     in_socket(io_service, ssl_context) {}

boost::asio::basic_socket<tcp, boost::asio::stream_socket_service<tcp> >& ServerSession::accept_socket() {
    return in_socket.lowest_layer();
}

void ServerSession::start() {
    delete this;
}
