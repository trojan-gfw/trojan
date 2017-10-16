#include "serversession.h"
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
using namespace boost::asio::ip;
using boost::asio::ip::tcp;
using namespace boost::asio::ssl;

ServerSession::ServerSession(const Config &config, boost::asio::io_service &io_service, context &ssl_context) : Session(config, io_service) {}

tcp::socket& ServerSession::accept_socket() {

}

void ServerSession::start() {

}
