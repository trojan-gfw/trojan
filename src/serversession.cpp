#include "serversession.h"
#include <boost/asio.hpp>
using namespace boost::asio::ip;
using boost::asio::ip::tcp;

ServerSession::ServerSession(const Config &config, boost::asio::io_service &io_service) : Session(config, io_service) {}

tcp::socket& ServerSession::socket() {

}

void ServerSession::start() {

}
