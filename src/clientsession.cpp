#include "clientsession.h"
#include <string>
#include <boost/asio.hpp>
#include "log.h"
using namespace boost::asio::ip;
using boost::asio::ip::tcp;
using namespace std;

ClientSession::ClientSession(const Config &config, boost::asio::io_service &io_service) : Session(config, io_service), in_socket(io_service) {}

tcp::socket& ClientSession::accept_socket() {
    return in_socket;
}

void ClientSession::start() {
    Log::log_with_date_time("incoming connection from " + in_socket.remote_endpoint().address().to_string() + ':' + to_string(in_socket.remote_endpoint().port()));
    in_async_read();
}

void ClientSession::in_async_read() {
    in_socket.async_read_some(boost::asio::buffer(in_buffer, MAX_LENGTH), [this](boost::system::error_code error, size_t length) {
        if (!error) {
            in_async_write(length);
        } else {
            Log::log_with_date_time(in_socket.remote_endpoint().address().to_string() + ':' + to_string(in_socket.remote_endpoint().port()) + " closed the connection");
            in_socket.close();
            delete this;
        }
    });
}

void ClientSession::in_async_write(size_t length) {
    boost::asio::async_write(in_socket, boost::asio::buffer(in_buffer, length), [this](boost::system::error_code error, size_t) {
        if (!error) {
            in_async_read();
        } else {
            in_socket.close();
            delete this;
        }
    });
}
