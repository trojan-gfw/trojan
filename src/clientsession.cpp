#include "clientsession.h"
#include <string>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include "log.h"
using namespace std;
using namespace boost::asio::ip;
using namespace boost::asio::ssl;

ClientSession::ClientSession(const Config &config, boost::asio::io_service &io_service, context &ssl_context) :
    Session(config),
    in_socket(io_service),
    out_socket(io_service, ssl_context),
    status(HANDSHAKE) {}

boost::asio::basic_socket<tcp, boost::asio::stream_socket_service<tcp> >& ClientSession::accept_socket() {
    return in_socket;
}

void ClientSession::start() {
    in_async_read();
}

void ClientSession::in_async_read() {
    in_socket.async_read_some(boost::asio::buffer(in_read_buf, MAX_LENGTH), [this](const boost::system::error_code &error, size_t length) {
        if (!error) {
            in_recv(string((const char*)in_read_buf, length));
            in_async_read();
        } else {
            if (out_write_queue.empty()) {
                destroy();
            } else {
                closing = true;
            }
        }
    });
}

void ClientSession::in_async_write() {
    boost::asio::async_write(in_socket, boost::asio::buffer(in_write_queue.front()), [this](boost::system::error_code error, std::size_t) {
        if (!error) {
            in_write_queue.pop();
            if (in_write_queue.size() > 0) {
                in_async_write();
            } else if (closing) {
                destroy();
            }
        } else {
            destroy();
        }
    });
}

void ClientSession::in_recv(const string &data) {
    switch (status) {
        case HANDSHAKE: {
            if (data[0] != 5) {
                destroy();
                return;
            }
            bool ok = false;
            for (char i = 0; i < data[1]; ++i) {
                if (data[i + 2] == 0) {
                    ok = true;
                    break;
                }
            }
            if (!ok) {
                closing = true;
                in_send(string("\x05\xff", 2));
                return;
            }
            in_send(string("\x05\x00", 2));
            status = REQUEST;
            break;
        }
        case REQUEST: {
            break;
        }
        case FORWARD: {
            break;
        }
    }
}

void ClientSession::in_send(const string &data) {
    in_write_queue.push(data);
    if (in_write_queue.size() == 1) {
        in_async_write();
    }
}

void ClientSession::destroy() {
    if (destroying) {
        return;
    }
    destroying = true;
    in_socket.shutdown(tcp::socket::shutdown_both);
    in_socket.close();
    out_socket.async_shutdown([this](boost::system::error_code error) {
        delete this;
    });
}
