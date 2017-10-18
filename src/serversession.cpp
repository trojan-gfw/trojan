#include "serversession.h"
#include <string>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
using namespace std;
using namespace boost::asio::ip;
using namespace boost::asio::ssl;

ServerSession::ServerSession(const Config &config, boost::asio::io_service &io_service, context &ssl_context) :
    Session(config, io_service),
    in_socket(io_service, ssl_context),
    out_socket(io_service),
    status(HANDSHAKE) {}

boost::asio::basic_socket<tcp, boost::asio::stream_socket_service<tcp> >& ServerSession::accept_socket() {
    return in_socket.lowest_layer();
}

void ServerSession::start() {
    in_socket.async_handshake(boost::asio::ssl::stream_base::server, [this](const boost::system::error_code error) {
        if (!error) {
            in_async_read();
        } else {
            destroy();
        }
    });
}

void ServerSession::in_async_read() {
    in_socket.async_read_some(boost::asio::buffer(in_read_buf, MAX_LENGTH), [this](const boost::system::error_code error, size_t length) {
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

void ServerSession::in_async_write() {
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

void ServerSession::in_recv(const string &data) {
    switch (status) {
        case HANDSHAKE: {
            size_t first = data.find("\r\n");
            if (first != string::npos) {
                if (config.password == data.substr(0, first)) {
                    size_t second = data.find("\r\n", first + 2);
                    if (second != string::npos) {
                        string req = data.substr(first + 2, second - first - 2);
                        destroy();
                        return;
                    }
                }
            }
            destroy();
            break;
        }
        case CONNECTING_REMOTE: {
            out_write_queue.push(data);
            break;
        }
        case FORWARD: {
            out_send(data);
            break;
        }
    }
}

void ServerSession::in_send(const string &data) {
    in_write_queue.push(data);
    if (in_write_queue.size() == 1) {
        in_async_write();
    }
}

void ServerSession::out_async_read() {
    out_socket.async_read_some(boost::asio::buffer(out_read_buf, MAX_LENGTH), [this](const boost::system::error_code error, size_t length) {
        if (!error) {
            out_recv(string((const char*)out_read_buf, length));
            out_async_read();
        } else {
            if (in_write_queue.empty()) {
                destroy();
            } else {
                closing = true;
            }
        }
    });
}

void ServerSession::out_async_write() {
    boost::asio::async_write(out_socket, boost::asio::buffer(out_write_queue.front()), [this](boost::system::error_code error, std::size_t) {
        if (!error) {
            out_write_queue.pop();
            if (out_write_queue.size() > 0) {
                out_async_write();
            } else if (closing) {
                destroy();
            }
        } else {
            destroy();
        }
    });
}

void ServerSession::out_recv(const std::string &data) {
    in_send(data);
}

void ServerSession::out_send(const std::string &data) {
    out_write_queue.push(data);
    if (out_write_queue.size() == 1) {
        out_async_write();
    }
}

void ServerSession::destroy() {
    if (destroying) {
        return;
    }
    destroying = true;
    resolver.cancel();
    if (out_socket.is_open()) {
        out_socket.cancel();
        boost::system::error_code error;
        out_socket.shutdown(tcp::socket::shutdown_both, error);
        out_socket.close();
    }
    if (in_socket.lowest_layer().is_open()) {
        in_socket.lowest_layer().cancel();
        in_socket.async_shutdown([this](boost::system::error_code error) {
            delete this;
        });
        return;
    }
    delete this;
}
