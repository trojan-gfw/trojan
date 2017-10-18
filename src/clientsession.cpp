#include "clientsession.h"
#include <string>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include "log.h"
using namespace std;
using namespace boost::asio::ip;
using namespace boost::asio::ssl;

ClientSession::ClientSession(const Config &config, boost::asio::io_service &io_service, context &ssl_context) :
    Session(config, io_service),
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
            for (char i = 0; i < data[1] && i < data.length(); ++i) {
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
            if (data[0] != 5 or data[1] != 1 or data[2] != 0) {
                closing = true;
                in_send(string("\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00", 10));
                return;
            }
            in_send(string("\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00", 10));
            string req = string("\r\n") + data[1] + data.substr(3) + "\r\n";
            out_write_queue.push(config.password + req);
            tcp::resolver::query query(config.remote_addr, to_string(config.remote_port));
            resolver.async_resolve(query, [this](const boost::system::error_code error, tcp::resolver::iterator iterator) {
                if (!error) {
                    out_socket.lowest_layer().async_connect(*iterator, [this](const boost::system::error_code error) {
                        if (!error) {
                            out_socket.async_handshake(boost::asio::ssl::stream_base::client, [this](const boost::system::error_code error) {
                                if (!error) {
                                    status = FORWARD;
                                    out_async_read();
                                    out_async_write();
                                } else {
                                    destroy();
                                }
                            });
                        } else {
                            destroy();
                        }
                    });
                } else {
                    destroy();
                }
            });
            status = CONNECTING_REMOTE;
            break;
        }
        case CONNECTING_REMOTE: {
            out_write_queue.front() += data;
            break;
        }
        case FORWARD: {
            out_send(data);
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

void ClientSession::out_async_read() {
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

void ClientSession::out_async_write() {
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

void ClientSession::out_recv(const std::string &data) {
    in_send(data);
}

void ClientSession::out_send(const std::string &data) {
    out_write_queue.push(data);
    if (out_write_queue.size() == 1) {
        out_async_write();
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
