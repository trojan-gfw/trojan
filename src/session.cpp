#include "session.h"
#include <boost/asio.hpp>

Session::Session(const Config &config, boost::asio::io_service &io_service) : config(config),
                                                                              closing(false),
                                                                              destroying(false),
                                                                              resolver(io_service) {}
