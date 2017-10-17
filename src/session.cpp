#include "session.h"
#include <boost/asio.hpp>

Session::Session(const Config &config) : config(config),
                                         closing(false),
                                         destroying(false) {}
