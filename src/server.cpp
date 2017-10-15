#include "server.h"
#include "config.h"

Server::Server(const Config &config) : Service(config) {}

int Server::run() {
    return 0;
}
