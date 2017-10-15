#include <cstdlib>
#include <string>
#include "log.h"
#include "config.h"
#include "service.h"
#include "server.h"
#include "client.h"
using namespace std;

int main(int argc, char const *argv[]) {
    if (argc != 2) {
        Log::log(string("usage: ") + argv[0] + " config_file");
        exit(1);
    }
    Config config;
    if (!config.load(argv[1])) {
        Log::log_with_date_time(string("fatal: unable to load config file: ") + argv[1]);
        Log::log_with_date_time("exiting. . . ");
        exit(1);
    }
    Service *service = nullptr;
    if (config.run_type == Config::SERVER) {
        service = new Server(config);
    } else {
        service = new Client(config);
    }
    int ret = service->run();
    delete service;
    service = nullptr;
    return ret;
}
