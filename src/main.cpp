#include <cstdlib>
#include <string>
#include "log.h"
#include "config.h"
#include "service.h"
using namespace std;

int main(int argc, const char *argv[]) {
    if (argc != 2) {
        Log::log(string("usage: ") + argv[0] + " config_file");
        exit(1);
    }
    Config config;
    try {
        config.load(argv[1]);
    } catch (const exception &e) {
        Log::log_with_date_time(string("fatal: ") + e.what());
        Log::log_with_date_time("exiting. . . ");
        exit(1);
    }
    try {
        Service service(config);
        return service.run();
    } catch (const exception &e) {
        Log::log_with_date_time(string("fatal: ") + e.what());
        Log::log_with_date_time("exiting. . . ");
        exit(1);
    }
}
