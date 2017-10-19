#include <cstdlib>
#include <string>
#include "log.h"
#include "config.h"
#include "service.h"
#include "version.h"
using namespace std;

int main(int argc, const char *argv[]) {
    puts(("Welcome to trojan " + Version::get_version()).c_str());
    if (argc != 2) {
        Log::log(string("usage: ") + argv[0] + " config_file");
        exit(1);
    }
    Config config;
    try {
        config.load(argv[1]);
        Service service(config);
        return service.run();
    } catch (const exception &e) {
        Log::log_with_date_time(string("fatal: ") + e.what());
        Log::log_with_date_time("exiting. . . ");
        exit(1);
    }
}
