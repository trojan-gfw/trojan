#include <cstdlib>
#include <string>
#include "log.h"
#include "config.h"
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
    return 0;
}
