/*
 * This file is part of the trojan project.
 * Trojan is an unidentifiable mechanism that helps you bypass GFW.
 * Copyright (C) 2017-2020  The Trojan Authors.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifdef ENABLE_MYSQL
#include "mysql.h"
#include <cstdlib>
#include <stdexcept>
using namespace std;

MySQLAuthenticator::MySQLAuthenticator(const MySQLConfig &config) {
    mysql_init(&con);
    Log::log_with_date_time("connecting to MySQL server " + config.server_addr + ':' + to_string(config.server_port), Log::INFO);
    if (config.cafile != "") {
        mysql_ssl_set(&con, NULL, NULL, config.cafile.c_str(), NULL, NULL);
    }
    if (mysql_real_connect(&con, config.server_addr.c_str(),
                                 config.username.c_str(),
                                 config.password.c_str(),
                                 config.database.c_str(),
                                 config.server_port, NULL, 0) == NULL) {
        throw runtime_error(mysql_error(&con));
    }
    bool reconnect = 1;
    mysql_options(&con, MYSQL_OPT_RECONNECT, &reconnect);
    Log::log_with_date_time("connected to MySQL server", Log::INFO);
}

bool MySQLAuthenticator::auth(const string &password) {
    if (!is_valid_password(password)) {
        return false;
    }
    if (mysql_query(&con, ("SELECT quota, download + upload FROM users WHERE password = '" + password + '\'').c_str())) {
        Log::log_with_date_time(mysql_error(&con), Log::ERROR);
        return false;
    }
    MYSQL_RES *res = mysql_store_result(&con);
    if (res == NULL) {
        Log::log_with_date_time(mysql_error(&con), Log::ERROR);
        return false;
    }
    MYSQL_ROW row = mysql_fetch_row(res);
    if (row == NULL) {
        mysql_free_result(res);
        return false;
    }
    int64_t quota = atoll(row[0]);
    int64_t used = atoll(row[1]);
    mysql_free_result(res);
    if (quota < 0) {
        return true;
    }
    if (used >= quota) {
        Log::log_with_date_time(password + " ran out of quota", Log::WARN);
        return false;
    }
    return true;
}

void MySQLAuthenticator::record(const string &password, uint64_t download, uint64_t upload) {
    if (!is_valid_password(password)) {
        return;
    }
    if (mysql_query(&con, ("UPDATE users SET download = download + " + to_string(download) + ", upload = upload + " + to_string(upload) + " WHERE password = '" + password + '\'').c_str())) {
        Log::log_with_date_time(mysql_error(&con), Log::ERROR);
    }
}

bool MySQLAuthenticator::is_valid_password(const string &password) {
    if (password.size() != PASSWORD_LENGTH) {
        return false;
    }
    for (size_t i = 0; i < PASSWORD_LENGTH; ++i) {
        if (!((password[i] >= '0' && password[i] <= '9') || (password[i] >= 'a' && password[i] <= 'f'))) {
            return false;
        }
    }
    return true;
}

MySQLAuthenticator::~MySQLAuthenticator() {
    mysql_close(&con);
}

#endif // ENABLE_MYSQL
