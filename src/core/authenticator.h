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

#ifndef _AUTHENTICATOR_H_
#define _AUTHENTICATOR_H_

#ifdef ENABLE_MYSQL
#include <mysql.h>
#endif // ENABLE_MYSQL
#include "config.h"

class Authenticator {
private:
#ifdef ENABLE_MYSQL
    MYSQL con{};
#endif // ENABLE_MYSQL
    enum {
        PASSWORD_LENGTH=56
    };
    static bool is_valid_password(const std::string &password);
public:
    explicit Authenticator(const Config &config);
    bool auth(const std::string &password);
    void record(const std::string &password, uint64_t download, uint64_t upload);
    ~Authenticator();
};

#endif // _AUTHENTICATOR_H_
