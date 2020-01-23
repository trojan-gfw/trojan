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

#ifndef _SSLSESSION_H_
#define _SSLSESSION_H_

#include <list>
#include <openssl/ssl.h>

class SSLSession {
private:
    static std::list<SSL_SESSION*>sessions;
    static int new_session_cb(SSL*, SSL_SESSION *session);
    static void remove_session_cb(SSL_CTX*, SSL_SESSION *session);
public:
    static SSL_SESSION *get_session();
    static void set_callback(SSL_CTX *context);
};

#endif // _SSLSESSION_H_
