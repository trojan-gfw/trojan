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

#include "sslsession.h"
using namespace std;

list<SSL_SESSION*>SSLSession::sessions;

int SSLSession::new_session_cb(SSL*, SSL_SESSION *session) {
    sessions.push_front(session);
    return 0;
}

void SSLSession::remove_session_cb(SSL_CTX*, SSL_SESSION *session) {
    sessions.remove(session);
}

SSL_SESSION *SSLSession::get_session() {
    if (sessions.empty()) {
        return nullptr;
    }
    return sessions.front();
}

void SSLSession::set_callback(SSL_CTX *context) {
    SSL_CTX_sess_set_new_cb(context, new_session_cb);
    SSL_CTX_sess_set_remove_cb(context, remove_session_cb);
}
