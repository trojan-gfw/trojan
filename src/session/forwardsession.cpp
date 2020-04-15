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

#include "forwardsession.h"
using namespace std;
using namespace boost::asio::ssl;

ForwardSession::ForwardSession(const Config &config, boost::asio::io_context &io_context, context &ssl_context) :
    NATSession(config, io_context, ssl_context){}

pair<string, uint16_t> ForwardSession::get_target_endpoint() {
    return make_pair(config.target_addr, config.target_port);
}
