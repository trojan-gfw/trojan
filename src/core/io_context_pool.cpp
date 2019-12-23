/*
 * This file is part of the trojan project.
 * Trojan is an unidentifiable mechanism that helps you bypass GFW.
 * Copyright (C) 2017-2019  GreaterFire
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
#include <stdexcept>
#include <thread>
#include "io_context_pool.h"

io_context_pool::io_context_pool(std::size_t pool_size)
  : next_io_context_(0)
{
  if (pool_size == 0)
    throw std::runtime_error("io_context_pool size is 0");

  // Give all the io_contexts work to do so that their run() functions will not
  // exit until they are explicitly stopped.
  for (std::size_t i = 0; i < pool_size; ++i)
  {
    io_context_ptr io_context(new boost::asio::io_context);
    io_contexts_.push_back(io_context);
    work_.push_back(boost::asio::make_work_guard(*io_context));
  }
}

void io_context_pool::run()
{
  // Create a pool of threads to run all of the io_contexts.
  std::vector<std::shared_ptr<std::thread> > threads;
  for (unsigned int i = 0; i < io_contexts_.size(); ++i)
  {
      std::shared_ptr<std::thread> thread(new std::thread([this,i]{
                  io_contexts_[i]->run();
                  }));
    threads.push_back(thread);
  }

  // Wait for all threads in the pool to exit.
  for (std::size_t i = 0; i < threads.size(); ++i)
    threads[i]->join();
}

void io_context_pool::stop()
{
  // Explicitly stop all io_contexts.
  for (std::size_t i = 0; i < io_contexts_.size(); ++i)
    io_contexts_[i]->stop();
}

boost::asio::io_context& io_context_pool::get_io_context()
{
  // Use a round-robin scheme to choose the next io_context to use.
  boost::asio::io_context& io_context = *io_contexts_[next_io_context_];
  ++next_io_context_;
  if (next_io_context_ == io_contexts_.size())
    next_io_context_ = 0;
  return io_context;
}

