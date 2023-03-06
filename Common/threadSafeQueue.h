#pragma once

#include <deque>
#include <mutex>
#include <iostream>

#include "netMessage.h"

class ThreadSafeQueue {

public:
	void insertFront(const Message& message)
	{
		std::scoped_lock lock(messageMutex);
		m_threadSafeQueue.emplace_front(message);
	}

	void insertBack(const Message& message)
	{
		std::scoped_lock lock(messageMutex);
		m_threadSafeQueue.emplace_back(message);
	}

	Message popBack()
	{
		std::scoped_lock lock(messageMutex);
		Message m(m_threadSafeQueue.back());
		m_threadSafeQueue.pop_back();
		return m;
	}

	Message popFront()
	{
		std::scoped_lock lock(messageMutex);
		if (m_threadSafeQueue.empty())
		{
			exit(1);
		}
		else
		{
			Message m(m_threadSafeQueue.front());
			m_threadSafeQueue.pop_front();
			return m;
		}

	}

	const Message& front()
	{
		std::scoped_lock lock(messageMutex);
		if (m_threadSafeQueue.empty())
		{
			exit(1);
		}
		return m_threadSafeQueue.front();
	}

	bool empty()
	{
		std::scoped_lock lock(messageMutex);
		return m_threadSafeQueue.empty();
	}

	size_t count()
	{
		std::scoped_lock lock(messageMutex);
		return m_threadSafeQueue.size();
	}

	void clear()
	{
		std::scoped_lock lock(messageMutex);
		m_threadSafeQueue.clear();
	}

private:
	std::mutex messageMutex;
	std::deque<Message> m_threadSafeQueue;
};