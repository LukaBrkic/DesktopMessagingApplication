#pragma once

#include <asio.hpp>
#include <unordered_map>
#include <functional>

#include "../../Common/netMessage.h"
#include "../../Common/threadSafeQueue.h"

class Connection
{
public:
	typedef asio::ip::tcp::socket tcpSocket;

	Connection(ThreadSafeQueue& serverMessageQueue, tcpSocket clientSocket, asio::io_context& m_asioContext);
	
	void sendMessage(const Message& message);
	void setUsername(const std::string& username);
	void setAesKey(const std::string& aesKey);
	void setAesInitVector(const std::string& aesInitVector);
	void setRSAKey(const std::string& rsaKey);
	void displayClientInfo();

	const std::string& getUsername() const;
	const std::string& getAesKey() const;
	const std::string& getAesInitVector() const;
	const std::string& getRSAKey() const;

	std::string toString() const;

private:
	void sendMessageHeader();
	void sendMessageType();
	void sendMessageBody();

	void readMessageHeader();
	void readMessageType();
	void readMessageBody();
	void pushMessageToClientQueue();

private:
	asio::io_context& m_asioContext;
	asio::ip::tcp::socket m_clientSocket;
	ThreadSafeQueue m_outgoingMessageQueue; // messages from server to client
	ThreadSafeQueue& m_incomingMessageQueue; // messages from clients to server
	Message m_tempMessage;
	std::string m_clientUsername;
	std::string m_connectionAsString;
	std::string m_aesKey;
	std::string m_aesInitVector;
	std::string m_rsaKey;
};

