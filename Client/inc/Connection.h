#pragma once

#include <asio.hpp>
#include <unordered_map>
#include <functional>

#include "../../Common/netMessage.h"
#include "../../Common/threadSafeQueue.h"

class Client;

class Connection
{
public:
	typedef asio::ip::tcp::socket tcpSocket;

	Connection(ThreadSafeQueue& serverMessageQueue, tcpSocket clientSocket, asio::io_context& m_asioContext, Client& client);
	void sendMessage(const Message& message);
	void connectToServer(const asio::ip::tcp::resolver::results_type& serverEndpoints);
	bool connectedToServer();

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
	ThreadSafeQueue m_outgoingMessageQueue; // messages from client to server
	ThreadSafeQueue& m_incomingMessageQueue; // messages from server to client
	Message m_tempMessage;
	Client& m_client;
};

