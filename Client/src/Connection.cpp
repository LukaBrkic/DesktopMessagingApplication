#include "../inc/Connection.h"
#include "../inc/Client.h"

#include <iostream>

typedef asio::ip::tcp::socket tcpSocket;

//std::unordered_map<MessageType, std::function<void(Message&, tcpSocket&)>> Connection::readMessageBody = 
//{ 
//    {MessageType::Login, Connection::readLoginMessage},
//    {MessageType::Registration, Connection::readRegistrationMessage},
//    {MessageType::TextMessage, Connection::readTextMessage} 
//};


Connection::Connection(ThreadSafeQueue& clientMessageQueue, tcpSocket clientSocket, asio::io_context& asioContext, Client& client) :
    m_clientSocket(std::move(clientSocket)),
    m_incomingMessageQueue(clientMessageQueue),
    m_asioContext(asioContext),
    m_client(client)
{
}

void Connection::connectToServer(const asio::ip::tcp::resolver::results_type& serverEndpoints)
{
    asio::async_connect(m_clientSocket, serverEndpoints, 
        [this, &serverEndpoints](const asio::error_code& ec, asio::ip::tcp::endpoint endpoint) 
        {
            if (!ec)
            {
                readMessageHeader();
            }
            else {
                std::cout << "Couldn't connect to server." << std::endl;
                connectToServer(serverEndpoints);
                // add loading animation
                // try to connect to server every 2 seconds
            }

        }
    );
}

void Connection::readMessageHeader()
{
    std::cout << "reading message header" << std::endl;
    asio::async_read(m_clientSocket, asio::buffer(&m_tempMessage.messageSize, sizeof(m_tempMessage.messageSize)), 
        [this](const asio::error_code& ec, size_t a) {
            std::cout << "read Message header" << m_tempMessage.messageSize << std::endl;
            if (ec)
            {
                std::cout << ec.value() << std::endl;
                std::cout << ec.message() << std::endl;

            }
            else if (m_tempMessage.messageSize > 0 || m_tempMessage.messageType != MessageType::TextMessage)
            {
                m_tempMessage.messageContent.resize(m_tempMessage.messageSize);
                readMessageType();
            }
        }
    );
}

void Connection::readMessageType()
{
    asio::async_read(m_clientSocket, asio::buffer(&m_tempMessage.messageType, sizeof(m_tempMessage.messageType)),
        [this](const asio::error_code& ec, size_t a) {
            std::cout << "Type: " << static_cast<int>(m_tempMessage.messageType) << std::endl;
            if (ec)
                std::cout << ec.message() << std::endl;
            else
                readMessageBody();
                //readMessageBody[m_tempMessage.messageType](m_tempMessage, m_clientSocket);
        }
    );
}

void Connection::readMessageBody()
{
    asio::async_read(m_clientSocket, asio::buffer(m_tempMessage.messageContent.data(), m_tempMessage.messageSize),
        [this](asio::error_code ec, size_t a) {
            if (ec)
                std::cout << ec.message() << std::endl;
            std::cout << m_clientSocket.remote_endpoint() << std::endl;
            std::cout << "Read message body"  << std::endl;
            pushMessageToClientQueue();
            readMessageHeader();
        }
    );
}

void Connection::sendMessage(const Message& message)
{
    bool hasMessage = !m_outgoingMessageQueue.empty();
    m_outgoingMessageQueue.insertBack(message);
    if (!hasMessage) {
        sendMessageHeader();
    }
}


void Connection::sendMessageHeader()
{
    asio::async_write(m_clientSocket, asio::buffer(&m_outgoingMessageQueue.front().messageSize, sizeof(m_outgoingMessageQueue.front().messageSize)), 
        [this](const asio::error_code& ec, size_t a) {
            std::cout << "header bytes sent: " << a << std::endl;
            if (ec)
                std::cout << ec.message() << std::endl;
            sendMessageType();
        });
}

void Connection::sendMessageType()
{
    asio::async_write(m_clientSocket, asio::buffer(&m_outgoingMessageQueue.front().messageType, sizeof(m_outgoingMessageQueue.front().messageType)),
        [this](const asio::error_code& ec, size_t a) {
            std::cout << "sent Type: " << static_cast<int>(m_outgoingMessageQueue.front().messageType) << std::endl;
            if (ec)
                std::cout << ec.message() << std::endl;
            else
                sendMessageBody();
        }
    );
}

void Connection::sendMessageBody()
{
    asio::async_write(m_clientSocket, asio::buffer(m_outgoingMessageQueue.front().messageContent.data(), m_outgoingMessageQueue.front().messageSize),
        [this](const asio::error_code& ec, size_t a) {
            std::cout << "sent message body" << std::endl;
            if (ec)
                std::cout << ec.message() << std::endl;
            m_outgoingMessageQueue.popFront();
        }
    );
}


void Connection::pushMessageToClientQueue()
{
    std::cout << "uslo pushMessageToClientQueue" << std::endl;
    m_tempMessage.sourceConnection = this;
    m_incomingMessageQueue.insertBack(m_tempMessage);
}



