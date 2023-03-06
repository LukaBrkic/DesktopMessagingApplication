#include "../inc/Connection.h"
#include "../inc/Cryptography.h"

#include <iostream>


typedef asio::ip::tcp::socket tcpSocket;

Connection::Connection(ThreadSafeQueue& serverMessageQueue, tcpSocket clientSocket, asio::io_context& asioContext) :
    m_clientSocket(std::move(clientSocket)),
    m_incomingMessageQueue(serverMessageQueue),
    m_asioContext(asioContext),
    m_connectionAsString("IP: " + m_clientSocket.remote_endpoint().address().to_string() + " PORT: " + std::to_string(m_clientSocket.remote_endpoint().port()))
{
    readMessageHeader();
}


void Connection::readMessageHeader()
{
    asio::async_read(m_clientSocket, asio::buffer(&m_tempMessage.messageSize, sizeof(m_tempMessage.messageSize)), 
        [this](const asio::error_code& ec, size_t a) {
            if (ec)
                std::cout << ec.message() << std::endl;
            else if (m_tempMessage.messageSize > 0)
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
            if (ec)
                std::cout << ec.message() << std::endl;
            else {
                readMessageBody();
            }
        }
    );
}

void Connection::readMessageBody()
{
    asio::async_read(m_clientSocket, asio::buffer(m_tempMessage.messageContent.data(), m_tempMessage.messageSize),
        [this](asio::error_code ec, size_t a) {
            if (ec)
                std::cout << ec.message() << std::endl;
            pushMessageToClientQueue();
            readMessageHeader();
        }
    );
}

void Connection::sendMessage(const Message& message)
{
    Message encryptedMessage = Cryptography::encryptAndSign(message, m_aesKey, m_aesInitVector);
    asio::post(m_asioContext, 
        [this, encryptedMessage]()
        {
            bool hasMessage = !m_outgoingMessageQueue.empty();
            m_outgoingMessageQueue.insertBack(encryptedMessage);
            if (!hasMessage) {
                sendMessageHeader();
            }
        }
    );
}


void Connection::sendMessageHeader()
{
    asio::async_write(m_clientSocket, asio::buffer(&m_outgoingMessageQueue.front().messageSize, sizeof(m_outgoingMessageQueue.front().messageSize)), 
        [this](const asio::error_code& ec, size_t a) {
            if (ec)
                std::cout << ec.message() << std::endl;
            sendMessageType();
        });
}

void Connection::sendMessageType()
{
    asio::async_write(m_clientSocket, asio::buffer(&m_outgoingMessageQueue.front().messageType, sizeof(m_outgoingMessageQueue.front().messageType)),
        [this](const asio::error_code& ec, size_t a) {
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
            if (ec)
                std::cout << ec.message() << std::endl;
            else
            {
            }

            m_outgoingMessageQueue.popFront();
        }
    );
}

void Connection::pushMessageToClientQueue()
{
    m_tempMessage.sourceConnection = this;
    m_tempMessage.sourceConnection->m_connectionAsString = m_connectionAsString;
    m_incomingMessageQueue.insertBack(m_tempMessage);

}

void Connection::setAesKey(const std::string& aesKey)
{
    m_aesKey = aesKey;
}

void Connection::setAesInitVector(const std::string& aesInitVector)
{
    m_aesInitVector = aesInitVector;
}


void Connection::setRSAKey(const std::string& rsaKey)
{
    m_rsaKey = rsaKey;
}

void Connection::setUsername(const std::string& username)
{
    m_clientUsername = username;
}



const std::string& Connection::getUsername() const
{
    return m_clientUsername;
}

const std::string& Connection::getAesKey() const
{
    return m_aesKey;
}

const std::string& Connection::getAesInitVector() const
{
    return m_aesInitVector;
}

const std::string& Connection::getRSAKey() const
{
    return m_rsaKey;
}

std::string Connection::toString() const
{
    return m_connectionAsString;
}

void Connection::displayClientInfo()
{
    std::cout << std::endl;
    std::cout << "user info: ";
    std::cout << m_clientUsername << " ";
    std::cout << m_clientSocket.remote_endpoint().address() << " ";
    std::cout << m_clientSocket.remote_endpoint().port() << " ";
    std::cout << std::endl;
}


