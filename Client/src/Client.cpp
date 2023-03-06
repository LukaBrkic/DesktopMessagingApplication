#include "../inc/Client.h"
#include "../inc/ClientApp.h"
#include "../inc/Cryptography.h"

#include <chrono>
#include <osrng.h>

using namespace std::chrono_literals;



Client::Client(const std::string& serverIP, unsigned short serverPort, ClientApp& clientApp) :
    m_serverIP(serverIP),
    m_serverPort(serverPort),
    m_clientApp(clientApp)
{
}

void Client::start()
{
    m_started = true;
    try {
        m_connection = std::make_unique<Connection>(m_incomingQueue, std::move(asio::ip::tcp::socket{ m_asioIOContext }), m_asioIOContext, *this);
    }
    catch (const std::exception& e)
    {
        std::cout << e.what() << std::endl;
    }
    asio::ip::tcp::resolver resolver(m_asioIOContext);
    asio::ip::tcp::resolver::results_type endpoints = resolver.resolve(m_serverIP, std::to_string(m_serverPort));
    
    m_connection->connectToServer(endpoints);
    Cryptography::loadRSAKeys();
    Cryptography::generateAESKey();
    sendPublicKey();
    m_asioExecutionCompletionThread = std::thread([&] {m_asioIOContext.run(); });
    update();
}

void Client::sendRegistrationMessage(std::string&& username, 
                                     std::string&& secretWord, 
                                     std::string&& password, 
                                     std::string&& repeatPassword)
{
    std::string message = username + ";";
    message += password + ";";
    message +=  repeatPassword + ";";
    message += secretWord + ";";
    Cryptography::encryptAndSign(message, MessageType::Registration);
    m_connection->sendMessage(Message(message, MessageType::Registration));
}

void Client::sendResetPasswordMessage(std::string&& username,
    std::string&& secretWord,
    std::string&& newPassword,
    std::string&& newPasswordRepeat)
{
    std::string message = username + ";";
    message += newPassword + ";";
    message += newPasswordRepeat + ";";
    message += secretWord + ";";
    Cryptography::encryptAndSign(message, MessageType::ResetPassword);
    m_connection->sendMessage(Message(message, MessageType::ResetPassword));
}



void Client::sendLoginMessage(std::string&& username, std::string&& password)
{
    std::string message = username + ";";
    message +=  password + ";";
    Cryptography::encryptAndSign(message, MessageType::Login);
    m_connection->sendMessage(Message(message, MessageType::Login));
}

void Client::sendTextMessage(std::string&& destinationUser, std::string&& textMessage)
{
    std::string message = destinationUser + ';';
    message += textMessage + ";";
    std::cout << "message to send: " << message << std::endl;
    Cryptography::encryptAndSign(message, MessageType::TextMessage);
    Message m(message, MessageType::TextMessage);
    m_connection->sendMessage(m);
}

void Client::sendPublicKey()
{
    try {
        CryptoPP::ByteQueue transitionalQueue;
        Cryptography::clientPublicRSAKey.Save(transitionalQueue);
        CryptoPP::lword size = transitionalQueue.TotalBytesRetrievable();
        std::vector<uint8_t> clientPublicRSAKey(transitionalQueue.TotalBytesRetrievable());
        for (int i = 0; i < size; i++)
        {
            transitionalQueue.Get(clientPublicRSAKey[i]);
        }
        std::vector<uint8_t> fullMessage(std::move(clientPublicRSAKey));
        fullMessage.insert(fullMessage.end(),
            Cryptography::aesKey.begin(),
            Cryptography::aesKey.end());
        Cryptography::encryptAndSignFirstMessage(fullMessage);
        Message m(fullMessage, MessageType::KeyExchange);
        m_connection->sendMessage(m);
    }
    catch (CryptoPP::Exception& ex) {
        std::cout << ex.what() << std::endl;
        
    }
}


void Client::update()
{
    m_updateThread = std::thread
    {
        [&]()
        {
            while (true)
            {
                    if (!m_incomingQueue.empty())
                    {
                        processMessage(m_incomingQueue.popFront());
                    }
            }
        }
    };
}

void Client::processMessage(const Message& message)
{
    try {
        Message decryptedMessage = Cryptography::decryptAndVerify(message);
        if (decryptedMessage.messageType == MessageType::Registration)
            processRegistrationMessage(decryptedMessage);
        else if (decryptedMessage.messageType == MessageType::Login)
            processLoginMessage(decryptedMessage);
        else if (decryptedMessage.messageType == MessageType::TextMessage || decryptedMessage.messageType == MessageType::FriendRequest)
            processTextMessage(decryptedMessage);
    }
    catch (std::exception e)
    {
        std::cout << e.what() << std::endl;
    }
}


void Client::processRegistrationMessage(const Message& message)
{
    if (message.messageContent.empty())
        m_clientApp.SetState(1); // go to login success screen;
}

void Client::processLoginMessage(const Message& message)
{
    if (message.messageContent[0] == 'S')
        m_clientApp.SetState(2); // go to main screen;
}

void Client::processTextMessage(const Message& message)
{
    m_clientApp.pushMessage(message);
}




bool Client::started()
{
    return m_started;
}

void Client::checkIfFriendExists(std::string&& username)
{
    username += ";";
    Cryptography::encryptAndSign(username, MessageType::FriendRequest);
    Message m(username, MessageType::FriendRequest);
    m_connection->sendMessage(m);
}

void Client::deleteAccount() {
    std::string content = m_clientApp.getClientUsername() + ";";
    Cryptography::encryptAndSign(content, MessageType::AccountDeletion);
    m_connection->sendMessage(Message(content, MessageType::AccountDeletion));
}

