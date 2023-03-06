#pragma once

#include <iostream>
#include <functional>
#include <memory>
#include <queue>
#include <string>
#include <thread>

#include <asio.hpp>	

#include "Connection.h"
#include "../../Common/netMessage.h"
#include "../../Common/threadSafeQueue.h"

class ClientApp;

class Client {
public:
    Client(const std::string& serverIP, unsigned short serverPort, ClientApp& clientApp);

    void start();
    void update();
    void processMessage(const Message& message);
    void sendRegistrationMessage(std::string&& username, std::string&& secretWord, std::string&& password, std::string&& repeatPassword);
    void sendResetPasswordMessage(std::string&& username, std::string&& secretWord, std::string&& newPasword, std::string&& newPaswordRepeat);
    void sendLoginMessage(std::string&& username, std::string&& password);
    void sendTextMessage(std::string&& destinationUser, std::string&& message);
    void sendPublicKey();
    void deleteAccount();
    
    bool started();
    void checkIfFriendExists(std::string&& username);

private:
    void processLoginMessage(const Message& message);
    void processRegistrationMessage(const Message& message);
    void processTextMessage(const Message& message);

    ThreadSafeQueue m_incomingQueue;
    asio::io_context m_asioIOContext;
    asio::error_code m_asioErrorCode;
    std::string m_serverIP;
    unsigned short m_serverPort;
    std::thread m_asioExecutionCompletionThread;
    std::thread m_updateThread;
    std::unique_ptr<Connection> m_connection;
    bool m_started = false;
    ClientApp& m_clientApp;
};