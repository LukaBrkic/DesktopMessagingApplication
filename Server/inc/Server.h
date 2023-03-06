#pragma once

#include <memory>
#include <vector>
#include <unordered_map>
#include <deque>
#include <thread>

#include <asio.hpp>

#include "../inc/Database.h"
#include "../../Common/netMessage.h"
#include "../../Common/threadSafeQueue.h"
#include "Connection.h"

#include <rsa.h>



class Server {
    typedef std::unordered_map<std::string, std::tuple<std::string, std::string, std::string>> clientKeysMap;
public:
    Server(unsigned short port);
    void update();

    void processMessage(const Message& message);
    void validateLogin(const Message& message);
    void validateRegistration(const Message& message);
    void sendTextMessage(const Message& message);
    void checkIfFriendExists(const Message& message);
    void tryResetPassword(const Message& message);
    void deleteAccount(const Message& message);
    void extractAndStoreKeys(const Message& message);
    Message decryptAndVerify(const Message& message);

    void start();

    void startAccept();


private:
    void generateReport();

    Database m_database;
    ThreadSafeQueue m_messageQueue;
    std::vector<std::unique_ptr<Connection>> m_unnamedConnections;
    std::vector<std::unique_ptr<Connection>> m_loggedInUsers; 
    std::unordered_map<std::string, Connection*> m_connectionsByUsername;
    clientKeysMap m_keysByConnection;
    unsigned short m_port;
    asio::io_context m_asioIOContext;
    asio::ip::tcp::acceptor m_asioAcceptor;
    asio::error_code m_asioErrorCode;
    std::thread m_threadContext;
    std::thread m_reportThread;
    SHA256 m_sha256;
    int m_userStatistics[3]; // 0 - registered, 1 - logged in, 2 - text messages sent
};