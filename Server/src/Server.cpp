#include "../inc/Server.h"

#include <iostream>
#include <algorithm>
#include <iterator>
#include <fstream>
#include <tuple> 

#include <conio.h>

#include <osrng.h>
#include <files.h>

#include <Aspose.PDF.Cpp/document.h>
#include <Aspose.PDF.Cpp/Page.h>
#include <Aspose.PDF.Cpp/PageCollection.h>
#include <Aspose.PDF.Cpp/Generator/Paragraphs.h>
#include <Aspose.PDF.Cpp/Text/TextFragment.h>
#include <Aspose.PDF.Cpp/SaveFormat.h>
#include <Aspose.Words.Cpp/DocumentBuilder.h>
#include <Aspose.Words.Cpp/Document.h>

#include "../inc/sha256.h"
#include "../inc/Util.h"
#include "../inc/Cryptography.h"
#include "../inc/Connection.h"



Server::Server(unsigned short port) : 
    m_port(port),
    m_asioAcceptor(m_asioIOContext, std::move(asio::ip::tcp::endpoint(asio::ip::address::from_string("0.0.0.0"), port)))
{}

void Server::start()
{
    Cryptography::loadRSAKeys();
    startAccept();
    m_threadContext = std::thread([this]() { m_asioIOContext.run(); });
    m_reportThread = std::thread([this]() { generateReport(); });
    update();
}


void Server::startAccept()
{
    m_asioAcceptor.async_accept([this](const asio::error_code& ec, asio::ip::tcp::socket socket) {
        std::cout << "CLIENT CONNECTED" << std::endl;
        if (ec)
            std::cout << ec.message() << std::endl;
        else
        {
            m_unnamedConnections.emplace_back(std::make_unique<Connection>(m_messageQueue, std::move(socket), m_asioIOContext));
        }
        startAccept();
        });
}


void Server::update()
{
    while (true)
    {
        if (!m_messageQueue.empty())
        {
            processMessage(m_messageQueue.popFront());
        }
    }
}

void Server::processMessage(const Message& message)
{
    try {
        Message decryptedMessage = decryptAndVerify(message);
        if (message.messageType == MessageType::Login)
            validateLogin(decryptedMessage);
        else if (message.messageType == MessageType::Registration)
            validateRegistration(decryptedMessage);
        else if (message.messageType == MessageType::TextMessage)
            sendTextMessage(decryptedMessage);
        else if (message.messageType == MessageType::FriendRequest)
            checkIfFriendExists(decryptedMessage);
        else if (message.messageType == MessageType::ResetPassword)
            tryResetPassword(decryptedMessage);
        else if (message.messageType == MessageType::AccountDeletion)
            deleteAccount(decryptedMessage);
    }
    catch (const std::exception& e)
    {
        return; // ignore message, validation failed
    }
}

void Server::validateLogin(const Message& message)
{
    std::string username, password, passwordSalt, passwordHash, messageContent;
    std::string connectionAsString = message.sourceConnection->toString();
    std::string clientRSAKey = message.sourceConnection->getRSAKey();
    std::string aesKey = message.sourceConnection->getAesKey();
    std::string aesInitVector = message.sourceConnection->getAesInitVector();
    Util::extractUserInfo(message.messageContent, username, password);
    passwordSalt = m_database.getPasswordSalt(username);
    passwordHash = m_sha256(password + passwordSalt);
    if (m_database.usernameExists(username) && m_database.correctPassword(username, passwordHash))
    {
        message.sourceConnection->setUsername(username);
        messageContent = "Success" + username;
        m_connectionsByUsername[username] = message.sourceConnection;
        m_database.storeUserKeys(username, clientRSAKey,   
                                           aesKey,         
                                           aesInitVector); 
        m_userStatistics[1]++; 
    }
    else
    {
        messageContent = "Fail for user " + username;
    }
    message.sourceConnection->sendMessage(Message(messageContent, MessageType::Login));
}


void Server::validateRegistration(const Message& message)
{
    std::string connectionAsString = message.sourceConnection->toString();
    std::string clientRSAKey = std::get<0>(m_keysByConnection[connectionAsString]);
    std::string aesKey = std::get<1>(m_keysByConnection[connectionAsString]);
    std::string aesInitVector = std::get<2>(m_keysByConnection[connectionAsString]);
    std::string username, secretWord, pass, repeatPass;
    Util::extractUserInfo(message.messageContent, username, secretWord, pass, repeatPass);
    std::vector<uint8_t> registrationErrors;
    if (m_database.usernameExists(username))
        registrationErrors.emplace_back(static_cast<uint8_t>(RegistrationValidationError::UsernameNotUnique));
    if (username.length() < USERNAME_MIN_LENGTH)
        registrationErrors.emplace_back(static_cast<uint8_t>(RegistrationValidationError::UsernameTooShort));
    else if (username.length() > USERNAME_MAX_LENGTH)
        registrationErrors.emplace_back(static_cast<uint8_t>(RegistrationValidationError::UsernameTooLong));
    if (!std::all_of(username.begin(), username.end(), [](const char& ch) {return ch != ';'; }))
        registrationErrors.emplace_back(static_cast<uint8_t>(RegistrationValidationError::UsernameContainsInvalidCharacters));
    
    if (!std::all_of(secretWord.begin(), secretWord.end(), [](const char& ch) {return ch != ';'; }))
        registrationErrors.emplace_back(static_cast<uint8_t>(RegistrationValidationError::SecretWordContainsInvalidCharacters));
    if(secretWord.length() == 0)
        registrationErrors.emplace_back(static_cast<uint8_t>(RegistrationValidationError::SecretWordTooShort));

    if (pass.length() < PASSWORD_MIN_LENGTH)
        registrationErrors.emplace_back(static_cast<uint8_t>(RegistrationValidationError::PasswordTooShort));
    if (!std::all_of(pass.begin(), pass.end(), [](const char& ch) {return ch != ';'; }))
        registrationErrors.emplace_back(static_cast<uint8_t>(RegistrationValidationError::PasswordContainsInvalidCharacters));
    if(pass != repeatPass)
        registrationErrors.emplace_back(static_cast<uint8_t>(RegistrationValidationError::PasswordsNotTheSame));

    if (registrationErrors.empty())
    {
        const std::string passSalt(Util::generateRandomSalt());
        const std::string passHash = m_sha256(pass + passSalt);
        const std::string secretWordSalt(Util::generateRandomSalt());
        const std::string secretWordHash = m_sha256(secretWord + secretWordSalt);
        m_database.storeUserLoginInfo(username, secretWordHash, passHash, passSalt, secretWordSalt);
        m_userStatistics[0]++;
    }
    std::string messageContent(registrationErrors.begin(), registrationErrors.end());
    Message m(registrationErrors, MessageType::Registration);
    message.sourceConnection->sendMessage(m);


}

void Server::sendTextMessage(const Message& message)
{
    std::string destinationUser, textMessage;
    Util::extractUsernameAndMessage(message.messageContent, destinationUser, textMessage);
    if (m_connectionsByUsername.find(destinationUser) != m_connectionsByUsername.end()) // check if destination is logged in
    {
        std::string sourceUser = message.sourceConnection->getUsername();
        Message newMessage(std::string(sourceUser + ';' + textMessage), MessageType::TextMessage);
        m_connectionsByUsername[destinationUser]->sendMessage(newMessage);
        m_connectionsByUsername[destinationUser]->displayClientInfo();
        m_userStatistics[2]++;
    }
    else {
        std::cout << "Colud not find username " + destinationUser << std::endl;
    }
}

void Server::checkIfFriendExists(const Message& message)
{
    std::string username;
    Util::extractUsername(message.messageContent, username);
    if (m_database.usernameExists(username))
        message.sourceConnection->sendMessage(Message("True", MessageType::FriendRequest));
    else
        message.sourceConnection->sendMessage(Message("False", MessageType::FriendRequest));
}

void Server::tryResetPassword(const Message& message)
{
    std::string response;
    std::string username, secretWord, pass, repeatPass, secretWordHash, secretWordSalt;
    Util::extractUserInfo(message.messageContent, username, secretWord, pass, repeatPass);
    secretWordSalt = m_database.getSecretSalt(username);
    secretWordHash = m_sha256(secretWord + secretWordSalt);
    if (pass.size() >= PASSWORD_MIN_LENGTH && pass == repeatPass && m_database.correctSecretWord(username, secretWordHash))
    {
        const std::string passSalt(Util::generateRandomSalt());
        const std::string passHash = m_sha256(pass + passSalt);
        m_database.updateUserLoginInfo(username, passHash, passSalt);
        response = "Successful reset for " + username;
    }
    else
        response = "Failed reset for " + username;
    std::string messageContent(response);
    Message m(response, MessageType::ResetPassword, message.sourceConnection);
    message.sourceConnection->sendMessage(m);
}

void Server::deleteAccount(const Message& message)
{
    std::string username;
    Util::extractUsername(message.messageContent, username);
    m_database.deleteAccount(username);
}


void Server::extractAndStoreKeys(const Message& message)
{
    std::string clientRSAKey, aesKey, initializationVector;
    if (!Util::extractKeys(message.messageContent, clientRSAKey, aesKey, initializationVector))
    {
        throw std::exception();
    }
    std::string s = message.sourceConnection->toString();
    message.sourceConnection->setAesKey(aesKey);
    message.sourceConnection->setRSAKey(clientRSAKey);
    message.sourceConnection->setAesInitVector(initializationVector);
    m_keysByConnection[s] = {clientRSAKey, aesKey, initializationVector};
}

Message Server::decryptAndVerify(const Message& message)
{
    Message decryptedMessage;
    try {
        std::string clientRSAKey, clientAESKey, clientIV;
        if (message.messageType == MessageType::KeyExchange)
        {
            decryptedMessage = Cryptography::decryptFirstMessage(message); // decrypt using server RSA Key
            extractAndStoreKeys(decryptedMessage);
            clientRSAKey = std::get<0>(m_keysByConnection.at(message.sourceConnection->toString()));
        }
        else {
            if (message.messageType == MessageType::Registration || message.messageType == MessageType::Login || message.messageType == MessageType::ResetPassword)
            {
                // get client keys from map, since they get stored in the database once the user has logged in
                if (m_keysByConnection.find(message.sourceConnection->toString()) != m_keysByConnection.end())
                {
                    clientRSAKey = std::get<0>(m_keysByConnection.at(message.sourceConnection->toString()));
                    clientAESKey = std::get<1>(m_keysByConnection.at(message.sourceConnection->toString()));
                    clientIV = std::get<2>(m_keysByConnection.at(message.sourceConnection->toString()));
                }
            }
            else 
            {
                clientRSAKey = m_database.getClientRSAKey(message.sourceConnection->getUsername());
                clientAESKey = m_database.getClientAESKey(message.sourceConnection->getUsername());
                clientIV = m_database.getClientCBCInitializationVector(message.sourceConnection->getUsername());
            }
            decryptedMessage = Cryptography::decryptMessage(message, clientAESKey, clientIV);
        }
        Cryptography::verifyMessage(message, decryptedMessage, clientRSAKey);
    }
    catch (const std::exception& e) {
        throw e;
    }
    return decryptedMessage;
}

void Server::generateReport()
{
    while (true)
    {
        using namespace System;
        using namespace Aspose::Pdf;
        char ch = getchar();
        std::string registeredUsers = "Number of users who registered: " + std::to_string(m_userStatistics[0]);
        std::string loggedInUsers = "Number of users who logged in: " + std::to_string(m_userStatistics[1]);
        std::string textMessagesSent = "Number of text messages sent: " + std::to_string(m_userStatistics[2]);
        System::String reportText(registeredUsers + "\n" + loggedInUsers + "\n" + textMessagesSent);
        if (ch == 'r')
        {
            System::SharedPtr<Aspose::Words::Document> rtf = System::MakeObject<Aspose::Words::Document>();
            System::SharedPtr<Aspose::Words::DocumentBuilder> bldr = System::MakeObject<Aspose::Words::DocumentBuilder>(rtf);
            bldr->Write(reportText);
            rtf->Save(u"report.rtf");

        }
        else if (ch == 'p')
        {
            System::String  filename("report.pdf");
            auto document = System::MakeObject<Aspose::Pdf::Document>();
            auto page = document->get_Pages()->Add();
            auto text = System::MakeObject<Aspose::Pdf::Text::TextFragment>(reportText);
            auto paragraphs = page->get_Paragraphs();
            paragraphs->Add(text);
            document->Save(filename);
        }
    }
}








