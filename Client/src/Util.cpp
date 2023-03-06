#include "../inc/Util.h"
#include <iostream>

#define SIGNATURE_LENGTH 256
#define AES_KEY_LENGTH 16
#define RSA_KEY_LENGTH 160

void extractToken(const std::vector<uint8_t>& message, std::string& word, int& positionInMessage)
{
	size_t msgSize = message.size();
	for (; positionInMessage < msgSize; positionInMessage++)
	{
		if (char(message[positionInMessage]) == ';')
		{
			positionInMessage++; // skip the ';' symbol for the next extractToken call
			return;
		}
		else
			word += message[positionInMessage];
	}
	std::cout << "extracted word: " << word << std::endl;
}


void Util::extractUserInfo(const std::vector<uint8_t>& regMessage, std::string& username, std::string& email, std::string& password, std::string& repeatPassword)
{
	int positionInMessage = 0;
	extractToken(regMessage, username, positionInMessage);
	extractToken(regMessage, password, positionInMessage);
	extractToken(regMessage, repeatPassword, positionInMessage);
	extractToken(regMessage, email, positionInMessage);
}

void Util::extractUserInfo(const std::vector<uint8_t>& regMessage, std::string& username, std::string& password)
{
	int positionInMessage = 0;
	extractToken(regMessage, username, positionInMessage);
	extractToken(regMessage, password, positionInMessage);
}


void Util::extractUsername(const std::vector<uint8_t>& regMessage, std::string& username)
{
	int positionInMessage = 0;
	extractToken(regMessage, username, positionInMessage);
}

void Util::extractUsernameAndMessage(const std::vector<uint8_t>& message, std::string& username, std::string& textMessage)
{
	int positionInMessage = 0;
	extractToken(message, username, positionInMessage);
	extractToken(message, textMessage, positionInMessage);
}

void Util::extractSignature(const std::vector<uint8_t>& messageContent, std::string& signature)
{
	for (int i = 0; i < SIGNATURE_LENGTH; i++)
	{
		signature += messageContent[i];
	}
}

void Util::extractMessage(const std::vector<uint8_t>& messageContent, std::string& message)
{
	for (int i = SIGNATURE_LENGTH; i < messageContent.size(); i++)
	{
		message += messageContent[i];
	}
}