#include "../inc/Util.h"
#include <iostream>
#include <random>

#define SIGNATURE_LENGTH 128
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


void Util::extractUserInfo(const std::vector<uint8_t>& regMessage, std::string& username, std::string& secretWord, std::string& password, std::string& repeatPassword)
{
	int positionInMessage = 0;
	extractToken(regMessage, username, positionInMessage);
	extractToken(regMessage, password, positionInMessage);
	extractToken(regMessage, repeatPassword, positionInMessage);
	extractToken(regMessage, secretWord, positionInMessage);
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

bool Util::extractKeys(const std::vector<uint8_t>& decryptedContent, std::string& clientRSAKeyString, std::string& aesKey, std::string& initializationVector)
{
	if (decryptedContent.size() != AES_KEY_LENGTH * 2 + RSA_KEY_LENGTH)
		return 0;
	for (int i = 0; i < RSA_KEY_LENGTH; i++)
	{
		clientRSAKeyString += decryptedContent[i];
	}
	for (int i = RSA_KEY_LENGTH; i < RSA_KEY_LENGTH + AES_KEY_LENGTH; i++)
	{
		aesKey += decryptedContent[i];
	}
	for (int i = RSA_KEY_LENGTH + AES_KEY_LENGTH; i < RSA_KEY_LENGTH + AES_KEY_LENGTH * 2; i++)
	{
		initializationVector += decryptedContent[i];
	}
	return 1;
}

std::string Util::generateRandomSalt()
{
	const static int SALT_LENGTH = 16;
	const std::string CHARACTERS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

	std::random_device random_device;
	std::mt19937 generator(random_device());
	std::uniform_int_distribution<> distribution(0, CHARACTERS.size() - 1);

	std::string random_string;

	for (std::size_t i = 0; i < SALT_LENGTH; ++i)
	{
		random_string += CHARACTERS[distribution(generator)];
	}

	return random_string;
}

