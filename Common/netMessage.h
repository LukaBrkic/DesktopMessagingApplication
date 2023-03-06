#pragma once

#include <stdint.h>
#include <vector>
#include <string>
#include <set>

#define USERNAME_MAX_LENGTH 255
#define USERNAME_MIN_LENGTH 5
#define PASSWORD_MIN_LENGTH 5

class Connection;

enum class RegistrationValidationError {
	UsernameNotUnique,
	UsernameTooShort,
	UsernameTooLong,
	UsernameContainsInvalidCharacters,
	SecretWordContainsInvalidCharacters,
	SecretWordTooShort,
	PasswordTooShort,
	PasswordContainsInvalidCharacters,
	PasswordsNotTheSame
};

enum class MessageType {
	Registration,
	Login,
	TextMessage,
	FriendRequest,
	KeyExchange,
	ResetPassword,
	AccountDeletion
};


struct Message {
	Message() : messageSize(0){}
	Message(uint16_t l_messageSize) :
		messageSize(l_messageSize),
		messageContent(l_messageSize)
		{}

	Message(const std::string& messageToSend, MessageType messageType) : 
		messageSize(messageToSend.size()),
		messageType(messageType),
		messageContent(messageToSend.begin(), messageToSend.end()) {}

	Message(std::vector<uint8_t>& messageContent, MessageType messageType) :
		messageSize(messageContent.size()),
		messageType(messageType),
		messageContent(std::move(messageContent)) {}

	Message(std::vector<uint8_t>& messageContent, MessageType messageType, Connection* sourceConnection) :
		messageSize(messageContent.size()),
		messageType(messageType),
		messageContent(std::move(messageContent)),
		sourceConnection(sourceConnection){}

	Message(const std::string& messageContent, MessageType messageType, Connection* sourceConnection) :
		messageSize(messageContent.size()),
		messageType(messageType),
		messageContent(messageContent.begin(), messageContent.end()),
		sourceConnection(sourceConnection) {}

	uint16_t messageSize;
	MessageType messageType;
	std::vector<uint8_t> messageContent;
	Connection* sourceConnection;
};
