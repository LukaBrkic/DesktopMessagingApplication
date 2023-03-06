#pragma once
#include <set>
#include <vector>
#include <string>
#include <iostream>




class Util
{
public:
	static void extractUserInfo(const std::vector<uint8_t>& regMessage, std::string& username, std::string& email, std::string& password, std::string& repeatPassword);
	static void extractUserInfo(const std::vector<uint8_t>& regMessage, std::string& username, std::string& password);
	static void extractUsernameAndMessage(const std::vector<uint8_t>& message, std::string& destinationUser, std::string& textMessage);
	static void extractUsername(const std::vector<uint8_t>& regMessage, std::string& username);
	static void extractSignature(const std::vector<uint8_t>& messageContent, std::string& signature);
	static void extractMessage(const std::vector<uint8_t>& messageContent, std::string& message);
};

