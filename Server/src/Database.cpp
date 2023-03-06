#include "../inc/Database.h"

#include <mysql/jdbc.h>
#include <iostream>
#include <istream> 
#include <sstream>

const std::string DATABASE_NAME = "USERS";
const std::string USER_LOGIN_INFO_TABLE_NAME = "USER_LOGIN_INFO";
const std::string USER_AES_KEY_TABLE_NAME = "USER_AES_KEY";
const std::string USER_RSA_KEY_TABLE_NAME = "USER_RSA_KEY";

using namespace std;

Database::Database() :
	m_driver(nullptr),
	m_con(nullptr),
	m_stmt(nullptr),
	m_prepStmt(nullptr),
	m_res(nullptr)
{
	try {
		m_driver = sql::mysql::get_mysql_driver_instance();
		m_con = m_driver->connect("tcp://127.0.0.1:3306", "root", "rootpass");
		m_stmt = m_con->createStatement();
		m_stmt->execute("USE " + DATABASE_NAME);
	}
	catch (const sql::SQLException& e)
	{
		std::cout << e.what() << std::endl;
	}
}

bool Database::usernameExists(const std::string& username)
{
	std::cout << std::endl;
	std::cout << "usernameeee  " << username << std::endl;
	try {
		m_prepStmt = m_con->prepareStatement("SELECT username FROM " + USER_LOGIN_INFO_TABLE_NAME + " WHERE BINARY username = ? ");
		m_prepStmt->setString(1, username);
		m_res = m_prepStmt->executeQuery();
	}
	catch (const sql::SQLException& e) {
		std::cout << e.what() << std::endl;
	}
	if (m_res->next()) // at least 1 row
		return true;
	return false;
}

bool Database::correctPassword(const std::string& username, const std::string& passwordHash)
{
	try {
		m_prepStmt = m_con->prepareStatement("SELECT password_hash FROM " + USER_LOGIN_INFO_TABLE_NAME + " WHERE password_hash = ? AND username = ?");
		m_prepStmt->setString(1, passwordHash);
		m_prepStmt->setString(2, username);
		m_res = m_prepStmt->executeQuery();
	}
	catch (const sql::SQLException& e) {
		std::cout << e.what() << std::endl;
	}
	if (m_res->next()) // at least 1 row
		return true;
	return false;
}

bool Database::correctSecretWord(const std::string& username, const std::string& secretWordHash)
{
	try {
		m_prepStmt = m_con->prepareStatement("SELECT secret_hash FROM " + USER_LOGIN_INFO_TABLE_NAME + " WHERE secret_hash = ? AND username = ?");
		m_prepStmt->setString(1, secretWordHash);
		m_prepStmt->setString(2, username);
		m_res = m_prepStmt->executeQuery();
	}
	catch (const sql::SQLException& e) {
		std::cout << e.what() << std::endl;
	}
	if (m_res->next()) // at least 1 row
		return true;
	return false;
}


void Database::storeUserLoginInfo(const std::string& username, 
								  const std::string& secretWordHash, 
								  const std::string& passwordHash,
								  const std::string& passSalt,
								  const std::string& secretWordSalt)
{
	try {
		m_prepStmt = m_con->prepareStatement("INSERT INTO " + USER_LOGIN_INFO_TABLE_NAME + " (username, secret_hash, password_hash, password_salt, secret_salt) VALUES(?, ?, ?, ?, ?)");
		m_prepStmt->setString(1, username);
		m_prepStmt->setString(2, secretWordHash);
		m_prepStmt->setString(3, passwordHash);
		m_prepStmt->setString(4, passSalt);
		m_prepStmt->setString(5, secretWordSalt);
		m_res = m_prepStmt->executeQuery();
	}
	catch (const sql::SQLException& e) {
		std::cout << e.what() << std::endl;
	}
}

void Database::updateUserLoginInfo(const std::string& username,
								   const std::string& passwordHash,
								   const std::string& passSalt)
{
	try {
		m_prepStmt = m_con->prepareStatement("UPDATE " + USER_LOGIN_INFO_TABLE_NAME + " SET password_hash = ?, password_salt = ? WHERE username = ?");
		m_prepStmt->setString(1, passwordHash);
		m_prepStmt->setString(2, passSalt);
		m_prepStmt->setString(3, username);
		m_res = m_prepStmt->executeQuery();
	}
	catch (const sql::SQLException& e) {
		std::cout << e.what() << std::endl;
	}
}

void Database::storeUserKeys(const std::string& username, const std::string& RSAKey, const std::string& aesKey, const std::string& initializationVector)
{
	std::istringstream aesBlob(aesKey);
	std::istringstream initVecBlob(initializationVector);
	std::istringstream rsaBlob(RSAKey);
	try {
		m_prepStmt = m_con->prepareStatement("REPLACE INTO " + USER_AES_KEY_TABLE_NAME + " (username, aes_key, initialization_vector) VALUES(?, ?, ?)");
		m_prepStmt->setString(1, username);
		m_prepStmt->setBlob(2, &aesBlob);
		m_prepStmt->setBlob(3, &initVecBlob);
		m_res = m_prepStmt->executeQuery();
		m_prepStmt = m_con->prepareStatement("REPLACE INTO " + USER_RSA_KEY_TABLE_NAME + " (username, rsa_key) VALUES(?, ?)");
		m_prepStmt->setString(1, username);
		m_prepStmt->setBlob(2, &rsaBlob);
		m_res = m_prepStmt->executeQuery();
	}
	catch (const sql::SQLException& e) {
		std::cout << e.what() << std::endl;
	}
}


void Database::deleteAccount(const std::string& username)
{
	try {
		m_prepStmt = m_con->prepareStatement("DELETE FROM " + USER_LOGIN_INFO_TABLE_NAME + " WHERE username = ?");
		m_prepStmt->setString(1, username);
		m_res = m_prepStmt->executeQuery();
		m_prepStmt = m_con->prepareStatement("DELETE FROM " + USER_AES_KEY_TABLE_NAME + " WHERE username = ?");
		m_prepStmt->setString(1, username);
		m_prepStmt = m_con->prepareStatement("DELETE FROM " + USER_RSA_KEY_TABLE_NAME + " WHERE username = ?");
		m_prepStmt->setString(1, username);
		m_res = m_prepStmt->executeQuery();
	}
	catch (const sql::SQLException& e) {
		std::cout << e.what() << std::endl;
	}
}

std::string Database::getClientRSAKey(const std::string& username)
{
	try {
		m_prepStmt = m_con->prepareStatement("SELECT rsa_key FROM " + USER_RSA_KEY_TABLE_NAME + " WHERE username = ?");
		m_prepStmt->setString(1, username);
		m_res = m_prepStmt->executeQuery();
		if (m_res->next())
		{
			return dynamic_cast<istringstream*>(m_res->getBlob(1))->str();
		}
	}
	catch (const sql::SQLException& e) {
		std::cout << e.what() << std::endl;
	}
	return "";
}

std::string Database::getClientAESKey(const std::string& username)
{
	try {
		m_prepStmt = m_con->prepareStatement("SELECT aes_key FROM " + USER_AES_KEY_TABLE_NAME + " WHERE username = ?");
		m_prepStmt->setString(1, username);
		m_res = m_prepStmt->executeQuery();
		if (m_res->next())
		{
			return dynamic_cast<istringstream*>(m_res->getBlob(1))->str();
		}
	}
	catch (const sql::SQLException& e) {
		std::cout << e.what() << std::endl;
	}
	return "";
}

std::string Database::getClientCBCInitializationVector(const std::string& username)
{
	try {
		m_prepStmt = m_con->prepareStatement("SELECT initialization_vector FROM " + USER_AES_KEY_TABLE_NAME + " WHERE username = ?");
		m_prepStmt->setString(1, username);
		m_res = m_prepStmt->executeQuery();
		if (m_res->next())
		{
			return dynamic_cast<istringstream*>(m_res->getBlob(1))->str();
		}
	}
	catch (const sql::SQLException& e) {
		std::cout << e.what() << std::endl;
	}
	return "";
}

std::string Database::getPasswordSalt(const std::string& username)
{
	try {
		m_prepStmt = m_con->prepareStatement("SELECT password_salt FROM " + USER_LOGIN_INFO_TABLE_NAME + " WHERE username = ?");
		m_prepStmt->setString(1, username);
		m_res = m_prepStmt->executeQuery();
		if (m_res->next())
		{
			return m_res->getString(1);
		}
	}
	catch (const sql::SQLException& e) {
		std::cout << e.what() << std::endl;
	}
	return "";
}

std::string Database::getSecretSalt(const std::string& username)
{
	try {
		m_prepStmt = m_con->prepareStatement("SELECT secret_salt FROM " + USER_LOGIN_INFO_TABLE_NAME + " WHERE username = ?");
		m_prepStmt->setString(1, username);
		m_res = m_prepStmt->executeQuery();
		if (m_res->next())
		{
			return m_res->getString(1);
		}
	}
	catch (const sql::SQLException& e) {
		std::cout << e.what() << std::endl;
	}
	return "";
}



Database::~Database() {
	delete m_stmt;
	delete m_con;
	delete m_prepStmt;
	delete m_res;
}