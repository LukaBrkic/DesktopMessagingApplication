#pragma once
#include <string>
#include "../inc/sha256.h"


namespace sql 
{
	class Connection;
	class Statement;
	class PreparedStatement;
	class ResultSet;
	namespace mysql 
	{
		class MySQL_Driver;
	} // mysql
	
} // sql



class Database
{
public:
	Database();
	~Database();

	bool uniqueUsername(const std::string& username);
	bool usernameExists(const std::string& username);
	bool correctPassword(const std::string& username, const std::string& passwordHash);
	bool correctSecretWord(const std::string& username, const std::string& secretWordHash);

	void storeUserLoginInfo(const std::string& username, 
							const std::string& secretWordHash, 
							const std::string& passwordHash, 
							const std::string& passwordSalt, 
							const std::string& secretWordSalt);
	void storeUserKeys(const std::string& username, 
					   const std::string& RSAKey, 
					   const std::string& aesKey, 
					   const std::string& initializationVector);
	void updateUserLoginInfo(const std::string& username,
							 const std::string& passwordHash,
							 const std::string& passSalt);
	void deleteAccount(const std::string& username);

	std::string getClientRSAKey(const std::string& username);
	std::string getClientAESKey(const std::string& username);
	std::string getClientCBCInitializationVector(const std::string& username);
	std::string getPasswordSalt(const std::string& username);
	std::string getSecretSalt(const std::string& username);

private:
	sql::mysql::MySQL_Driver* m_driver;
	sql::Connection* m_con;
	sql::PreparedStatement* m_prepStmt;
	sql::Statement* m_stmt;
	sql::ResultSet* m_res;
};

