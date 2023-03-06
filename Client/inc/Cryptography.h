#pragma once

#include <rsa.h>
#include <vector>
#include <osrng.h>
#include <modes.h>

struct Message;
enum class MessageType;

class Cryptography
{
public:
	static void loadRSAKeys();
	static void generateRSAKeys();
	static void generateAESKey();
	static void encryptAndSignFirstMessage(std::vector<uint8_t>& messageContent);
	static void encryptAndSign(std::string& messageContent, MessageType messageType);
	static Message decryptAndVerify(const Message& message);
	
	inline static CryptoPP::RSA::PublicKey clientPublicRSAKey;
	inline static CryptoPP::RSA::PrivateKey clientPrivateRSAKey;
	inline static CryptoPP::RSA::PublicKey serverPublicKey;
	inline static std::vector<uint8_t>  aesKey;
	inline static CryptoPP::AutoSeededRandomPool randomNumGen;
	inline static CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption aesEncryptor;
	inline static CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption aesDecryptor;
	inline static CryptoPP::SecByteBlock iv;
};

