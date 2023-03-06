#pragma once

#include <rsa.h>
#include <vector>
#include <osrng.h>
#include <pssr.h>
#include <modes.h>

struct Message;
enum class MessageType;

class Cryptography
{
public:
	static void loadRSAKeys();
	static Message decryptFirstMessage(const Message& message);
	static Message decryptMessage(const Message& message, std::string clientAESKey, std::string clientCBCInitVector);
	static bool verifyMessage(const Message& message, const Message& decryptedMessage, const std::string& clientRSAKey);
	static Message encryptAndSign(const Message& messageContent, const std::string& AESKey, const std::string& clientCBCInitVector);
private:
	inline static CryptoPP::RSA::PublicKey publicRSAKey;
	inline static CryptoPP::RSA::PrivateKey privateRSAKey;
	inline static CryptoPP::AutoSeededRandomPool randomNumGen;
	inline static CryptoPP::RSASS<CryptoPP::PSS, CryptoPP::SHA256>::Signer signer;
	inline static CryptoPP::RSAES_OAEP_SHA_Decryptor rsaDecryptor;
	inline static CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption  aesDecryptor;
	inline static CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption  aesEncryptor;
};

