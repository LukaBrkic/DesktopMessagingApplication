#include "../inc/Cryptography.h"

#include <files.h>
#include <hex.h>

#include "../inc/Util.h"
#include "../../Common/netMessage.h"
#include "../inc/Connection.h"


void Cryptography::loadRSAKeys()
{
    try
    {
        CryptoPP::FileSource privKeyInput("keys/rsaprivate.der", true);
        CryptoPP::FileSource pubKeyInput("keys/rsapublic.der", true);
        publicRSAKey.BERDecode(pubKeyInput);
        privateRSAKey.BERDecode(privKeyInput);
        signer.AccessPrivateKey().AssignFrom(privateRSAKey);
        rsaDecryptor.AccessPrivateKey().AssignFrom(privateRSAKey);
    }
    catch (const CryptoPP::Exception& e) {

        std::cerr << e.what() << std::endl;
        std::cerr << e.GetErrorType() << std::endl;
        if (e.GetErrorType() == CryptoPP::Exception::IO_ERROR) // keys dont exist
        {
            std::cout << "cant find server keys" << std::endl;
            exit(1);
        }
    }
}

Message Cryptography::decryptFirstMessage(const Message& message)
{
    std::string decryptedContent;
    try {
        std::string content;
        Util::extractMessage(message.messageContent, content);
        CryptoPP::StringSource ss2(content, true,
            new CryptoPP::PK_DecryptorFilter(randomNumGen, rsaDecryptor,
                new CryptoPP::StringSink(decryptedContent)
            )
        );
        // no exception thrown, so verification is succesfull
    }
    catch (const CryptoPP::Exception& e) {
        std::cerr << e.what() << std::endl;
        std::cerr << e.GetErrorType() << std::endl;
        throw e; 
    }
    return Message(decryptedContent, message.messageType, message.sourceConnection);
}

Message Cryptography::decryptMessage(const Message& message, 
                                   std::string clientAESKey, 
                                   std::string clientCBCInitVector)
{
    std::string decryptedContent;
    try {
        std::string content;
        Util::extractMessage(message.messageContent, content);
        CryptoPP::SecByteBlock aesKeyBytes(reinterpret_cast<const CryptoPP::byte*>(&clientAESKey[0]), clientAESKey.size());
        CryptoPP::SecByteBlock initVectorBytes(reinterpret_cast<const CryptoPP::byte*>(&clientCBCInitVector[0]), clientCBCInitVector.size());
        CryptoPP::HexEncoder encoder(new CryptoPP::FileSink(std::cout));
        CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption aesDecryptor;
        aesDecryptor.SetKeyWithIV(aesKeyBytes, aesKeyBytes.size(), initVectorBytes);
        for (int i = 0; i < content.size(); i++)
            std::cout << content[i];
        CryptoPP::StringSource s(content, true,
            new CryptoPP::StreamTransformationFilter(aesDecryptor,
                new CryptoPP::StringSink(decryptedContent)
            ) 
        ); 
    }
    catch (const CryptoPP::Exception& e) {
        std::cerr << e.what() << std::endl;
        std::cerr << e.GetErrorType() << std::endl;
        throw e;
    }
    return Message(decryptedContent, message.messageType, message.sourceConnection);
}

bool Cryptography::verifyMessage(const Message& message, const Message& decryptedMessage, const std::string& clientRSAKey)
{
    std::string signature, content, decryptedContent;
    Util::extractSignature(message.messageContent, signature);
    Util::extractMessage(message.messageContent, content);
    CryptoPP::StringSource source(clientRSAKey, true);
    CryptoPP::RSA::PublicKey clientPublicKey;
    try {
        clientPublicKey.Load(source);
        CryptoPP::RSASS<CryptoPP::PSS, CryptoPP::SHA256>::Verifier clientVerifier(clientPublicKey);
        CryptoPP::StringSource(content + signature, true,
            new CryptoPP::SignatureVerificationFilter(
                clientVerifier,
                new CryptoPP::StringSink(decryptedContent),
                CryptoPP::SignatureVerificationFilter::THROW_EXCEPTION |
                CryptoPP::SignatureVerificationFilter::PUT_MESSAGE
            ) 
        ); 
        // no exception thrown, so verification is succesfull
        return 1;
    } 
    catch (const CryptoPP::Exception& e) {
        std::cerr << e.what() << std::endl;
        std::cerr << e.GetErrorType() << std::endl;
        throw e; // throw to server
        return 0;
    }
}

Message Cryptography::encryptAndSign(const Message& message, const std::string& AESKey, const std::string& clientCBCInitVector)
{
    CryptoPP::SecByteBlock initVectorBytes(reinterpret_cast<const CryptoPP::byte*>(&clientCBCInitVector[0]), clientCBCInitVector.size());
    aesEncryptor.SetKeyWithIV((const CryptoPP::byte*)AESKey.data(), AESKey.size(), initVectorBytes);
    std::string messageContent(message.messageContent.begin(), message.messageContent.end());
    if (message.messageType != MessageType::Registration)
    {
        messageContent += ";" + std::to_string(static_cast<int>(message.messageType)) + ";";
        messageContent += std::to_string(messageContent.size());
    }

    std::string encryptedContent, decryptedContent;
    std::string signature;
    encryptedContent.reserve(messageContent.size());
    // encrypt message content
    CryptoPP::StringSource a(messageContent, true,
        new CryptoPP::StreamTransformationFilter(aesEncryptor,
            new CryptoPP::StringSink(encryptedContent)
        )
    );
    // sign message content
    CryptoPP::RSASS<CryptoPP::PSS, CryptoPP::SHA256>::Signer signer(privateRSAKey);
    CryptoPP::StringSource s(encryptedContent, true,
        new CryptoPP::SignerFilter(randomNumGen, signer,
            new CryptoPP::StringSink(signature)
        )
    );
    messageContent.reserve(signature.size() + encryptedContent.size());
    messageContent = std::move(signature);
    std::move(encryptedContent.begin(), encryptedContent.end(), std::back_inserter(messageContent));
    return Message(messageContent, message.messageType, message.sourceConnection);
}

