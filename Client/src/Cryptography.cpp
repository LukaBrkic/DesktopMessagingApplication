#include "../inc/Cryptography.h"

#include "../../Common/netMessage.h"
#include "../inc/Util.h"


#include <osrng.h>
#include <files.h>
#include <rsa.h>
#include <pssr.h>
#include <hex.h>

void Cryptography::loadRSAKeys()
{
    try
    {
        CryptoPP::FileSource pubServerKeyInput("keys/rsapublicServer.der", true);
        serverPublicKey.BERDecode(pubServerKeyInput);
        CryptoPP::FileSource privKeyInput("keys/rsaprivate.der", true);
        clientPrivateRSAKey.BERDecode(privKeyInput);
        CryptoPP::FileSource pubKeyInput("keys/rsapublic.der", true);
        clientPublicRSAKey.BERDecode(pubKeyInput);
    }
    catch (const CryptoPP::Exception& e) {

        std::cerr << e.what() << std::endl;
        std::cerr << e.GetErrorType() << std::endl;
        if (e.GetErrorType() == CryptoPP::Exception::IO_ERROR) // keys dont exist
        {
            generateRSAKeys();
        }
        else {
            std::exit(1);
        }
    }
}


void Cryptography::generateRSAKeys()
{
    try
    {
        CryptoPP::AutoSeededRandomPool rng;
        clientPrivateRSAKey.GenerateRandomWithKeySize(rng, 1024);
        clientPublicRSAKey = clientPrivateRSAKey;
        if (!clientPublicRSAKey.Validate(rng, 3))
        {
            std::cout << "bad validation" << std::endl;
        }
        CryptoPP::FileSink outputPrivate("keys/rsaprivate.der");
        clientPrivateRSAKey.DEREncode(outputPrivate);
        CryptoPP::FileSink outputPublic("keys/rsapublic.der");
        clientPublicRSAKey.DEREncode(outputPublic);
    }
    catch (const CryptoPP::Exception& e) {
        std::cerr << e.what() << std::endl;
        std::cerr << e.GetErrorType() << std::endl;
        std::exit(1);
    }
}



void Cryptography::generateAESKey()
{
    try
    {
        aesKey.resize(CryptoPP::AES::DEFAULT_KEYLENGTH);
        randomNumGen.GenerateBlock(aesKey.data(), CryptoPP::AES::DEFAULT_KEYLENGTH);
    }
    catch (const CryptoPP::Exception& e) {
        std::cerr << e.what() << std::endl;
        std::cerr << e.GetErrorType() << std::endl;
        std::exit(1);
    }
}

void Cryptography::encryptAndSignFirstMessage(std::vector<uint8_t>& messageContent) 
{
    // generate initialization vector and initialize aes encryptor
    // used to encrypt second message
    iv.resize(CryptoPP::AES::DEFAULT_KEYLENGTH);
    randomNumGen.GenerateBlock(iv, iv.size());
    aesEncryptor.SetKeyWithIV((const CryptoPP::byte*)aesKey.data(), aesKey.size(), iv);
    CryptoPP::SecByteBlock aesKeyBytes(reinterpret_cast<const CryptoPP::byte*>(&aesKey[0]), aesKey.size());
    // proceed with rsa encryption
    messageContent.insert(messageContent.end(), std::begin(iv), std::end(iv));
    std::vector<uint8_t> encryptedContent;
    std::vector<uint8_t> signature;
    encryptedContent.reserve(messageContent.size());
    CryptoPP::RSAES_OAEP_SHA_Encryptor serverPublicKeyEncryptor(Cryptography::serverPublicKey);
    // encrypt message content
    CryptoPP::StringSource(messageContent.data(), messageContent.size(), true, 
        new CryptoPP::PK_EncryptorFilter(randomNumGen, 
                                         serverPublicKeyEncryptor, 
                                         new CryptoPP::VectorSink(encryptedContent)));
    // sign message content
    CryptoPP::RSASS<CryptoPP::PSS, CryptoPP::SHA256>::Signer signer(clientPrivateRSAKey);
    CryptoPP::StringSource(encryptedContent.data(), encryptedContent.size(), true,
        new CryptoPP::SignerFilter(randomNumGen, signer,
            new CryptoPP::VectorSink(signature)
        ) 
    );
    messageContent.reserve(encryptedContent.size() + signature.size());
    messageContent = std::move(signature);
    std::move(encryptedContent.begin(), encryptedContent.end(), std::back_inserter(messageContent));
}


void Cryptography::encryptAndSign(std::string& messageContent, MessageType messageType)
{
    aesEncryptor.SetKeyWithIV((const CryptoPP::byte*)aesKey.data(), aesKey.size(), iv);
    messageContent += std::to_string(messageContent.size()) + ";";
    messageContent += std::to_string(static_cast<int>(messageType));
    std::string encryptedContent, decryptedContent;
    std::string signature; 
    encryptedContent.reserve(messageContent.size());
    CryptoPP::StringSource a(messageContent, true,
        new CryptoPP::StreamTransformationFilter(aesEncryptor,
            new CryptoPP::StringSink(encryptedContent)
        )
    );
    // sign message content
    CryptoPP::RSASS<CryptoPP::PSS, CryptoPP::SHA256>::Signer signer(clientPrivateRSAKey);
    CryptoPP::StringSource s(encryptedContent, true,
        new CryptoPP::SignerFilter(randomNumGen, signer,
            new CryptoPP::StringSink(signature)
        )
    );
    messageContent.reserve(signature.size() + encryptedContent.size());
    messageContent = std::move(signature);
    std::move(encryptedContent.begin(), encryptedContent.end(), std::back_inserter(messageContent));
}

Message Cryptography::decryptAndVerify(const Message& message)
{

    std::string signature, content, decryptedContent;
    Util::extractSignature(message.messageContent, signature);
    Util::extractMessage(message.messageContent, content);
    try {
        CryptoPP::RSASS<CryptoPP::PSS, CryptoPP::SHA256>::Verifier clientVerifier(serverPublicKey);
        CryptoPP::StringSource(content + signature, false,
            new CryptoPP::SignatureVerificationFilter(
                clientVerifier,
                new CryptoPP::StringSink(decryptedContent),
                CryptoPP::SignatureVerificationFilter::THROW_EXCEPTION |
                CryptoPP::SignatureVerificationFilter::PUT_MESSAGE
            )
        );
        aesDecryptor.SetKeyWithIV(reinterpret_cast<const CryptoPP::byte*>(aesKey.data()), aesKey.size(), iv);
        CryptoPP::StringSource s(content, true,
            new CryptoPP::StreamTransformationFilter(aesDecryptor,
                new CryptoPP::StringSink(decryptedContent)
            )
        );
        // no exception thrown, so verification is succesfull
        return Message(decryptedContent, message.messageType, message.sourceConnection);
    }
    catch (const CryptoPP::Exception& e) {
        std::cerr << e.what() << std::endl;
        std::cerr << e.GetErrorType() << std::endl;
        throw e; // throw to server
    }
}
