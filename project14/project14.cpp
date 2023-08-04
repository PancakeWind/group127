#include <iostream>
#include <string>
#include <cryptopp/eccrypto.h>
#include <cryptopp/asn.h>
#include <cryptopp/oids.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>

using namespace CryptoPP;

int main() {
    // ��ʼ��SM2��Կ
    ECIES<ECP>::PrivateKey privateKey;
    ECIES<ECP>::PublicKey publicKey;

    privateKey.Initialize(CryptoPP::ASN1::secp256r1());
    privateKey.MakePublicKey(publicKey);

    // ������Ϣ
    std::string plaintext = "Hello, SM2!";

    // ����
    ECIES<ECP>::Encryptor encryptor(publicKey);
    std::string ciphertext;
    StringSource(plaintext, true,
        new PK_EncryptorFilter(GlobalRNG(), encryptor,
            new StringSink(ciphertext)
        )
    );

    // ����
    ECIES<ECP>::Decryptor decryptor(privateKey);
    std::string decrypted;
    StringSource(ciphertext, true,
        new PK_DecryptorFilter(GlobalRNG(), decryptor,
            new StringSink(decrypted)
        )
    );

    // ������
    std::cout << "���ģ� " << plaintext << std::endl;
    std::cout << "���ܺ� " << ciphertext << std::endl;
    std::cout << "���ܺ� " << decrypted << std::endl;

    return 0;
}
