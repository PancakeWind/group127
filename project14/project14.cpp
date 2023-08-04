#include <iostream>
#include <string>
#include <cryptopp/eccrypto.h>
#include <cryptopp/asn.h>
#include <cryptopp/oids.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>

using namespace CryptoPP;

int main() {
    // 初始化SM2密钥
    ECIES<ECP>::PrivateKey privateKey;
    ECIES<ECP>::PublicKey publicKey;

    privateKey.Initialize(CryptoPP::ASN1::secp256r1());
    privateKey.MakePublicKey(publicKey);

    // 明文消息
    std::string plaintext = "Hello, SM2!";

    // 加密
    ECIES<ECP>::Encryptor encryptor(publicKey);
    std::string ciphertext;
    StringSource(plaintext, true,
        new PK_EncryptorFilter(GlobalRNG(), encryptor,
            new StringSink(ciphertext)
        )
    );

    // 解密
    ECIES<ECP>::Decryptor decryptor(privateKey);
    std::string decrypted;
    StringSource(ciphertext, true,
        new PK_DecryptorFilter(GlobalRNG(), decryptor,
            new StringSink(decrypted)
        )
    );

    // 输出结果
    std::cout << "明文： " << plaintext << std::endl;
    std::cout << "加密后： " << ciphertext << std::endl;
    std::cout << "解密后： " << decrypted << std::endl;

    return 0;
}
