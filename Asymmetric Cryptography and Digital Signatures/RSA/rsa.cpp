/* Modern Cryptography Assignment 3: 2048-bit RSA
Requires the installation of the cryptopp library
Compilation command: g++ rsa.cpp -lcryptopp -o main
Run command: ./main
2023.6
*/

#include <iostream>
#include <string>
#include <crypto++/rsa.h>
#include <crypto++/osrng.h>
#include <crypto++/hex.h>
#include <crypto++/base64.h>
#include <crypto++/files.h>
#include <crypto++/nbtheory.h>

bool IsPrimeFunction(const CryptoPP::Integer &p)
{
    // 使用CryptoPP提供的函数进行素性检测
    return CryptoPP::IsPrime(p);
}

void GenerateRSAKey(unsigned int keyLength, const std::string &privFilename, const std::string &pubFilename)
{
    CryptoPP::AutoSeededRandomPool rng;

    // 生成参数
    CryptoPP::InvertibleRSAFunction params;
    CryptoPP::Integer p, q;

    // 素性检测
    do
    {
        params.GenerateRandomWithKeySize(rng, keyLength);
        p = params.GetPrime1();
        q = params.GetPrime2();
    } while (!IsPrimeFunction(p) || !IsPrimeFunction(q));

    // 创建公钥和私钥
    CryptoPP::RSA::PrivateKey privateKey(params);
    CryptoPP::RSA::PublicKey publicKey(params);

    // 保存公钥和私钥
    CryptoPP::ByteQueue bytes;
    publicKey.Save(bytes);
    CryptoPP::Base64Encoder privkeysink(new CryptoPP::FileSink(privFilename.c_str()));
    privateKey.DEREncode(privkeysink);
    privkeysink.MessageEnd();

    publicKey.Save(bytes);
    CryptoPP::Base64Encoder pubkeysink(new CryptoPP::FileSink(pubFilename.c_str()));
    publicKey.DEREncode(pubkeysink);
    pubkeysink.MessageEnd();
}

std::string RSAEncryptString(const std::string &plain, const std::string &pubFilename)
{
    std::string cipher;
    CryptoPP::AutoSeededRandomPool rng;

    // 加载公钥
    CryptoPP::ByteQueue bytes;
    CryptoPP::FileSource file(pubFilename.c_str(), true, new CryptoPP::Base64Decoder);
    file.TransferTo(bytes);
    bytes.MessageEnd();
    CryptoPP::RSA::PublicKey pubKey;
    pubKey.Load(bytes);

    CryptoPP::RSAES_OAEP_SHA_Encryptor e(pubKey);

    CryptoPP::StringSource ss1(plain, true,
                               new CryptoPP::PK_EncryptorFilter(rng, e,
                                                                new CryptoPP::StringSink(cipher)));
    return cipher;
}

std::string RSADecryptString(const std::string &cipher, const std::string &privFilename)
{
    std::string plain;
    CryptoPP::AutoSeededRandomPool rng;

    // 加载私钥
    CryptoPP::ByteQueue bytes;
    CryptoPP::FileSource file(privFilename.c_str(), true, new CryptoPP::Base64Decoder);
    file.TransferTo(bytes);
    bytes.MessageEnd();
    CryptoPP::RSA::PrivateKey privKey;
    privKey.Load(bytes);

    CryptoPP::RSAES_OAEP_SHA_Decryptor d(privKey);

    CryptoPP::StringSource ss2(cipher, true,
                               new CryptoPP::PK_DecryptorFilter(rng, d,
                                                                new CryptoPP::StringSink(plain)));
    return plain;
}

int main()
{
    freopen("plain.txt", "r", stdin);
    freopen("cipher.txt", "w", stdout);

    // 密钥长度设置为2048位
    unsigned int keyLength = 2048;

    // 设置公钥和私钥文件的名称
    std::string privFilename = "rsa-private.key";
    std::string pubFilename = "rsa-public.key";

    // 生成公钥和私钥
    GenerateRSAKey(keyLength, privFilename, pubFilename);

    // 需要加密的字符串
    std::string plain;
    std::getline(std::cin, plain); // 从标准输入读取一行内容

    // 使用公钥进行加密
    std::string cipher = RSAEncryptString(plain, pubFilename);
    std::cout << cipher << std::endl;

    // 使用私钥进行解密
    freopen("decrypted.txt", "w", stdout);
    std::string decrypted = RSADecryptString(cipher, privFilename);
    std::cout << decrypted << std::endl;

    return 0;
}
