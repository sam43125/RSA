// g++ -g3 -ggdb -O0 -DDEBUG -I/usr/include/cryptopp rsa-encrypt.cpp -o rsa-encrypt -lcryptopp -lpthread
// g++ -g -O2 -DNDEBUG -I/usr/include/cryptopp rsa-encrypt.cpp -o rsa-encrypt -lcryptopp -lpthread

#include <iostream>
using std::cout;
using std::endl;

#include <iomanip>
using std::hex;

#include <string>
using std::string;

#include <sstream>
using std::ostringstream;

#include <cryptopp/rsa.h>
using CryptoPP::RSA;

#include <cryptopp/integer.h>
using CryptoPP::Integer;

typedef unsigned char byte;

const string rsa_enc(Integer n, Integer e, const string &message) {

    RSA::PublicKey pubKey;
    pubKey.Initialize(n, e);

    Integer m, c;
    m = Integer((const byte *)message.data(), message.size());
    c = pubKey.ApplyFunction(m);
    
    ostringstream oss;
    oss << hex << c;
    
    string cipher = oss.str();
    return cipher.substr(0, cipher.size() - 1);
}

int main(int argc, char** argv) {

    cout << rsa_enc(
        Integer("0xab9df7c82818bab3"), 
        Integer("0x11"), 
        "Alice") 
        << endl;

    cout << rsa_enc(
        Integer("0xcebe9e0617c706c632e64c3405cda5d1"), 
        Integer("0x11"), 
        "Hello World!") 
        << endl;

    cout << rsa_enc(
        Integer("0xaf195de7988cfaa1dbb18c5862e3853f0e79a12bbfa7aa326a52da97caa60c39"), 
        Integer("0x11"), 
        "RSA is public key.") 
        << endl;

    return 0;
}

