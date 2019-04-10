// g++ -g3 -ggdb -O0 -DDEBUG -I/usr/include/cryptopp rsa-decrypt.cpp -o rsa-decrypt -lcryptopp -lpthread
// g++ -g -O2 -DNDEBUG -I/usr/include/cryptopp rsa-decrypt.cpp -o rsa-decrypt -lcryptopp -lpthread

#include <iostream>
using std::cout;
using std::endl;

#include <iomanip>
using std::hex;

#include <string>
using std::string;

#include <cryptopp/rsa.h>
using CryptoPP::RSA;

#include <cryptopp/integer.h>
using CryptoPP::Integer;

#include <cryptopp/osrng.h>
using CryptoPP::AutoSeededRandomPool;

typedef unsigned char byte;

const string rsa_dec(Integer n, Integer e, Integer d, Integer c) {

    AutoSeededRandomPool prng;

    RSA::PrivateKey privKey;
    privKey.Initialize(n, e, d);

    string recovered;
    Integer r;

    r = privKey.CalculateInverse(prng, c);

    size_t req = r.MinEncodedSize();
    recovered.resize(req);
    r.Encode((byte *)recovered.data(), recovered.size());

    return recovered;
}

int main(int argc, char** argv) {

    cout << rsa_dec(
        Integer("0xae20a831558c0d69"),
        Integer("0x11"),
        Integer("0x111242af5740d14d"),
        Integer("0x194d5cdc0ec8efbc")) 
        << endl;

    cout << rsa_dec(
        Integer("0xa0c432951d9e7da10fa929ba570bfee52db56fc477e60b742581a35d1723ad6f"),
        Integer("0x11"),
        Integer("0x974f3eaa763ad0979644dbfaac47867bd87b4c5c8b7fcd72943d0dde4303639"),
        Integer("0x404ea0a1c26fc6562ff17a61849520e0fdf70654c6460b0954918e8447d6cdba")) 
        << endl;

    return 0;
}

