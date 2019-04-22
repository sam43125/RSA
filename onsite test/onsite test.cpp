#define NO_MAIN
#include "../RSA Encrypt/rsa-encrypt.cpp"
#include "../RSA Decrypt/rsa-decrypt.cpp"

int main(int argc, char** argv) {

    AutoSeededRandomPool rng;
    InvertibleRSAFunction par;
    par.GenerateRandomWithKeySize(rng, 1024);

    const Integer& n = par.GetModulus();
    const Integer& p = par.GetPrime1();
    const Integer& q = par.GetPrime2();
    const Integer& d = par.GetPrivateExponent();
    const Integer& e = par.GetPublicExponent();

    string plain = "Paris prosecutors are investigating if short-circuit caused Notre Dame fire.";
    Integer c = rsa_enc(n, e, plain);
    string cipher = Integer2hex(c);
    string recovered = rsa_dec(n, e, d, c, rng);

    cout << "n = " << hex << n << endl
        << "\np = " << p << endl
        << "\nq = " << q << endl
        << "\ne = " << e << endl
        << "\nd = " << d << endl
        << "\ncipher = " << cipher << endl
        << "\nrecovered = " << recovered << endl;

    return 0;
}
