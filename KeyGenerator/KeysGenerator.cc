#include <iostream>
#include "cryptopp/eccrypto.h"
#include "cryptopp/osrng.h"
#include "cryptopp/oids.h"
using namespace CryptoPP;
#include <string>
using std::string;
#include "cryptopp/files.h"
using CryptoPP::FileSource;
using CryptoPP::FileSink;
#include <string>
using namespace std;
#include <crypto++/rsa.h>
#include <crypto++/osrng.h>
#include <crypto++/base64.h>
#include <crypto++/files.h>
using namespace CryptoPP;

void SavePrivateKeyECC_conf(const PrivateKey& key, const string& file ="privkeyECC(dest).txt");
void SavePublicKeyECC_conf(const PublicKey& key,const string& file = "pubkeyECC(dest).txt");

void SavePrivateKeyECC_conf(const PrivateKey& key, const string& file) {
    FileSink sink(file.c_str());
    key.Save(sink);
}

void SavePublicKeyECC_conf(const PublicKey& key, const string& file) {
    FileSink sink(file.c_str());
    key.Save(sink);
}

void SavePrivateKeyECC_int_and_auth( const string& filename, const ECDSA<ECP, SHA256>::PrivateKey& key )
{
    key.Save( FileSink( filename.c_str(), true /*binary*/ ).Ref() );
}

void SavePublicKeyECC_int_and_auth( const string& filename, const ECDSA<ECP, SHA256>::PublicKey& key )
{
    key.Save( FileSink( filename.c_str(), true /*binary*/ ).Ref() );
}

void GenKeyPairRSA()
{
    // InvertibleRSAFunction is used directly only because the private key
    // won't actually be used to perform any cryptographic operation;
    // otherwise, an appropriate typedef'ed type from rsa.h would have been used.
    AutoSeededRandomPool rng;
    InvertibleRSAFunction privkey;
    privkey.Initialize(rng, 3072);

    // With the current version of Crypto++, MessageEnd() needs to be called
    // explicitly because Base64Encoder doesn't flush its buffer on destruction.
    Base64Encoder privkeysink(new FileSink("privkeyRSA3072.txt"));
    privkey.DEREncode(privkeysink);
    privkeysink.MessageEnd();

    // Suppose we want to store the public key separately,
    // possibly because we will be sending the public key to a third party.
    RSAFunction pubkey(privkey);

    Base64Encoder pubkeysink(new FileSink("pubkeyRSA3072.txt"));
    pubkey.DEREncode(pubkeysink);
    pubkeysink.MessageEnd();

}

void genPairKeysECC_Integrity_and_Authentication() {
    AutoSeededRandomPool prng;

    ECDSA<ECP, SHA256>::PrivateKey k1;
    k1.Initialize(prng, ASN1::secp256r1());

    SavePrivateKeyECC_int_and_auth("privkeyECC.txt", k1);

    ECDSA<ECP, SHA256>::PublicKey publicKey;
    k1.MakePublicKey(publicKey);
    SavePublicKeyECC_int_and_auth("pubkeyECC.txt", publicKey);
}

void genPairKeysECC_Confidentiality() {
    AutoSeededRandomPool prng;

    ECIES<ECP>::Decryptor d0(prng, ASN1::secp256r1());

    ECIES<ECP>::Encryptor e0(d0);

    SavePrivateKeyECC_conf(d0.GetPrivateKey());
    SavePublicKeyECC_conf(e0.GetPublicKey());
}

int main(){
    //da riempire con il metodo che si desidera lanciare
}
