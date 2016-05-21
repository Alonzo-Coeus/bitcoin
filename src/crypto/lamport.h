// Copyright (c) 2016 Ansho Enigu
#ifndef BITCOIN_CRYPTO_LAMPORT_H
#define BITCOIN_CRYPTO_LAMPORT_H

#include <boost/multiprecision/cpp_int.hpp>

#include "crypto/ripemd160.h"

using namespace boost::multiprecision;

class LAMPORT
{
private:
    char pubkeys[320][20];
    char prikeys[320][20];

public:
    const int chuncksize = 1; /* in bytes */
    bool checksig(unsigned char data[], char sig[20][2][20], char rootkey[20], char exmerklewit[][20] /*this is the merkle wit minus the main public key*/, char pubkey[20][2][20]);
    char * createsig(unsigned char data[], uint512_t prikey, int selkeyset);                 /* data is data to be signed and prikey is a sudo-random num gen seed */
    char * createpubkey(uint512_t prikey);
};

#endif // BITCOIN_CRYPTO_LAMPORT_H
