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
    bool checksig(char data[], char sig[160][20], char pubkey[320][20]);    /* data is the transaction and sig is 160-bit's  */
    char [320][20]createsig(char data[], uint512_t prikey);                 /* data is data to be signed and prikey is a sudo-random num gen seed */
    
};

#endif // BITCOIN_CRYPTO_LAMPORT_H
