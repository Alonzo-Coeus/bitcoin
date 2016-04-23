// Copyright (c) 2016 Ansho Enigu
#ifndef BITCOIN_CRYPTO_LAMPORT_H
#define BITCOIN_CRYPTO_LAMPORT_H

#include "crypto/lamport.h"
#include "crypto/ripemd160.h"

class LAMPORT
{
private:
    char pubkeys[20][160];
    char[320][20] prikeys;
    
public:
    bool checksig(unsigned char* data, char[160][20] sig, char[20][160] pubkey);    /* data is the transaction and sig is 160-bit's  */
    char[160][20] createsig(unsigned char* data, unsigned uint512_t prikey);                 /* data is data to be signed and prikey is a sudo-random num gen seed */
    
}

#endif // BITCOIN_CRYPTO_LAMPORT_H
