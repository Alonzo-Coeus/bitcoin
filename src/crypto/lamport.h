// Copyright (c) 2016 Ansho Enigu
#ifndef BITCOIN_CRYPTO_LAMPORT_H
#define BITCOIN_CRYPTO_LAMPORT_H

#include <stdint.h>
#include <stdlib.h>
#include "crypto/ripemd160.h"

class LAMPORT
{
private:
    uint8_t pubkey[20][160];
    char[320][20] prikeys;
    
public:
    bool checksig(unsigned char* data, uint8_t[20] sig, uint8_t[20][160] pubkey);    /* data is the transaction and sig is 160-bit's  */
    char[160][20] createsig(unsigned char* data, unsigned uint512_t prikey);                 /* data is data to be signed and prikey is a sudo-random num gen seed */
    
}

#endif
