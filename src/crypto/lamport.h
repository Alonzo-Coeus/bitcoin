// Copyright (c) 2016 Ansho Enigu
#ifndef BITCOIN_CRYPTO_LAMPORT_H
#define BITCOIN_CRYPTO_LAMPORT_H

#include <boost/multiprecision/cpp_int.hpp>

#include "crypto/ripemd160.h"

using namespace boost::multiprecision;
typedef std::vector<unsigned char> valtype;

class LAMPORT
{
private:
    char pubkeys[320][20];
    char prikeys[320][20];
    char sig[20][2][20];
public:
    static const int chunksize = 1; /* in bytes */
    bool checksig(valtype *pointerdata, valtype *pointerasig, valtype *pointerrootkey, valtype *pointermerklewit);
    char *createsig(valtype *pdata, uint512_t *pprikey, int sellectedpubkey);                 /* data is data to be signed and prikey is a sudo-random num gen seed */
    char *createmerklewit(uint512_t prikey, int sellectedpubkey);
    char *createrootkey(uint512_t prikey);
    char *createpubkey(uint512_t prikey);
};

#endif // BITCOIN_CRYPTO_LAMPORT_H
