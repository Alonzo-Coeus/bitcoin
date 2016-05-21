// Copyright (c) 2016 Ansho Enigu
#include "crypto/lamport.h"

#include "crypto/ripemd160.h"
#include "crypto/common.h"
namespace
{
  namespace lamport
  {
    bool LAMPORT::checksig(unsigned char* data, char[160][20] sig, char[20][160] pubkey) 
    {
            bool messhashb[160];
            valtype messhash(true ? 20 : 32);
            CRIPEMD160().Write(begin_ptr(data), data.size()).Finalize(begin_ptr(messhash));
            memcpy(messhashb, messhash, sizeof(messhashb));
            
            char _sig[160][20];
            char _csig[160][20];
            
            for(int i=0; i < 160; i++)
            {
              for(int o=0; o < 20; o++)
              {
                  if(messhashb[i]) 
                  {
                    _sig[o][i] = pubkey[o][2*i];
                  }
                  else
                  {
                    _sig[o][i] = pubkey=[o][(2*i)+1];
                  }
              }
            }
            
            valtype sighop(true ? 20 : 32)
            for(int i=0; i < 160; i++)
            {
              CRIPEMD160().Write(begin_ptr(_sig[i]), _sig[i].size()).Finalize(begin_ptr(sighop));
              memcpy(_csig[i], sighop, _csig[i].size());
            }
            return sig == _csig;
          
    }

    char[160][20] LAMPORT::createsig(unsigned char* data, unsigned uint512_t prikey) 
    {
      /* hash of the message */
      bool messhashb[160];
      valtype messhash(true ? 20 : 32);
      CRIPEMD160().Write(begin_ptr(data), data.size()).Finalize(begin_ptr(messhash));
      
      /* creating true key from seed (the seed is used as the key by the user but it only is a form of compress key) */
      valtype vchHash(true ? 20 : 32);
      CRIPEMD160().Write(begin_ptr(prikey), prikey.size()).Finalize(begin_ptr(vchHash));
      for(int i =0; i < 320; i++) 
      {
        valtype tempHash(true ? 20 : 32);
        CRIPEMD160().Write(begin_ptr(vchHash), prikey.size()).Write(i, i.size()).Finalize(begin_ptr(tempHash));
        prikeys[i] = temphash;
      }
      
      /* the signing will happen uder this */
      char[160][20] sig;
      memcpy(messhashb, messhash, sizeof(messhashb));
      for(int i=0; i < 160; i++)
      {
        if(messhashb[i]) 
        {
          sig[i] = prikeys[2*i];
        }
        else
        {
          sig[i] = prikeys[(2*i)+1];
        }
      }
      return sig;
    }
  }
}
