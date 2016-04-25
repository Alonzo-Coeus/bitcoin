// Copyright (c) 2016 Ansho Enigu
#include "crypto/lamport.h"

#include "crypto/ripemd160.h"
#include "crypto/common.h"
    bool LAMPORT::checksig(unsigned char* data, char sig[160][20], char pubkey[320][20]) 
    {
            bool messhashb[160];
            unsigned char* messhash;
            CRIPEMD160().Write(&data, data.size()).Finalize(&messhash);
            memcpy(messhashb, messhash, sizeof(messhashb));
            
            char _sig[160][20];
            char _csig[160][20];
            for(int i=0; i < 160; i++)
            {
              for(int o=0; o < 20; o++)
              {
                  if(messhashb[i]) 
                  {
                    _sig[i][o] = pubkey[2*i][o];
                  }
                  else
                  {
                    _sig[i][o] = pubkey[(2*i)+1][o];
                  }
              }
            }
            
            unsigned char* sighop;
            for(int i=0; i < 160; i++)
            {
              CRIPEMD160().Write(&_sig[i], _sig[i].size()).Finalize(&sighop);
              memcpy(_csig[i], sighop, _csig[i].size());
            }
            return sig == _csig;
          
    }

    char[320][20] LAMPORT::createsig(unsigned char* data, uint512_t prikey) 
    {
      /* hash of the message */
      bool messhashb[160];
      unsigned char* messhash;
      CRIPEMD160().Write(&data, data.size()).Finalize(&messhash);
      
      /* creating true key from seed (the seed is used as the key by the user but it only is a form of compress key) */
      valtype vchHash(true ? 20 : 32);
      CRIPEMD160().Write(&prikey, prikey.size()).Finalize(&vchHash);
      for(int i =0; i < 320; i++) 
      {
        unsigned char* tempHash;
        CRIPEMD160().Write(&vchHash, prikey.size()).Write(&i, i.size()).Finalize(&tempHash);
        prikeys[i] = temphash;
      }
      
      /* the signing will happen uder this */
      char sig[320][20];
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
