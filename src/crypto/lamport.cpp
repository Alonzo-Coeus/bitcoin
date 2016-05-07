// Copyright (c) 2016 Ansho Enigu
#include "crypto/lamport.h"

#include "crypto/ripemd160.h"
#include "crypto/common.h"
    bool LAMPORT::checksig(char data[], char sig[160][20], char pubkey[320][20]) 
    {
            bool messhashb[160];
            unsigned char* messhash;
            CRIPEMD160().Write(&data, sizeof(data)).Finalize(&messhash);
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
              CRIPEMD160().Write(&_sig[i], sizeof(_sig[i])).Finalize(&sighop);
              memcpy(_csig[i], sighop, sizeof(_csig[i]));
            }
            return sig == _csig;
          
    }

    char [160][20]LAMPORT::createsig(char data[], uint512_t prikey) 
    {
      /* hash of the message */
      bool messhashb[160];
      unsigned char* messhash;
      CRIPEMD160().Write(&data, sizeof(data)).Finalize(&messhash);
      
      /* creating true key from seed (the seed is used as the key by the user but it only is a form of compress key) */
      unsigned char* vchHash
      CRIPEMD160().Write(&prikey, sizeof(prikey)).Finalize(&vchHash);
      char tempHash[];
      for(int i =0; i < 320; i++) 
      {
        CRIPEMD160().Write(&vchHash, sizeof(vchHash)).Write(&i, sizeof(i)).Finalize(&tempHash);
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
