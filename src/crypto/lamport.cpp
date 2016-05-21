// Copyright (c) 2016 Ansho Enigu
#include "crypto/lamport.h"

#include "crypto/ripemd160.h"
#include "crypto/common.h"
#include "uint256.h"
bool LAMPORT::checksig(unsigned char data[], char sig[20][2][20], char rootkey[20], char merklewit[])
{

  char exmerklewit[8][20]; /*this is the merkle wit minus the main public key max number of publickeys to rootkey is 256 due to 2^n where n is the first array index is 8*/
  char pubkey[20][2][20];
  bool valid = true;
  bool merklecheckfin = false;

  //start converting merkle wit to exmerklewit and public key
  char merklebuffer[800]; //size of publickey is the max size of the buffer
  unsigned int i;
  for(i = 0; i < sizeof(merklewit); i++)
  {
    if(merklewit[i] == 0x00 && merklewit[i+1] == 0x00) /*test for partition beetween merkle segments*/
      break;
    merklebuffer[i] = merklewit[i];
  }

  memcpy(&pubkey, &merklebuffer, sizeof(merklebuffer));
  int o = 0;
  int r = 0; //number of times we have reset o count
  for(; i < sizeof(merklewit); i++)
  {
    if(merklewit[i] == 0x00 && merklewit[i+1] == 0x00)
    {
      memcpy(&exmerklewit[r], &merklebuffer, sizeof(merklebuffer))
      r++;
      i++; //get i+1 index chunk so we can jump to next part of the merklewit at the end of cycle
      o = 0;
    }
    else
    {
      merklebuffer[o] = merklewit[i];
      o++;
    }
  }
  //end decoding merkle wit format

  //start checking if new publickey is a part of the root key
  for(int i = 0; !merklecheckfin; i++) //to end if false we will use return to lower processing time
  {
    return false;
  }
  //end checking if new publickey is a part of the root key

  /*
      unsigned char* datapart;
      unsigned char[(160/LAMPORT::chuncksize)]* datahashs;
      for(int i = 0; i < (160/LAMPORT::chuncksize); i++)
      {

        for(int o = 0; o < chuncksizeinbyte; o++)
        {
          datapart[o] = data[(i * LAMPORT::chuncksize) + o];
        }

        CRIPEMD160().Write(begin_ptr(datapart), datapart.size()).Finalize(begin_ptr(datahashs[i]));
      }
      */
      return true; // if compleats all tests return true
}
    char * LAMPORT::createsig(unsigned char data[], uint512_t prikey)
    {
      /* hash of the message */
      bool messhashb[160];
      unsigned char[] messhash;
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
      memcpy(&messhashb, &messhash, sizeof(messhashb));
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
      return &sig;
    }
