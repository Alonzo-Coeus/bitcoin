// Copyright (c) 2016 Ansho Enigu
#include "crypto/lamport.h"

#include "crypto/ripemd160.h"
#include "crypto/common.h"
#include "uint256.h"

typedef vector<unsigned char> valtype;

bool LAMPORT::checksig(unsigned char data[10000], char sig[20][2][20], char rootkey[20], char merklewit[])
{

  char exmerklewit[8][20]; /*this is the merkle wit minus the main public key max number of publickeys to rootkey is 256 due to 2^n where n is the first array index is 8*/
  char pubkey[20][2][20];

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
      if(r == 8)
        break; //lim of exmerklewit
      memcpy(&exmerklewit[r], &merklebuffer, sizeof(merklebuffer));
      r++;
      i++; //get i+1 index chunk so we can jump to next part of the merklewit at the end of cycle
      o = 0; //merklebuffer index
    }
    else
    {
      merklebuffer[o] = merklewit[i];
      o++;
    }
  }
  //end decoding merkle wit format

  //start checking if new publickey is a part of the root key
  char tempverifyhash[20];
  CRIPEMD160().Write(begin_ptr(publickey), 800).Finalize(begin_ptr(tempverifyhash)); //first element is start of arrays address length pre-def
  for(int i = 0; true; i++) //to end if false we will use return to lower processing time
  {
    if(exmerklewit[i][0] == 0 && exmerklewit[i][1] == 0 && exmerklewit[i][2] == 0 && exmerklewit[i][3] == 0)
    {
      if(tempverifyhash == rootkey)
      {
        break;
      }
      else
      {
        return false;
      }
    }

    CRIPEMD160().Write(begin_ptr(tempverifyhash), tempverifyhash.size()).Write(begin_ptr(exmerklewit), exmerklewit.size()).Finalize(begin_ptr(tempverifyhash));
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
    char *LAMPORT::createsig(unsigned char data[10000], uint512_t prikey, int sellectedpubkey)
    {
      /* the signing will happen under this */
      return &sig[0][0][0];
    }
