// Copyright (c) 2016 Alonzo Coeus
#include "crypto/lamport.h"

#include "crypto/ripemd160.h"
#include "crypto/common.h"
#include "uint256.h"

using namespace std;
typedef vector<unsigned char> valtype;

bool LAMPORT::checksig(valtype *pointerdata, valtype *pointerasig, valtype *pointerrootkey, valtype *pointermerklewit)
{

valtype data = *pointerdata;
valtype asig = *pointerasig;
valtype rootkey = *pointerrootkey;
valtype merklewit = *pointermerklewit;

//STARTING to convert asig vector to sig[20][2][20]
unsigned char sig[160/(LAMPORT::chunksize*8)][2][20];
for(int i = 0; i < (LAMPORT::chunksize*8); i++)
{
  for(int o = 0; o < 2; o++)
  {
    for(int p = 0; p < 20; p++)
    {
      sig[i][o][p] = asig[p + (o * 20) + (p * 40)];
    }
  }
}
//END converting asig vector to sig[20][2][20]

  valtype exmerklewit[8]; /*this is the merkle wit minus the main public key max number of publickeys to rootkey is 256 due to 2^n where n is the first array index is 8*/
  char pubkey[160/(LAMPORT::chunksize*8)][2][20];
  valtype hashablepubkey;

  //START converting merkle wit to exmerklewit and public key
  char merklebuffer[800]; //size of publickey is the max size of the buffer
  unsigned int i;
  for(i = 0; i < sizeof(merklewit); i++)
  {
    if(merklewit[i] == 0x00 && merklewit[i+1] == 0x00) /*test for partition beetween merkle segments*/
      break;
    merklebuffer[i] = merklewit[i];
  }

  memcpy(&(pubkey[0][0][0]), &(merklebuffer[0]), sizeof(merklebuffer));
  memcpy(&(hashablepubkey[0]), &(merklebuffer[0]), sizeof(merklebuffer));

  int o = 0;
  int r = 0; //number of times we have reset o count
  for(; i < merklewit.size(); i++)
  {
    if(merklewit[i] == 0x00 && merklewit[i+1] == 0x00)
    {
      if(r == 8)
        break; //lim of exmerklewit
      memcpy(&(exmerklewit[r][0]), &(merklebuffer[0]), sizeof(merklebuffer));
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
  //END decoding merkle wit format

  //START checking if new publickey is a part of the root key
  valtype tempverifyhash;
  CRIPEMD160().Write(&(hashablepubkey[0]), hashablepubkey.size()).Finalize(&(tempverifyhash[0])); //first element is start of arrays address length pre-def
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

    CRIPEMD160().Write(&(tempverifyhash[0]), tempverifyhash.size()).Write(&(exmerklewit[i][0]), exmerklewit[i].size()).Finalize(&(tempverifyhash[0]));
  }

  //END checking if new publickey is a part of the root key

  //START checking if sig is valid

  //create hash of data
  valtype hashdata;
  valtype sellectedhashseg; //to allow seamless scaling to larger segment sizes
  uint512_t sellectedinthashseg; //memcpy of valtype to uint512_t format
  CRIPEMD160().Write(&(data[0]), data.size()).Finalize(&(hashdata[0]));
  unsigned char keypair[2][20]; //the two public values at the ends of the ladder
  unsigned char sigpair[2][20]; //the two values from each side of hash ladder when signing

  for(int i = 0; i < 160/(LAMPORT::chunksize*8); i++) {
    //get sig, key pair and sellect hash segments
    uint512_t sellectedinthashseg;
    memcpy(&(sellectedhashseg), &(hashdata[i*LAMPORT::chunksize]), LAMPORT::chunksize);
    memcpy(&(sellectedinthashseg), &(sellectedhashseg), LAMPORT::chunksize);
    for(int o = 0; o < 2; o++) {
      memcpy(&(keypair[o][0]), &(pubkey[i][o]), 20);
      memcpy(&(sigpair[i][0]), &(sig[i][o]), 20);
    }
    //
    uint512_t i_a = 0;
    while (true) { //i-a sigpair[0]
      CRIPEMD160().Write(&(sigpair[0][0]), data.size()).Finalize(&(sigpair[0][0]));
      i_a++; //increment after data hased
      if(i_a == 160) {
        return false;
      }
      if(sigpair[0] == keypair[0]) {
        break;
      }
    }
    uint512_t i_b = 0;
    while (true) { //i-b sigpair[1]
      CRIPEMD160().Write(&(sigpair[1][0]), data.size()).Finalize(&(sigpair[1][0]));
      i_b++;
      if(i_b == 160) {
        return false;
      }
      if(sigpair[1] == keypair[1]) {
        break;
      }
    }
    if((160-i_a != i_b-1) || (160-i_a != sellectedinthashseg)) {
      return false;
    }
  }
  //END checking if sig is valid
  return true; // if compleats all tests return true
}
    char *LAMPORT::createsig(valtype *pdata, uint512_t *pprikey, int sellectedpubkey)
    {
      /* the signing will happen under this */
      valtype data = *pdata;
      uint512_t prikey = *pprikey;
      valtype pkey[20][2][20];

      valtype hash;
      CRIPEMD160().Write(&(data), data.size()).Finalize(&(hash));



      return &sig[0][0][0];
    }
