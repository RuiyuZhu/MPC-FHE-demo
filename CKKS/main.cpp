#include <iostream>
#include "fhekey.h"
int main(int argc,char ** argv) {
  int id = atoi(argv[1]);
  int port = 12345;
  int numberOfParty = 2;
  int OffSet = 0;
  if (argc >= 3) {
    OffSet = atoi(argv[2]);
  }
  if (argc >= 4) {
    numberOfParty = atoi(argv[3]);
  }
  if (argc >= 5) {
    port = atoi(argv[4]);
  }
  assert(OffSet + numberOfParty <= 16);
  __m128i key = _mm_set_epi32(0, 0, 0, id);
  fheKey<testL, testDegree> keySet(testPrimes, id, numberOfParty,
                                   &(HostAddress[OffSet]), port, key);

  fheKey<testL, testDegree>::swKey switchKey;
  fheKey<testL, testDegree>::pubKey publicKey;
  fheKey<testL, testDegree>::pvtKeyOnRing privateKey;
  
  keySet.keyGen(&privateKey, &switchKey, &publicKey);
  
  const int testLen = 32;
  fheKey<testL, testDegree>::plaintext p(testLen);
  fheKey<testL, testDegree>::ciphertext c(testLen);
  keySet.dec<testLen>(&p, &c, &privateKey);
}
