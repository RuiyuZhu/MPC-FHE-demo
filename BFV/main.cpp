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
  fheKey<testL, testDegree, testW> keySet(testPrimes, id, numberOfParty,
                                   &(HostAddress[OffSet]), port, key);

  fheKey<testL, testDegree, testW>::swKey switchKey(&keySet);
  fheKey<testL, testDegree, testW>::pubKey publicKey;
  fheKey<testL, testDegree, testW>::pvtKeyOnRing privateKey;
  
//  keySet.keyGen(&privateKey, &switchKey, &publicKey);
  
  fheKey<testL, testDegree, testW>::plaintext p;
  fheKey<testL, testDegree, testW>::ciphertext c;
  keySet.dec(&p, &c, &privateKey);
}
