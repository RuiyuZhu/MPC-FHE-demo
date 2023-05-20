#pragma once

template<int QL, int degree, uint64_t w>
class fheKey<QL, degree, w>::cryptoBackends::committedExcg {
public:
  committedExcg(cryptoBackends* backend, const int l, const int n,
               arithmeticNum** dst);
  //      ~committedExcg();
  void push(arithmeticNum value);
  void exchange();
private:
  cryptoBackends* backend;
  const int size;
  const int numberOfParty;
  arithmeticNum* myValue;
  arithmeticNum** receivedValues;
  int count = 0;
  unsigned char* hashCommit;
  unsigned char** hashActual;
};


template<int QL, int degree, uint64_t w>
fheKey<QL, degree, w>::cryptoBackends::committedExcg::committedExcg(
    cryptoBackends* crypto, const int l, const int n, arithmeticNum** dst):
    backend(crypto), size(l), numberOfParty(n), receivedValues(dst) {
  myValue = new arithmeticNum[l];
  hashCommit = new unsigned char[SHA256_DIGEST_LENGTH];
  hashActual = new unsigned char * [n];
  for (int i = 0 ; i < n - 1 ; i++) {
    hashActual[i] = new unsigned char[SHA256_DIGEST_LENGTH];
  }
}


template<int QL, int degree, uint64_t w>
void fheKey<QL, degree, w>::cryptoBackends::committedExcg::push(arithmeticNum v){
  myValue[count] = v;
  count++;
}

template<int QL, int degree, uint64_t w>
void fheKey<QL, degree, w>::cryptoBackends::committedExcg::exchange(){
  SHA256((unsigned char*)myValue, sizeof(arithmeticNum) * size, hashCommit);
  backend->io->exchange((unsigned char **)hashActual, hashCommit, SHA256_DIGEST_LENGTH );
  backend->io->exchange((unsigned char **)receivedValues, (unsigned char *)myValue,
                  sizeof(arithmeticNum) * size);
  //compare hash
  unsigned char tmp[SHA256_DIGEST_LENGTH];
  for (int i = 0 ; i < numberOfParty - 1; i++) {
    SHA256((unsigned char*)receivedValues[i], sizeof(arithmeticNum) * size,
           tmp);
    for (int j = 0 ; j < SHA256_DIGEST_LENGTH  ; j++) {
      assert((tmp[j] ^ hashActual[i][j]) == 0);
    }
  }
  
  delete[] hashCommit;
  for (int i = 0 ; i < numberOfParty - 1 ; i++) {
      delete[] hashActual[i];
  }
  
  delete[] hashActual;
  delete[] myValue;
}
