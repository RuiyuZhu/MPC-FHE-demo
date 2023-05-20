#pragma once
#include <gmp.h>
//ring<QL> RQL;

template<int QL, int degree, uint64_t w>
fheKey<QL, degree, w>::fheKey(const rnsBasePrime base, int ID, int n,
                          const char** address, int defaultPortNo,
                          __m128i maskerKey): ell(getell()), rnsBase(base), myID(ID),
                          numberOfParty(n) {
  backend = new cryptoBackends(this, ID, n, address, defaultPortNo,
                               maskerKey);
  RQL = new ring<QL>(this);
  s = new poly<QL, 1>;
  maxLen = ceil(log2(w));
  for (int i = 0 ; i < QL ; i++) {
    maxLen += ceil(log2(rnsBase[i]));
  }
  maxLen = (maxLen + 7) / 8;
}
template<int QL, int degree, uint64_t w>
fheKey<QL, degree, w>::~fheKey() {
  delete s;
  delete backend;
  delete RQL;
}

template<int QL, int degree, uint64_t w>
void fheKey<QL, degree, w>::keyGen(pvtKeyOnRing* privateKey, swKey* switchKey,
                               pubKey* publicKey) {

  // switch key variables
  poly<QL, 1> polyforErrorQL[ell + 2];
  auto time0 = clock_start();
  // online computation - sampling
  {
    
    sampleSecretKey(s);
    printf("Sampled secret key\n");

    for (int i = 0 ; i < ell + 2 ; i++) {
      sampleError<QL>(&polyforErrorQL[i]);
    }
    printf("Sampled evl key\n");
  }
  
  
  
  // private key variables
  typename ring<QL>::template element<1>* privateKeyOnRing;
  privateKeyOnRing = &(privateKey->s);
  
  // public key variable
  typename ring<QL>::template element<1> errorOnRingQL;
  
  // switch key variables
  typename ring<QL>::template element<1> s1;
  
  
  //local computation
  {
    RQL->convert(privateKeyOnRing, s);
    RQL->convert(&errorOnRingQL, &polyforErrorQL[0]);
    RQL->sampleUniformElement(&(publicKey->a));
  }

  
  // local computation - mulplication
  {
    // public key code
    // a * s, online computation - mulplication
    RQL->mulElement(&(publicKey->b), &(publicKey->a), privateKeyOnRing);
    RQL->addElement(&(publicKey->b), &(publicKey->b), &errorOnRingQL, 1);
  }
  // online computation - mulplication
  {
    //switch key code
    RQL->squareElement(&s1, privateKeyOnRing);
  }
  typename ring<QL>::template element<0> wOnRing;
  RQL->setConstElement(&wOnRing, w);
  typename ring<QL>::template element<1> offSet;
  
  //local computation
  {
    RQL->convert(&errorOnRingQL, &polyforErrorQL[1]);
    RQL->sampleUniformElement(&(switchKey->a[0]));
    RQL->mulElement(&(switchKey->b[0]), &(switchKey->a[0]),
                    privateKeyOnRing);
    RQL->addElement(&(switchKey->b[0]), &(switchKey->b[0]),
                    &errorOnRingQL, 1);
    RQL->addElement(&(switchKey->b[0]), privateKeyOnRing,
                    &(switchKey->b[0]), 1);
    RQL->mulElement(&offSet, privateKeyOnRing, &wOnRing);
    for (int i = 1 ; i < ell + 1 ; i++) {
      RQL->convert(&errorOnRingQL, &polyforErrorQL[i + 1]);
      RQL->sampleUniformElement(&(switchKey->a[i]));
      RQL->mulElement(&(switchKey->b[i]), &(switchKey->a[i]),
                      privateKeyOnRing);
      RQL->addElement(&(switchKey->b[i]), &(switchKey->b[i]),
                      &errorOnRingQL, 1);
      RQL->addElement(&(switchKey->b[i]), &offSet, &(switchKey->b[i]), 1);
      RQL->mulElement(&offSet, &offSet, &wOnRing);
    }
  }
  auto time1 = time_from(time0);
  printf("Total time = %Lf\n", time1);
  printf("Total B/W:\n");
  backend->printAndResetBW();
}

template<int QL, int degree, uint64_t w>
template<int8_t ringSize>
void fheKey<QL, degree, w>::open(rnsArithmetic<ringSize, 1>* shared) {
  if (myID == 0 ){
    rnsArithmetic<ringSize, 1> tmp;
    receiveRNSFromPortion(&tmp, numberOfParty);
    addRns(&shared, &shared, &tmp, 1);
  } else {
    sendRNSToPortion(shared, numberOfParty);
    setSecretRns(&shared, 0);
  }
}


// code for secret sampling

template<int QL, int degree, uint64_t w>
void fheKey<QL, degree, w>::sampleSecretKey(poly<QL, 1>* dst) {
  typename cryptoBackends::secretKeySampling secSample(backend);
  secSample.generateSecretKey(dst);
}

// convert the secret from represented in rns{p0, q1, ..., qL} to represented
// in rns{q1,...,qL}
template<int QL, int degree, uint64_t w>
template<int d>
void fheKey<QL, degree, w>::truncate(poly<d, 1>* dst,
                                 const poly<QL, 1>* src) {
  for (int i = 0; i < degree; i++) {
    for (int j = 0 ; j < d ; j++) {
      dst->getWritableCoefficient(i)->setValue(j, src->getCoefficient(i)
                                                     ->getValue(j));
    }
  }
}


// code for error sampling

template<int QL, int degree, uint64_t w>
template<int8_t ringSize>
void fheKey<QL, degree, w>::sampleError(poly<ringSize, 1>* dst) {
  typename cryptoBackends::template errorSampling<ringSize> errorSample(backend);
    errorSample.generateError(dst);
}

template<int QL, int degree, uint64_t w>
void fheKey<QL, degree, w>::dec(plaintext* dst, ciphertext* src,
                            pvtKeyOnRing* key) {

  mpz_t mod;
  mpz_init(mod);
  mpz_set_ui(mod, 1);
  mpz_t crtCoefficientsMPZ[QL];

  for (int i = 0 ; i < QL ; i++) {
    mpz_mul_ui(mod, mod, rnsBase[i]);
  }

  for (int i = 0 ; i < QL ; i++) {
    mpz_init(crtCoefficientsMPZ[i]);
    mpz_set_ui(crtCoefficientsMPZ[i], 1);
  }
  
  for (int i = 0 ; i < QL ; i++) {
    for (int j = 0 ; j < QL ; j++) {
      if (j != i) {
        mpz_mul_ui(crtCoefficientsMPZ[i], crtCoefficientsMPZ[i], rnsBase[i]);
      }
    }
  }
  mpz_t invertTmp;
  mpz_init(invertTmp);
  for (int i = 0 ; i < QL ; i++) {
    mpz_set_ui(invertTmp, rnsBase[i]);
    mpz_invert(invertTmp, invertTmp, mod);
    mpz_mod(crtCoefficientsMPZ[i], invertTmp, mod);
  }
  mpz_clear(invertTmp);
  
  int totalWidth = mpz_sizeinbase(mod, 2);
  unsigned char *tmpResult = new unsigned char[degree * totalWidth];
  unsigned char *modular = new unsigned char[totalWidth];
  if (myID == 0) {
    unsigned char *modulartmp = new unsigned char[totalWidth + 2];
    mpz_get_str((char*)modulartmp, 2, mod);
    for(int i = 0 ; i < totalWidth ; i++) {
      if(modulartmp[i] == '0') {
        modular[i] = 0;
      } else {
        modular[i] = 1;
      }
    }
    delete[] modulartmp;
  } else {
    for (int i = 0 ; i < totalWidth ; i++) {
      modular[i] = 0;
    }
  }
  auto time0 = clock_start();
  typename ring<QL>::template element<1> tmp;
  RQL->mulElement(&tmp, &(src->c1), &(key->s));
  RQL->addElement(&tmp, &tmp, &(src->c0), 1);
  poly<QL, 1> m;
  RQL->InverseConvert(&m, &tmp);
  
  for (int i = 0 ; i < degree ; i++) {
    mpz_t adder;
    mpz_t sum;
    mpz_init(adder);
    mpz_init(sum);
    for (int j = 0 ; j < QL ; j++) {
      mpz_mul_ui(adder, crtCoefficientsMPZ[j],
                 m.getCoefficient(i)->getValue(j));
      mpz_add(sum, sum, adder);
    }
    unsigned char *modulartmp = new unsigned char[totalWidth + 2];
    mpz_get_str((char*)modulartmp, 2, sum);
    for(int j = 0 ; j < totalWidth ; j++) {
      if(modulartmp[j] == '0') {
        tmpResult[i * totalWidth + j] = 0;
      } else {
        tmpResult[i * totalWidth + j] = 1;
      }
    }
    delete[] modulartmp;
    mpz_clear(adder);
    mpz_clear(sum);
  }
  for (int i = 0 ; i < QL ; i++) {
    mpz_clear(crtCoefficientsMPZ[i]);
  }
  mpz_clear(mod);
  rnsArithmetic<1, 1>* offSet = new rnsArithmetic<1, 1>[degree];
  int n = 2;
  while(n <= numberOfParty) {
    backend->arithmeticToBinaryReshareSpecial(tmpResult, offSet,
                                              totalWidth, degree, modular, 1, n);
    n *= 2;
    for (int i = 0 ; i < degree ; i++) {
      addRns(dst->m.getWritableCoefficient(i),
             dst->m.getCoefficient(i), &offSet[i]);
    }
  }
  auto time1 = time_from(time0);
  printf("Decode time = %Lf\n", time1);
  printf("Decode B/W:\n");
  backend->printAndResetBW();
  delete[] tmpResult;
  delete[] modular;

  delete[] offSet;
  
}
