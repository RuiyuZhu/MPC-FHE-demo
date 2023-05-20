#pragma once
//ring<QL> RQL;
//ring<p0QL> RP0QL;

template<int L, int degree>
fheKey<L, degree>::fheKey(const rnsBasePrime base, int ID, int n,
                          const char** address, int defaultPortNo,
                          __m128i maskerKey): rnsBase(base), myID(ID),
                          numberOfParty(n) {
  backend = new cryptoBackends(this, ID, n, address, defaultPortNo,
                               maskerKey);
  Rq0 = new ring<1>(this);
  RQL = new ring<QL>(this);
  RP0QL = new ring<p0QL>(this);
  s = new poly<p0QL, 1>;
}
template<int L, int degree>
fheKey<L, degree>::~fheKey() {
  delete s;
  delete backend;
  delete Rq0;
  delete RQL;
  delete RP0QL;
}

template<int L, int degree>
void fheKey<L, degree>::keyGen(pvtKeyOnRing* privateKey, swKey* switchKey,
                               pubKey* publicKey) {
    // private key variables
  typename ring<QL>::template element<1> privateKeyOnRing;
  
    // public key variable
  poly<QL, 1> polyforErrorQL;
  typename ring<QL>::template element<1> errorOnRingQL;
  
    // switch key variables
  int switchKeyIter = L + 1;
#ifdef BM
  switchKeyIter = 1;
#endif
  
  typename ring<p0QL>::template element<1> s2;
  typename ring<p0QL>::template element<1> s1;
  poly<p0QL, 1> polyforErrorP0QL[switchKeyIter];
  typename ring<p0QL>::template element<1> errorOnRingP0QL[switchKeyIter];



  
  auto time0 = clock_start();
  // online computation - sampling
  {
     printf("Next: Sampled secret key\n");
    sampleSecretKey(s);
    printf("Sampled secret key done\n");
    
    printf("next: Sampled error on QL\n");
    sampleError<QL>(&polyforErrorQL);
    printf("Sampled error on QL done\n");
    
    printf("Next: Sampled error on P0QL\n");
    for (int i = 0 ; i < switchKeyIter ; i++) {
      sampleError<p0QL>(&polyforErrorP0QL[i]);
      printf("Sampled error %d on P0QL\n", i);
    }
    printf("Sampled error on P0QL Done\n");
  }
  
  pvtKeyInPoly privateKeyInPoly;
  //local computation
  {
    //private key code;
    truncate<QL>(&privateKeyInPoly, s);
    
    
    printf("Next: NTT\n");
    printf("Next: secretKey NTT\n");
    RP0QL->convert(&s2, s);
    
    printf("Next: publicKey error NTT\n");
    RQL->convert(&errorOnRingQL, &polyforErrorQL);
    for (int i = 0 ; i < switchKeyIter ; i++) {
      printf("Next: switchKey error NTT %d\n", i);
      RP0QL->convert(&errorOnRingP0QL[i], &polyforErrorP0QL[i]);
    }
      // online computation - mulplication
    {
        //switch key code
      RP0QL->squareElement(&s1, &s2);
    }
    
    for (int i = 0 ; i < degree ; i++) {
      arithmeticNum tmp;
      tmp = s2.getValue(i)->getValue(0);
      privateKey->s.getWritableValue(i)->setValue(0, tmp);
      for (int j = 1 ; j < QL ; j++) {
        tmp = s2.getValue(i)->getValue(j);
        privateKeyOnRing.getWritableValue(i)->setValue(j, tmp);
      }
    }
  }

  // local computation - mulplication
  {
    // public key code
    // a * s, online computation - mulplication
    RQL->mulElement(&(publicKey->b), &(publicKey->a), &privateKeyOnRing);
  }

  //local computation
  {
    //public key code
    //e - a * s local computation
    RQL->addElement(&(publicKey->b), &errorOnRingQL, &(publicKey->b), 0);
  }
  {
    //switch key code
    for (int i = 0 ; i < switchKeyIter ; i++) {
      RP0QL->sampleUniformElement(&(switchKey->a[i]));
    }
    for (int i = 0 ; i < switchKeyIter ; i++) {
      RP0QL->mulElement(&(switchKey->b[i]), &(switchKey->a[i]), &s2);
      RP0QL->addElement(&(switchKey->b[i]), &errorOnRingP0QL[i],
                        &(switchKey->b[i]), 0);
      typename ring<p0QL>::template element<1> tmp;
      RP0QL->truncateElementWithP(&tmp, &s1, i);
        // e - s2 * a + Bi * s1, local computation
      RP0QL->addElement(&(switchKey->b[i]), &(switchKey->b[i]), &tmp);
    }
  }
  auto time1 = time_from(time0);
  printf("Total time = %Lf\n", time1);
  printf("Total B/W:\n");
  backend->printAndResetBW();
}

template<int L, int degree>
template<int8_t ringSize>
void fheKey<L, degree>::open(rnsArithmetic<ringSize, 1>* shared) {
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

template<int L, int degree>
void fheKey<L, degree>::sampleSecretKey(poly<p0QL, 1>* dst) {
  typename cryptoBackends::secretKeySampling secSample(backend);
  secSample.generateSecretKey(dst);
}

// convert the secret from represented in rns{p0, q1, ..., qL} to represented
// in rns{q1,...,qL}
template<int L, int degree>
template<int d>
void fheKey<L, degree>::truncate(poly<d, 1>* dst,
                                 const poly<p0QL, 1>* src) {
  for (int i = 0; i < degree; i++) {
    for (int j = 0 ; j < d ; j++) {
      dst->getWritableCoefficient(i)->setValue(j, src->getCoefficient(i)
                                                     ->getValue(j));
    }
  }
}


// code for error sampling

template<int L, int degree>
template<int8_t ringSize>
void fheKey<L, degree>::sampleError(poly<ringSize, 1>* dst) {
  typename cryptoBackends::template errorSampling<ringSize> errorSample(backend, myID);
  errorSample.generateError(dst);
}

template<int L, int degree>
template<int n>
void fheKey<L, degree>::dec(plaintext* dst, ciphertext* src,
                            pvtKeyOnRing* key) {
  
  auto time0 = clock_start();
//  backend->template batchMul<1, n> (dst->message, src->c1, &(key->s));
  for (int i = 0 ; i < n ; i++) {
    Rq0->mulElement(&(dst->message[i]), &(src->c1[i]), &(key->s));
    Rq0->addElement(&(dst->message[i]), &(dst->message[i]), &(src->c0[i]), 1);
  }
  typename ring<1>::template element<1> tmp;
  for (int i = 0 ; i < n ; i++) {
    backend->openRingElement(&(dst->message[i]), &tmp);
  }
  auto time1 = time_from(time0);
  printf("Decode time = %Lf\n", time1);
  printf("Decode B/W:\n");
  backend->printAndResetBW();
}
