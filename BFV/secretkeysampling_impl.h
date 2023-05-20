#pragma once

template<int QL, int degree, uint64_t w>
class fheKey<QL, degree, w>::cryptoBackends::secretKeySampling {
public:
  secretKeySampling(cryptoBackends* b);
  ~secretKeySampling();
  void generateSecretKey(poly<QL, 1>* dst);
  
private:
  cryptoBackends* backend;
//
  // construct a share of s1+s2 from a shared value of s' from a group of
  // parties and a shared value of s" from another group of parties
  void reSharing(int numberOfPartyThisRound);
  
  // mul each coefficient of s1 with the corresponding coefficient of s
//      void batchMul(poly<QL, 1>* s1, int numberOfPartyThisRound);
  poly<QL, 1>* s;
  d2TupleStack<QL>* tuples;
};

template<int QL, int degree, uint64_t w>
fheKey<QL, degree, w>::cryptoBackends::secretKeySampling::secretKeySampling(
    cryptoBackends* b):backend(b) {
  s = new poly<QL, 1>;
  
  tuples = backend->d2TupleOnRQLGen;
}

template<int QL, int degree, uint64_t w>
fheKey<QL, degree, w>::cryptoBackends::secretKeySampling::~secretKeySampling() {
  delete s;
}

template<int QL, int degree, uint64_t w>
void fheKey<QL, degree, w>::cryptoBackends::secretKeySampling::generateSecretKey(
    poly<QL, 1>* dst) {
      
  for (int i = 0 ; i < degree ; i++) {
    char x = rand() % 2; //each party picks a random share
    backend->keySet->setSecretRns(s->getWritableCoefficient(i), x);
  }
  int n = 2;
  do {
    reSharing(n);
    n = n * 2;
  } while(n <= backend->keySet->numberOfParty);
}


template<int QL, int degree, uint64_t w>
void fheKey<QL, degree, w>::cryptoBackends::secretKeySampling::reSharing(
    int numberOfPartyThisRound) {

  
  int level = log2(numberOfPartyThisRound) - 1;
  // compute f(x) = (2 - x) * x
  // f(0) = 0
  // f(1) = 1
  // f(2) = 0
  
  d2Tuple<QL>** tuplesToUse;
  tuplesToUse = new d2Tuple<QL>*[degree];
  
  rnsArithmetic<QL, 1>* valuesToOpen;
  valuesToOpen = new rnsArithmetic<QL, 1>[degree];
  
  rnsArithmetic<QL, 0>* valuesOpened;
  valuesOpened = new rnsArithmetic<QL, 0>[degree];
  
  for (int i = 0 ; i < degree ; i++) {
    tuplesToUse[i] = tuples[level].getNextTuple();
    backend->keySet->addRns(&(valuesToOpen[i]), s->getWritableCoefficient(i),
                            &tuplesToUse[i]->v[0], 0);
  }
  
  backend->io->batchOpenRns(valuesOpened, valuesToOpen, degree,
                     numberOfPartyThisRound);
  delete[] valuesToOpen;
  // x^2 = (x - v)^2 + 2 * (x - v) * v + v^2
  //    2 * x - x^2 * 2
  // = 2 * (x - (x - v)^2 - 2 * (x - v) * v - v^2)

  for (int i = 0 ; i < degree ; i++) {
    rnsArithmetic<QL, 1> tmp;
    rnsArithmetic<QL, 1> tmp1;
    backend->keySet->mulRns(&tmp1, &valuesOpened[i], &valuesOpened[i]);
    backend->keySet->addRns(&tmp, s->getWritableCoefficient(i), &tmp1, 0);
    backend->keySet->mulRns(&tmp1, s->getWritableCoefficient(i),
                            &valuesOpened[i]);
    backend->keySet->addRns(&tmp, &tmp, &tmp1, 0);
    backend->keySet->addRns(&tmp, &tmp, &tmp1, 0);
    backend->keySet->addRns(&tmp, &tmp, &tuplesToUse[i]->v[1], 0);
    
    backend->keySet->addRns(s->getWritableCoefficient(i), &tmp, &tmp, 1);
  }
  delete[] valuesOpened;
  delete[] tuplesToUse;
}
