#pragma once

template<int L, int degree>
class fheKey<L, degree>::cryptoBackends::secretKeySampling {
public:
  secretKeySampling(cryptoBackends* b);
  ~secretKeySampling();
  void generateSecretKey(poly<p0QL, 1>* dst);
  
private:
  cryptoBackends* backend;
//
  // construct a share of s1+s2 from a shared value of s' from a group of
  // parties and a shared value of s" from another group of parties
  void reSharing(int numberOfPartyThisRound);
  
  // mul each coefficient of s1 with the corresponding coefficient of s
//      void batchMul(poly<p0QL, 1>* s1, int numberOfPartyThisRound);
  poly<p0QL, 1>* s;
  rnsArithmetic<p0QL, 0> coefficient[4];
  d4TupleStack *tuples;
  // {3/8, -11/4, 45/8, -9/4}
};

template<int L, int degree>
fheKey<L, degree>::cryptoBackends::secretKeySampling::secretKeySampling(
    cryptoBackends* b):backend(b) {
  s = new poly<p0QL, 1>;
  rnsArithmetic<p0QL, 0> inverse2;
  for (int i = 0 ; i < p0QL ; i++) {
    //x = (rnsBase[i] + 1) / 2
    //x * 2 == 1 (mod rnsBase[i])
    arithmeticNum x = backend->keySet->rnsBase[i];
    x = x + 1;
    x = x << 1;
    inverse2.setValue(i, x);
  }
  
  rnsArithmetic<p0QL, 0> inverse4;
  
  backend->keySet->mulRns(&inverse4, &inverse2, &inverse2);
  rnsArithmetic<p0QL, 0> inverse8;
  backend->keySet->mulRns(&inverse8, &inverse2, &inverse4);
  
  
  rnsArithmetic<p0QL, 0> c[4];
  for (int i = 0 ; i <= L ; i++) {
    c[3].setValue(i, 3);
    c[2].setValue(i, -11);
    c[1].setValue(i, 45);
    c[0].setValue(i, -9);
  }
  
  backend->keySet->mulRns(&(coefficient[3]), &(c[3]), &inverse8);
  backend->keySet->mulRns(&(coefficient[2]), &(c[2]), &inverse4);
  backend->keySet->mulRns(&(coefficient[1]), &(c[1]), &inverse8);
  backend->keySet->mulRns(&(coefficient[0]), &(c[0]), &inverse4);
  
  tuples = backend->d4TupleOnRP0QLGen;
}

template<int L, int degree>
fheKey<L, degree>::cryptoBackends::secretKeySampling::~secretKeySampling() {
//  delete[] tuples;
  delete s;
}

template<int L, int degree>
void fheKey<L, degree>::cryptoBackends::secretKeySampling::generateSecretKey(
    poly<p0QL, 1>* dst) {
      
  for (int i = 0 ; i < degree ; i++) {
    char x = rand() % 3; //each party picks a random share
    backend->keySet->setSecretRns(s->getWritableCoefficient(i), x);
  }
#ifdef BM
  printf("mod-3 to arithmetic conversion, a.k.a. secret key sampling: \nvector length = %d\n", degree);
  backend->resetBW();
  auto time0 = clock_start();
#endif
  int n = 2;
  do {
    reSharing(n);
    n = n * 2;
  } while(n <= backend->keySet->numberOfParty);
  rnsArithmetic<p0QL, 0> offset;
  backend->keySet->setConstRns(&offset, -1);
  for (int i = 0 ; i < degree ; i++) {
    backend->keySet->addRns(dst->getWritableCoefficient(i),
                            s->getCoefficient(i), &offset, 1);
  }
#ifdef BM
  auto time1 = time_from(time0);
  printf("time = %Lf\n", time1);
  printf("B/W:\n");
  backend->printAndResetBW();
#endif
}


template<int L, int degree>
void fheKey<L, degree>::cryptoBackends::secretKeySampling::reSharing(
    int numberOfPartyThisRound) {
  // the partis add up s1 and s2 and compute f(s1+s2)
  
  // compute f(x) = 3/8 * x^4 - 11 / 4 * x^3 + 45 * 8 ^ -1 * x^2 - 9/4 * x
  // f(0) = 0
  // f(1) = 1
  // f(2) = 2
  // f(3) = 0
  // f(4) = 1
  
  int level = log2(numberOfPartyThisRound) - 1;
  d4Tuple** tuplesToUse;
  tuplesToUse = new d4Tuple*[degree];
  
  rnsArithmetic<p0QL, 1>* valuesToOpen;
  valuesToOpen = new rnsArithmetic<p0QL, 1>[degree];
  
  rnsArithmetic<p0QL, 0>* valuesOpened;
  valuesOpened = new rnsArithmetic<p0QL, 0>[degree];
  
  for (int i = 0 ; i < degree ; i++) {
    tuplesToUse[i] = tuples[level].getNextTuple();
    backend->keySet->addRns(&(valuesToOpen[i]), s->getWritableCoefficient(i),
                            &tuplesToUse[i]->v[0], 0);
  }
  
  backend->io->batchOpenRns(valuesOpened, valuesToOpen, degree,
                     numberOfPartyThisRound);
  delete[] valuesToOpen;
  
  // x^2 = (x - v)^2 + 2(x - v)v + v^2
  // x^3 = (x - v)^3 + 3(x - v)^2 * v + 3(x - v) * v^2 + v^3
  // x^4 = (x - v)^4 + 4(x - v)^3 * v + 6(x - v)^2 * v^2 + 4(x - v) * v^3 + v^4
  
  for (int i = 0 ; i < degree ; i++) {
    //(x - v)^2 , (x - v)^3, (x - v)^4,
    rnsArithmetic<p0QL, 0> publicCrossItem[3];
    
    /*
     2(x - v)v, 3(x - v)^2v, 4(x - v)^3v
     3(x - v) * v^2 , 6(x - v)^2 * v^2
     4(x - v) * v^3
    */
    rnsArithmetic<p0QL, 1> secretCrossItem[6];
    
    // x^2, x^3, x^4
    rnsArithmetic<p0QL, 1> x[3];
    
    {
      //(x - v)^2
      backend->keySet->mulRns(&publicCrossItem[0], &valuesOpened[i], &valuesOpened[i]);
      
      //(x - v)^3
      backend->keySet->mulRns(&publicCrossItem[1], &publicCrossItem[0],
                              &valuesOpened[i]);
      
      //(x - v)^4
      backend->keySet->mulRns(&publicCrossItem[2], &publicCrossItem[1],
                              &valuesOpened[i]);
      
      //(x - v) * v
      backend->keySet->mulRns(&secretCrossItem[0], &valuesOpened[i],
                              &(tuplesToUse[i]->v[0]));
      
      //(x - v)^2 * v
      backend->keySet->mulRns(&secretCrossItem[1], &valuesOpened[i],
                              &secretCrossItem[0]);
      
      //(x - v)^3 * v
      backend->keySet->mulRns(&secretCrossItem[2], &valuesOpened[i],
                              &secretCrossItem[1]);
      
      //(x - v) * v^2
      backend->keySet->mulRns(&secretCrossItem[3], &valuesOpened[i],
                              &(tuplesToUse[i]->v[1]));
      
      //(x - v)^2 * v^2
      backend->keySet->mulRns(&secretCrossItem[4], &valuesOpened[i],
                              &secretCrossItem[3]);
      
      //(x - v) * v^3
      backend->keySet->mulRns(&secretCrossItem[5], &valuesOpened[i],
                              &(tuplesToUse[i]->v[2]));
      
      //2 * (x - v) * v
      backend->keySet->addRns(&secretCrossItem[0], &secretCrossItem[0],
                              &secretCrossItem[0], 1);
      
      //3 * (x - v)^2 * v
      rnsArithmetic<p0QL, 1> tmp;
      backend->keySet->addRns(&tmp, &secretCrossItem[1],
                              &secretCrossItem[1], 1);
      backend->keySet->addRns(&secretCrossItem[1], &tmp,
                              &secretCrossItem[1], 1);
      
      //4 * (x - v)^3 * v
      backend->keySet->addRns(&tmp, &secretCrossItem[2],
                              &secretCrossItem[2], 1);
      backend->keySet->addRns(&secretCrossItem[2], &tmp, &tmp, 1);
      
      //3 * (x - v) * v ^2
      backend->keySet->addRns(&tmp, &secretCrossItem[3],
                              &secretCrossItem[3], 1);
      backend->keySet->addRns(&secretCrossItem[3], &tmp,
                              &secretCrossItem[3], 1);
      
      //6 * (x - v)^2 * v ^2
      backend->keySet->addRns(&tmp, &secretCrossItem[4],
                              &secretCrossItem[4], 1);
      backend->keySet->addRns(&tmp, &tmp, &secretCrossItem[4], 1);
      backend->keySet->addRns(&secretCrossItem[4], &tmp, &tmp, 1);
      
      
      //4 * (x - v) * v^3
      backend->keySet->addRns(&tmp, &secretCrossItem[5],
                              &secretCrossItem[5], 1);
      backend->keySet->addRns(&secretCrossItem[5], &tmp, &tmp, 1);
    }
    {
      backend->keySet->addRns(&x[0], &publicCrossItem[0], &secretCrossItem[0],
                              1);
      
      backend->keySet->addRns(&x[0], &x[0], &(tuplesToUse[i]->v[1]), 1);
      
      backend->keySet->addRns(&x[1], &publicCrossItem[1], &secretCrossItem[1],
                              1);
      backend->keySet->addRns(&x[1], &x[1], &secretCrossItem[3], 1);
      backend->keySet->addRns(&x[1], &x[1], &(tuplesToUse[i]->v[2]), 1);

      backend->keySet->addRns(&x[2], &publicCrossItem[2], &secretCrossItem[2], 1);
      backend->keySet->addRns(&x[2], &x[2], &secretCrossItem[4], 1);
      backend->keySet->addRns(&x[2], &x[2], &secretCrossItem[5], 1);
      backend->keySet->addRns(&x[2], &x[2], &(tuplesToUse[i]->v[3]), 1);
    }
    
    rnsArithmetic<p0QL, 1> newCoefficient;
    backend->keySet->mulRns(&newCoefficient, s->getWritableCoefficient(i),
                            &coefficient[0]);
    
    for (int j = 0 ; j < 2 ; j++) {
      rnsArithmetic<p0QL, 1> tmp;
      backend->keySet->mulRns(&tmp, &coefficient[j + 1], &x[j]);
      backend->keySet->addRns(&newCoefficient, &newCoefficient, &tmp, 1);
    }
    rnsArithmetic<p0QL, 1> tmp;
    backend->keySet->mulRns(&tmp, &coefficient[3], &x[2]);
    backend->keySet->addRns(s->getWritableCoefficient(i), &newCoefficient, &tmp, 1);
  }
  delete[] valuesOpened;
  delete[] tuplesToUse;
}
