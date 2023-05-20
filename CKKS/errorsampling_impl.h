#pragma once


template<int L, int degree>
template<int8_t ringSize>
class fheKey<L, degree>::cryptoBackends::errorSampling {
public:
  errorSampling(cryptoBackends* backend, int ID);
  ~errorSampling();
  void generateError(poly<ringSize, 1>* dst);
private:
  int myID = 0;
  cryptoBackends* backend;
  bitTupleStack* bitTupleGen;
  d2TupleStack<ringSize>* d2TupleGen;
  
  void batchAnd(sharedBit* dst, sharedBit* src1, sharedBit* src2, size_t size);
  void batchAdd(sharedBit** dst, sharedBit** src, int width, int repreat);
  
  poly<ringSize, 1>* tempResults;
  void batchComparison(sharedBit** dst);
  void reSharing(int numberOfPartyThisRound);
};

template<int L, int degree>
template<int8_t ringSize>
fheKey<L, degree>::cryptoBackends::errorSampling<ringSize>::errorSampling(cryptoBackends* crypto, int ID):backend(crypto), myID(ID) {
  tempResults = new poly<ringSize, 1>[widthOfError];
  if constexpr(ringSize == p0QL) {
    d2TupleGen = backend->d2TupleOnRP0QLGen;
  }
  if constexpr(ringSize == QL) {
    d2TupleGen = backend->d2TupleOnRQLGen;
  }
  bitTupleGen = backend->bitTupleGen;
}

template<int L, int degree>
template<int8_t ringSize>
fheKey<L, degree>::cryptoBackends::errorSampling<ringSize>::~errorSampling(){
  delete[] tempResults;
}

template<int L, int degree>
template<int8_t ringSize>
void fheKey<L, degree>::cryptoBackends::errorSampling<ringSize>::generateError(
    poly<ringSize, 1>* dst) {
#ifdef BM
  printf("sampling binary error: \nvector length = %d, ringSize = %d\n", degree, ringSize);
  backend->resetBW();
  auto time0 = clock_start();
#endif
  sharedBit** comparisonResults;
  comparisonResults = new sharedBit*[degree];
  for (int i = 0 ; i < degree ; i++) {
    comparisonResults[i] = new sharedBit[widthOfError];
  }
  batchComparison(comparisonResults);
  
  for (int i = 0 ; i < widthOfError; i++) {
    for (int j = 0 ; j < degree ; j++) {
      char x = rand() % 2;
      backend->keySet->setSecretRns(tempResults[i].getWritableCoefficient(j),
                               comparisonResults[j][i]);
    }
  }
  
  for (int i = 0 ; i < degree ; i++) {
    delete[] comparisonResults[i];
  }
  delete[] comparisonResults;
#ifdef BM
  auto time1 = time_from(time0);
  printf("time = %Lf\n", time1);
  printf("B/W:\n");
  backend->printAndResetBW();
  
    printf("binary to arithmetic conversion, a.k.a. secret key sampling: \nvector length = %d ringSize = %d\n", degree, ringSize);
   time0 = clock_start();
#endif
  int n = 2;
  do {
    reSharing(n);
    n = n * 2;
  } while(n <= backend->keySet->numberOfParty);
#ifdef BM
  time1 = time_from(time0);
  printf("time = %Lf\n", time1);
  printf("B/W:\n");
  backend->printAndResetBW();
#endif
  rnsArithmetic<ringSize, 0> offset;
  backend->keySet->setConstRns(&offset, -23);
  for (int i = 0 ; i < degree ; i++) {
    backend->keySet->setSecretRns(dst->getWritableCoefficient(i), 0);
    backend->keySet->addRns(dst->getWritableCoefficient(i),
                            dst->getCoefficient(i), &offset, 1);
  }
  
  for (int i = 0 ; i < widthOfError ; i++) {
    rnsArithmetic<ringSize, 0> scale;
    backend->keySet->setConstRns(&scale, 1 << i);
    for (int j = 0 ; j < degree ; j++) {
      backend->keySet->mulRns(tempResults[i].getWritableCoefficient(j),
                              tempResults[i].getCoefficient(j), &scale);
    }
    backend->keySet->addPoly(dst, dst, &tempResults[i]);
  }
}

template<int L, int degree>
template<int8_t ringSize>
void fheKey<L, degree>::cryptoBackends::errorSampling<ringSize>::
  batchAnd(sharedBit* dst, sharedBit* src1, sharedBit* src2, size_t size) {
    bitTuple** tuples = new bitTuple*[size];
    unsigned char* valuesToOpen = new unsigned char[size];
    unsigned char* valuesOpened = new unsigned char[size];
    for (int i = 0 ; i < size ; i++) {
      tuples[i] = bitTupleGen->getNextTuple();
      valuesToOpen[i] = ((src1[i] ^ tuples[i]->getA()) << 1) +
        (src2[i] ^ tuples[i]->getB());
    }
    backend->io->batchOpenBytes(valuesOpened, valuesToOpen, size);
    delete[] valuesToOpen;
    for (int i = 0 ; i < size ; i++) {
      dst[i] = tuples[i]->getC() ^ ((valuesOpened[i] >> 1) & tuples[i]->getB()) ^
          (valuesOpened[i] & src1[i]);
    }
    delete[] valuesOpened;
    delete[] tuples;
}
template<int L, int degree>
template<int8_t ringSize>
void fheKey<L, degree>::cryptoBackends::errorSampling<ringSize>::batchAdd(sharedBit** dst, sharedBit** src, int width, int repreat) {
  sharedBit* left = new sharedBit[degree * repreat];
  sharedBit* right = new sharedBit[degree * repreat];
  sharedBit* output = new sharedBit[degree * repreat];
  for (int i = 0 ; i < degree ; i++) {
    for (int j = 0 ; j < repreat ; j++) {
      dst[i][(width + 1) * j + width] = src[i][2 * width * j + width - 1] ^
        src[i][2 * width * (j + 1) - 1];
      left[i * repreat + j] = src[i][2 * width * j + width - 1];
      right[i * repreat + j] =  src[i][2 * width * (j + 1) - 1];
    }
  }
  
  batchAnd(output, left, right, degree * repreat);
  
  for (int bit = 1 ; bit < width ; bit++) {
    for (int i = 0 ; i < degree ; i++) {
      for (int j = 0 ; j < repreat ; j++) {
        left[i * repreat + j] = src[i][2 * width * j + width - 1 - bit];
        left[i * repreat + j] ^= output[i * repreat + j];
        
        right[i * repreat + j] = src[i][2 * width * (j + 1) - 1 - bit];
        right[i * repreat + j] ^= output[i * repreat + j];
        
        dst[i][(width + 1) * j + width - bit] = left[i * repreat + j] ^
          src[i][2 * width * (j + 1) - 1 - bit];
      }
    }
    batchAnd(output, left, right, degree * repreat);
  }
  
  
  delete[] left;
  delete[] right;
  
  for (int i = 0 ; i < degree ; i++) {
    for (int j = 0 ; j < repreat ; j++) {
      dst[i][(width + 1) * j] = output[i * repreat + j];
    }
  }
  delete[] output;
  
}

template<int L, int degree>
template<int8_t ringSize>
void fheKey<L, degree>::cryptoBackends::errorSampling<ringSize>::batchComparison(
    sharedBit** dst) {
  // if the sampled random value larger than the threashold
  // comparsion:
  // c: pervious result; a, b: two bits
  // mux(a xor b, c, a) = c xor ((c xor a) AND  (a xor b));
  sharedBit** result = new sharedBit*[degree];
  for (int i = 0 ; i < degree ; i++) {
    result[i] = new sharedBit[numberOfThreshold];
    for (int j = 0 ; j < numberOfThreshold ; j++) {
      sharedBit notX = rand() & 1; // share of not x
      result[i][j] =  ((normalThreshold[j] & 1) ^ 1) & notX;
    }
  }
  
  sharedBit* output = new sharedBit[degree * numberOfThreshold];
  sharedBit* left = new sharedBit[degree * numberOfThreshold];
  sharedBit* right = new sharedBit[degree * numberOfThreshold];
  
  for (int i = 1 ; i < lengthOfThreshold ; i++) {
    for (int j = 0 ; j < degree ; j++) {
      sharedBit x = rand() & 1;
      for (int k = 0 ; k < numberOfThreshold ; k++) {
        left[j * numberOfThreshold + k] = result[j][k] ^ x;
        right[j * numberOfThreshold + k] = x ^ ((normalThreshold[k] >> i) & 1);
      }
    }
    batchAnd(output, left, right, degree * numberOfThreshold);
    for (int j = 0 ; j < degree ; j++) {
      for (int k = 0 ; k < numberOfThreshold ; k++) {
        result[j][k] ^= output[j * numberOfThreshold + k];
      }
    }
  }
  
  sharedBit** result1 = new sharedBit*[degree];
  for (int i = 0 ; i < degree ; i++) {
    result1[i] = new sharedBit[16];
  }
  //1 * 24 -> 2 * 8 -> 3 * 4 -> 4 * 2 -> 5 * 1
  
  for (int i = 0 ; i < degree ; i++) {
    for(int j = 0 ; j < 8 ; j++) {
      left[i * 8 + j] = result[i][3 * j] ^ result[i][3 * j + 1];
      right[i * 8 + j] = result[i][3 * j] ^ result[i][3 * j + 2];
      result1[i][2 * j + 1] = left[i * 8 + j] ^ result[i][3 * j + 2];
    }
  }
  batchAnd(output, left, right, degree * 8);
  for (int i = 0 ; i < degree ; i++) {
    for(int j = 0 ; j < 8 ; j++) {
      result1[i][2 * j] = output[i * 8 + j];
    }
  }
  
  delete[] output;
  delete[] left;
  delete[] right;
  
  batchAdd(result, result1, 2, 4); // 8
  batchAdd(result1, result, 3, 2); // 6
  batchAdd(result, result1, 4, 1); // 4

  sharedBit sign = rand() & 1;
  for (int i = 0 ; i < degree ; i++) {
    for (int j = 0 ; j < 5 ; j++) {
      result[i][j] = result[i][j] ^ sign;
      result[i][j + 5] = 0;
    }
    result[i][10] = sign;
  }
  batchAdd(result1, result, 5, 1); // 5
  
  for (int i = 0 ; i < degree ; i++) {
    for (int j = 0 ; j < 5 ; j++) {
      result[i][j] = result[i][j + 1];
    }
    if (myID != 0) {
      for (int j = 0 ; j < 5 ; j++) {
        result[i][j + 5] = 0;
      }
    } else {
      result[i][5] = 1;
      result[i][6] = 0;
      result[i][7] = 1;
      result[i][8] = 1;
      result[i][9] = 1;
    }
  }
  batchAdd(dst, result1, 5, 1); // 5
  for (int i = 0 ; i < degree ; i++) {
    delete[] result[i];
    delete[] result1[i];
  }
  delete[] result;
  delete[] result1;
}


template<int L, int degree>
template<int8_t ringSize>
void fheKey<L, degree>::cryptoBackends::errorSampling<ringSize>::reSharing(
    int numberOfPartyThisRound) {
  int level = log2(numberOfPartyThisRound) - 1;
  // compute f(x) = (2 - x) * x
  // f(0) = 0
  // f(1) = 1
  // f(2) = 0
  
  // 2 - x
  poly<ringSize, 1> tempResults1[widthOfError];

  d2Tuple<ringSize>** tuplesToUse;
  tuplesToUse = new d2Tuple<ringSize>*[degree * widthOfError];
  
  rnsArithmetic<ringSize, 1>* valuesToOpen;
  valuesToOpen = new rnsArithmetic<ringSize, 1>[degree * widthOfError];
  
  rnsArithmetic<ringSize, 0>* valuesOpened;
  valuesOpened = new rnsArithmetic<ringSize, 0>[degree * widthOfError];

  
  for (int i = 0 ; i < widthOfError ; i++) {
      for (int j = 0 ; j < degree ; j++) {
        tuplesToUse[i * degree + j] = d2TupleGen[level].getNextTuple();

        backend->keySet->addRns(&(valuesToOpen[i * degree + j]),
                                tempResults[i].getCoefficient(j),
                                &tuplesToUse[i * degree + j]->v[0], 0);
    }
  }
  
  backend->io-> batchOpenRns(valuesOpened, valuesToOpen,
                           degree * widthOfError,
                           numberOfPartyThisRound);
  
  delete[] valuesToOpen;
  
  // x^2 = (x - v)^2 + 2 * (x - v) * v + v^2
  //    2 * x - x^2 * 2
  // = 2 * (x - (x - v)^2 - 2 * (x - v) * v - v^2)
  
  for (int i = 0 ; i < widthOfError ; i++) {
      for (int j = 0 ; j < degree ; j++) {
        rnsArithmetic<ringSize, 1> tmp;
        rnsArithmetic<ringSize, 1> tmp1;
        
        backend->keySet->mulRns(&tmp1, &valuesOpened[i * degree + j],
                                &valuesOpened[i * degree + j]);
        backend->keySet->addRns(&tmp, tempResults[i].getCoefficient(j), &tmp1,
                                0);
        
        backend->keySet->mulRns(&tmp1, &valuesOpened[i * degree + j],
                                &tuplesToUse[i * degree + j]->v[0]);
        backend->keySet->addRns(&tmp, &tmp, &tmp1, 0);
        backend->keySet->addRns(&tmp, &tmp, &tmp1, 0);
        backend->keySet->addRns(&tmp, &tmp, &tuplesToUse[i * degree + j]->v[1],
                                0);
        backend->keySet->addRns(tempResults[i].getWritableCoefficient(j),
                                &tmp, &tmp, 1);
        
    }
  }
  delete[] valuesOpened;
  delete[] tuplesToUse;
}
