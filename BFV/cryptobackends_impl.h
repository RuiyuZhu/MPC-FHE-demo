#pragma once

int count = testL * testL * 3;
static const uint16_t byteKeyword[16] = {0xff00, 0xf0f0, 0x0ff0, 0xcccc, 0x33cc,
  0x3c3c, 0xc33c, 0xaaaa, 0x55aa, 0x5a5a, 0xa55a, 0x6666, 0x9966, 0x9696,
  0x6996};
static __m128i binaryChoice[2];
static __m256i byteChoice[16];

inline __m128i replicate128(bool c) {
  if (c) {
    return _mm_set_epi32(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF);
  }
  else {
    return _mm_set_epi32(0, 0, 0, 0);
  }
}

inline __m256i replicate256(unsigned char t) {
  unsigned char tmp[15];
  for (int i = 0 ; i < 15 ; i++) {
    tmp[i] = (byteKeyword[t] >> (1 + i)) ^ (byteKeyword[t] << (14 - i));
  }
  return _mm256_set_epi8(tmp[0], tmp[1], tmp[2], tmp[3], tmp[4], tmp[5],
                         tmp[6], tmp[7], tmp[8], tmp[9], tmp[10], tmp[11],
                         tmp[12], tmp[13], tmp[14], tmp[0], tmp[1], tmp[2],
                         tmp[3], tmp[4], tmp[5], tmp[6], tmp[7], tmp[8],
                         tmp[9], tmp[10], tmp[11], tmp[12], tmp[13], tmp[14],
                         0, 0);
}

template<int QL, int degree, uint64_t w>
class fheKey<QL, degree, w>::cryptoBackends {
public:
  cryptoBackends(fheKey* parent, int myID, int numberOfParty,
                 const char** address, int defaultPortNo, __m128i key);
  ~cryptoBackends();

  class secretKeySampling;
  
  template<int8_t ringSize> class errorSampling;
  
  template<int8_t ringSize>
  void squareBatchRns(rnsArithmetic<ringSize, 1>* dst,
                      const rnsArithmetic<ringSize, 1>* src,
                      size_t size, int numberOfPartyThisRound);
  
  template<int8_t ringSize, int n>
  void batchMul(typename ring<ringSize>::template element<1>* dst,
                typename ring<ringSize>::template element<1>* src1,
                typename ring<ringSize>::template element<1>* src2);
  
  void printAndResetBW() const {
    io->printAndResetBW();
  }
  
  typedef unsigned char sharedBit;
  void arithmeticToBinaryReshare(sharedBit* dst, int width, size_t size, sharedBit* base, size_t baseSize, int numberOfPartyThisRound);
  void arithmeticToBinaryReshareSpecial(sharedBit* dst, rnsArithmetic<1, 1>* offset, int width, size_t size, sharedBit* base, size_t baseSize, int numberOfPartyThisRound);
  void binaryToArithmeticReshareSpecial(rnsArithmetic<1, 1>* dst, size_t size, int numberOfPartyThisRound);
  void batchAnd(sharedBit* dst, sharedBit* src1, sharedBit* src2, size_t size,
                const bool randomRight = false, int numberOfPartyThisRound = 0);
  void batchAdd(sharedBit* dst, sharedBit* src1, sharedBit* src2, int width, size_t size, int numberOfPartyThisRound = 0, bool sign = 1);
  
  void batchCompare(sharedBit* dst, sharedBit* src1, int width, size_t size, sharedBit* src2, size_t src2Size, int numberOfPartyThisRound);
  void getBinary(sharedBit *dst, uint32_t src, int width) const;
private:
  class obliviousTransfer;
  
  template<typename TupleType, int8_t ringSize = 0, int vecLen = 0>
  class tupleStack;
  

  class bitTuple;
//  class bitTupleStack;
  using bitTupleStack = tupleStack<bitTuple>;

    // secret shared random tuples such that v[i] = v[0]^(i + 1)
  template<int8_t ringSize>
  struct d2Tuple;
  
//  template<int8_t ringSize>
//  class d2TupleStack;
  template<int8_t ringSize>
  using d2TupleStack = tupleStack<d2Tuple<ringSize>, ringSize>;

  
  template<int8_t ringSize, int vecLen>//a vec by element multiplication tuple
  struct mulTuple;
  
  template<int8_t ringSize, int vecLen>
  using mulTupleStack = tupleStack<mulTuple<ringSize, vecLen>, ringSize, vecLen>;
  
//  template<int8_t ringSize, int vecLen>//a vec by element multiplication tuple
//  class mulTupleStack;
  
  void prg(__m128i* dst, size_t size, AES_KEY* Key, uint64_t keyIndex);
  void generateRandomBytes(unsigned char* dst, size_t size);
  
  template<int8_t ringSize>
  void generateRandomShares(rnsArithmetic<ringSize, 0>* dst, size_t size);
  
  // compute dot product in src provided by two parties
  template<int8_t ringSize>
  void generateMultiplicativeShares(rnsArithmetic<ringSize, 1>* dst,
                                    rnsArithmetic<ringSize, 1>* src,
                                    size_t size, int ID);

  


  class network;

  d2TupleStack<QL>* d2TupleOnRQLGen = nullptr;
  d2TupleStack<1>* d2TupleOnR1Gen = nullptr;
  bitTupleStack* bitTupleGen = nullptr;
  bitTupleStack* leveledBitTupleGen = nullptr;
  
  network* io;
  fheKey* keySet;
  obliviousTransfer* OT;
  uint64_t randomIndex = 0;
  std::mutex randomIndexMutex;
  __m128i masterKey;
  AES_KEY maskerAESKey;
};

template<int QL, int degree, uint64_t w>
fheKey<QL, degree, w>::cryptoBackends::cryptoBackends(fheKey* parent, int myID,
                                                  int numberOfParty,
                                                  const char** address,
                                                  int defaultPortNo,
                                                  __m128i key):keySet(parent){
  masterKey = key;
  AES_set_encrypt_key(masterKey, &maskerAESKey);
  io = new network(address, myID, numberOfParty,defaultPortNo, this);
  
  for (int i = 0 ; i < 16 ; i++) {
    byteChoice[i] = replicate256(i);
  }
  binaryChoice[0] = replicate128(0);
  binaryChoice[1] = replicate128(1);
  
  
  int level = log2(numberOfParty);
  
  OT = new obliviousTransfer[numberOfParty];
  for (int i = 0 ; i < numberOfParty ; i++) {
    if (i != myID) {
      OT[i].setup(this, i);
    }
  }
  d2TupleOnRQLGen = new d2TupleStack<QL>[level];
  bitTupleGen = new bitTupleStack;
  d2TupleOnR1Gen = new d2TupleStack<1>[level];
  
  int totalBitTuple = (degree * (numberOfThreshold *
                                 (lengthOfThreshold - 1) + 56) *
                       (keySet->ell + 2));
//  auto time0 = clock_start();
  bitTupleGen->generateTuples(totalBitTuple, this);
  
  int t = 2;
  for (int i = 0 ; i < level ; i++) {
    d2TupleOnRQLGen[i].setPartySize(t);
    if (t < numberOfParty) {
      d2TupleOnRQLGen[i].generateTuples(degree * widthOfError *
                                        (keySet->ell + 2) + degree, this);
    } else {
      d2TupleOnRQLGen[i].generateTuples(degree * widthOfError *
                                        (keySet->ell + 2) + degree * 2, this);
    }
    t *= 2;
  }
//  int time1 = time_from(time0);
//  printf("Offline time = %lf\n", time1 * 1.0 / 1000000);
//  printf("Offline BW\n");
//  printAndResetBW();
}

template<int QL, int degree, uint64_t w>
fheKey<QL, degree, w>::cryptoBackends::~cryptoBackends(){
  delete io;
  delete[] d2TupleOnRQLGen;
  delete[] d2TupleOnR1Gen;
  delete bitTupleGen;
  delete[] OT;
}

template<int QL, int degree, uint64_t w>
template<int8_t ringSize>
void fheKey<QL, degree, w>::cryptoBackends::squareBatchRns(
    rnsArithmetic<ringSize, 1>* dst, const rnsArithmetic<ringSize, 1>* src,
    size_t size, int numberOfPartyThisRound){
//  static_assert((ringSize == QL) or  (ringSize == QL));
  rnsArithmetic<ringSize, 1>* valuesToOpen;
  rnsArithmetic<ringSize, 0>* valuesOpened;
  d2Tuple<ringSize>** tuplesToUse;

  valuesToOpen = new rnsArithmetic<QL, 1>[size];
  valuesOpened = new rnsArithmetic<QL, 0>[size];
  tuplesToUse = new d2Tuple<ringSize>*[size];

  int level = log2(numberOfPartyThisRound) - 1;

  for (int i = 0 ; i < size ; i++) {
    if constexpr(ringSize == QL) {
      tuplesToUse[i] = d2TupleOnRQLGen[level].getNextTuple();
    }
    if constexpr(ringSize == QL) {
      tuplesToUse[i] = d2TupleOnRQLGen[level].getNextTuple();
    }
    keySet->addRns(&(valuesToOpen[i]), &(src[i]), &(tuplesToUse[i]->v[0]), 0);
  }
  
  io->batchOpenRns(valuesOpened, valuesToOpen, size, numberOfPartyThisRound);
  delete[] valuesToOpen;
  
  for (int i = 0 ; i < size ; i++) {
    rnsArithmetic<ringSize , 1> tmp1;
    rnsArithmetic<ringSize , 1> tmp2;
    // x^2 = (x - v)^2 + 2(x - v) * v + v^2
    
    // 2 * (x - v) * v
    keySet->mulRns(&tmp1, &valuesOpened[i], &tuplesToUse[i]->v[0]);
    keySet->addRns(&tmp2, &tmp1, &tmp1, 1);
    
    //(x - v)*
    keySet->mulRns(&tmp1, &valuesOpened[i], &valuesOpened[i]);
    
    keySet->addRns(&(dst[i]), &tmp1, &tmp2, 1);
    keySet->addRns(&(dst[i]), &(dst[i]), &tuplesToUse[i]->v[1], 1);
  }
  delete[] valuesOpened;
  delete[] tuplesToUse;
}

template<int QL, int degree, uint64_t w>
void fheKey<QL, degree, w>::cryptoBackends::prg(__m128i* dst, size_t size,
                                            AES_KEY* Key, uint64_t keyIndex) {
  for (int i = 0 ; i < size ; i++) {
    dst[i] = _mm_set_epi32(keyIndex + i, 0, 0, 1);
  }
  AES_ecb_encrypt_blks(dst, size, Key);
  for (int i = 0 ; i < size ; i++) {
    dst[i] = _mm_xor_si128(dst[i], _mm_set_epi32(keyIndex + i, 0, 0, 1));
  }
}


template<int QL, int degree, uint64_t w>
void fheKey<QL, degree, w>::cryptoBackends::generateRandomBytes(unsigned char* dst,
                                                            size_t size) {
  assert(size % 16 == 0);
  uint64_t index;
  randomIndexMutex.lock();
  index = randomIndex;
  randomIndex += size / 16;
  randomIndexMutex.unlock();
  prg((__m128i*)dst, size / 16, &maskerAESKey, index);
  
}


template<int QL, int degree, uint64_t w>
template<int8_t ringSize>
void fheKey<QL, degree, w>::cryptoBackends::generateRandomShares(
  rnsArithmetic<ringSize, 0>* dst, size_t size) {
  arithmeticNum pad = ((arithmeticNum)1 << primeWidth) - 1;
  for (int i = 0 ; i < size ; i++) {
    for (int j = 0 ; j < ringSize ; j++) {
      arithmeticNum tmp;
      do {
        tmp = rand() & pad;
      } while (tmp > keySet->rnsBase[j]);
      dst[i].setValue(j, tmp);
    }
  }
}



template<int QL, int degree, uint64_t w>
void fheKey<QL, degree, w>::cryptoBackends::batchAnd(sharedBit* dst,
                                                                   sharedBit* src1,
                                                                   sharedBit* src2,
                                                                   size_t size,
                                                                   const bool randomRight, int numberOfPartyThisRound) {
  bitTupleStack* bitTupleGenUsedHere;
  if (numberOfPartyThisRound == 0) {
    bitTupleGenUsedHere = bitTupleGen;
  } else {
    int level = (int)log2(numberOfPartyThisRound) - 1;
    bitTupleGenUsedHere = &(leveledBitTupleGen[level]);
  }
  bitTuple** tuples = new bitTuple*[size];
  unsigned char* valuesToOpen = new unsigned char[size];
  unsigned char* valuesOpened = new unsigned char[size];
  for (int i = 0 ; i < size ; i++) {
    tuples[i] = bitTupleGenUsedHere->getNextTuple();
    if (!randomRight) {
      valuesToOpen[i] = ((src1[i] ^ tuples[i]->getA()) << 1) +
      (src2[i] ^ tuples[i]->getB());
    } else {
      valuesToOpen[i] = (src1[i] ^ tuples[i]->getA());
    }
  }
  io->batchOpenBytes(valuesOpened, valuesToOpen, size, numberOfPartyThisRound);
  delete[] valuesToOpen;
  for (int i = 0 ; i < size ; i++) {
    if (!randomRight) {
      dst[i] = tuples[i]->getC() ^ ((valuesOpened[i] >> 1) & tuples[i]->getB()) ^
      (valuesOpened[i] & src1[i]);
    } else {
      dst[i] = tuples[i]->getC() ^ (valuesOpened[i] & src1[i]);
    }
  }
  delete[] valuesOpened;
  delete[] tuples;
}


template<int QL, int degree, uint64_t w>
void fheKey<QL, degree, w>::cryptoBackends::batchAdd(sharedBit* dst, sharedBit* src1, sharedBit* src2, int width, size_t size, int numberOfPartyThisRound, bool sign) {
  
  sharedBit* left = new sharedBit[size];
  sharedBit* right = new sharedBit[size];
  sharedBit* output = new sharedBit[size];
  
  for (int i = 0 ; i < size ; i++) {
    left[i] = src1[width * i];
    right[i] = src2[width * i];
  }
  if (sign) {
    for (int i = 0 ; i < size ; i++) {
      dst[(width + 1) * i] = src1[width * i] ^ src2[width * i];
    }
  } else {
    for (int i = 0 ; i < size ; i++) {
      dst[width * i] = src1[width * i] ^ src2[width * i];
      left[i] ^= left[i] ^ right[i];
    }
  }
  batchAnd(output, left, right, size, false, numberOfPartyThisRound);
  if (!sign) {
    for (int i = 0 ; i < size ; i++) {
      output[i] ^= left[i] ^ right[i];
    }
  }
  
  
  for (int bit = 1 ; bit < width - 1; bit++) {
    if (sign) {
      for (int j = 0 ; j < size ; j++) {
        left[j] = src1[width * j + bit];
        left[j] ^= output[j];
        
        right[j] = src2[width * j + bit];
        right[j] ^= output[j];
        
        dst[(width + 1) * j + bit] = left[j] ^ src2[width * j + bit];
      }
    } else {
      for (int j = 0 ; j < size ; j++) {
        left[j] = src1[width * j + bit];
        left[j] ^= src2[width * j + bit];
        
        right[j] = src1[width * j + bit];
        right[j] ^= output[j];
        
        dst[width * j + bit] = left[j] ^ output[j];
      }
    }
    
    batchAnd(output, left, right, size, false, numberOfPartyThisRound);
    
    if (!sign) {
      for (int j = 0 ; j < size ; j++) {
        output[j] ^= src2[width * j + bit] ^ right[j];
      }
    }
  }
  if (sign) {
    for (int j = 0 ; j < size ; j++) {
      left[j] = src1[width * j + width - 1];
      left[j] ^= output[j];
      
      right[j] = src2[width * j + width - 1];
      right[j] ^= output[j];
      
      dst[(width + 1) * j + width - 1] = left[j] ^ src2[width * j + width - 1];
    }
    batchAnd(output, left, right, size, false, numberOfPartyThisRound);
    for (int i = 0 ; i < size ; i++) {
      dst[(width + 1) * (i + 1) - 1] = output[i];
    }
  } else {
    for (int j = 0 ; j < size ; j++) {
      left[j] = src1[width * j + width - 1];
      left[j] ^= src2[width * j + width - 1];
      
      right[j] = src1[width * j + width - 1];
      right[j] ^= output[j];
      
      dst[width * j + width - 1] = left[j] ^ output[j];
    }
  }
  
  delete[] left;
  delete[] right;
  delete[] output;
}

template<int QL, int degree, uint64_t w>
void fheKey<QL, degree, w>::cryptoBackends::batchCompare(sharedBit* dst, sharedBit* src1, int width, size_t size, sharedBit* src2, size_t src2Size, int numberOfPartyThisRound) {
  sharedBit* left = new sharedBit[size];
  sharedBit* right = new sharedBit[size];
  sharedBit* output = new sharedBit[size];
  
  for (int i = 0 ; i < size ; i++) {
    left[i] = src1[width * i];
    right[i] = src2[(width - 1) * (i % src2Size)];
  }
  if (keySet->myID == 0) {
    for (int i = 0 ; i < size ; i++) {
      right[i] ^= 1;
    }
  }
  
  batchAnd(output, left, right, size, false, numberOfPartyThisRound);
  
  
  for (int bit = 1 ; bit < width - 1; bit++) {
    for (int j = 0 ; j < size ; j++) {
      left[j] = src1[width * j + bit];
      left[j] ^= output[j];
      
      right[j] = src2[(width - 1) * (j % src2Size) + bit];
      right[j] ^= output[j];
    }
    
    batchAnd(output, left, right, size, false, numberOfPartyThisRound);
    
    for (int j = 0 ; j < size ; j++) {
      output[j] ^= src1[width * j + bit];
    }
  }
  for (int i = 0 ; i < size ; i++) {
    left[i] = src1[width * (i + 1) - 1] ^ output[i];
  }
  batchAnd(dst, left, output, size, false, numberOfPartyThisRound);
  for (int i = 0 ; i < size ; i++) {
    dst[i] ^= src1[width * (i + 1) - 1];
  }
  delete[] left;
  delete[] right;
  delete[] output;
}

template<int QL, int degree, uint64_t w>
void fheKey<QL, degree, w>::cryptoBackends::arithmeticToBinaryReshare(sharedBit* dst, int width, size_t size, sharedBit* base, size_t baseSize, int numberOfPartyThisRound) {
  
  int level = log2(numberOfPartyThisRound) - 1;
  sharedBit* tmpSum = new sharedBit[(width + 1) * size];
  for (int i = 0 ; i < (width + 1) * size ; i++) {
    tmpSum[i] = 0;
  }
  
  bool order = ((keySet->myID) >> (int)(log2(numberOfPartyThisRound) - 1)) & 1;
  if (order) {
    batchAdd(tmpSum, dst, tmpSum, width, size, numberOfPartyThisRound, 1);
  } else {
    batchAdd(tmpSum, tmpSum, dst, width, size, numberOfPartyThisRound, 1);
  }
  sharedBit* tmpCmp = new sharedBit[size];
  batchCompare(tmpCmp, tmpSum, width + 1, size, base, baseSize,
               numberOfPartyThisRound);
  
  sharedBit* left = new sharedBit[size * width];
  sharedBit* right = new sharedBit[size * width];
  sharedBit* output = new sharedBit[size * width];
  
  for(int i = 0 ; i < size ; i++) {
    for (int j = 0 ; j < width ; j++) {
      left[i * width + j] = tmpCmp[i];
      right[i * width + j] = base[(i % baseSize) * width + j];
    }
  }
  batchAnd(output, left, right, size * width, false, numberOfPartyThisRound);
  batchAdd(dst, tmpSum, output, width, size, numberOfPartyThisRound, 0);
  delete[] tmpSum;
  delete[] tmpCmp;
  delete[] left;
  delete[] right;
  delete[] output;
}


template<int QL, int degree, uint64_t w>
void fheKey<QL, degree, w>::cryptoBackends::binaryToArithmeticReshareSpecial(rnsArithmetic<1, 1>* dst, size_t size, int numberOfPartyThisRound) {
  
  int level = log2(numberOfPartyThisRound) - 1;
    // compute f(x) = (2 - x) * x
    // f(0) = 0
    // f(1) = 1
    // f(2) = 0
  
  d2Tuple<1>** tuplesToUse;
  tuplesToUse = new d2Tuple<1>*[size];
  
  rnsArithmetic<1, 1>* valuesToOpen;
  valuesToOpen = new rnsArithmetic<1, 1>[size];
  
  rnsArithmetic<1, 0>* valuesOpened;
  valuesOpened = new rnsArithmetic<1, 0>[size];
  
  for (int i = 0 ; i < size ; i++) {
    tuplesToUse[i] = d2TupleOnR1Gen[level].getNextTuple();
    
    keySet->addRns(&(valuesToOpen[i]), &dst[i],
                   &tuplesToUse[i]->v[0], -1);
  }
  
  io->batchOpenRns(valuesOpened, valuesToOpen, size,
                   numberOfPartyThisRound);
  delete[] valuesToOpen;
    // x^2 = (x - v)^2 + 2 * (x - v) * v + v^2
    //    2 * x - x^2 * 2
    // = 2 * (x - (x - v)^2 - 2 * (x - v) * v - v^2)
  
  for (int i = 0 ; i < size ; i++) {
    rnsArithmetic<1, 1> tmp;
    rnsArithmetic<1, 1> tmp1;
    keySet->mulRns(&tmp1, &valuesOpened[i], &valuesOpened[i]);
    keySet->addRns(&tmp, &dst[i], &tmp1, 0);
    keySet->mulRns(&tmp1, &dst[i], &valuesOpened[i]);
    keySet->addRns(&tmp, &tmp, &tmp1, 0);
    keySet->addRns(&tmp, &tmp, &tmp1, 0);
    keySet->addRns(&tmp, &tmp, &tuplesToUse[i]->v[1], 0);
    
    keySet->addRns(&dst[i], &tmp, &tmp, 1);
  }
  delete[] valuesOpened;
  delete[] tuplesToUse;
}


template<int QL, int degree, uint64_t w>
void fheKey<QL, degree, w>::cryptoBackends::arithmeticToBinaryReshareSpecial(sharedBit* dst, rnsArithmetic<1, 1>* offset, int width, size_t size, sharedBit* base, size_t baseSize, int numberOfPartyThisRound) {
  
  int level = log2(numberOfPartyThisRound) - 1;
  sharedBit* tmpSum = new sharedBit[(width + 1) * size];
  for (int i = 0 ; i < (width + 1) * size ; i++) {
    tmpSum[i] = 0;
  }
  
  bool order = ((keySet->myID) >> (int)(log2(numberOfPartyThisRound) - 1)) & 1;
  if (order) {
    batchAdd(tmpSum, dst, tmpSum, width, size, numberOfPartyThisRound, 1);
  } else {
    batchAdd(tmpSum, tmpSum, dst, width, size, numberOfPartyThisRound, 1);
  }
  sharedBit* tmpCmp = new sharedBit[size];
  batchCompare(tmpCmp, tmpSum, width + 1, size, base, baseSize,
               numberOfPartyThisRound);
  
  for (int i = 0 ; i < size ; i++) {
    offset[i].setValue(i, tmpCmp[i]);
  }
  binaryToArithmeticReshareSpecial(offset, size, numberOfPartyThisRound);
  
  sharedBit* left = new sharedBit[size * width];
  sharedBit* right = new sharedBit[size * width];
  sharedBit* output = new sharedBit[size * width];
  
  for(int i = 0 ; i < size ; i++) {
    for (int j = 0 ; j < width ; j++) {
      left[i * width + j] = tmpCmp[i];
      right[i * width + j] = base[(i % baseSize) * width + j];
    }
  }
  batchAnd(output, left, right, size * width, false, numberOfPartyThisRound);
  batchAdd(dst, tmpSum, output, width, size, numberOfPartyThisRound, 0);
  delete[] tmpSum;
  delete[] tmpCmp;
  delete[] left;
  delete[] right;
  delete[] output;
}

template<int QL, int degree, uint64_t w>
void fheKey<QL, degree, w>::cryptoBackends::getBinary(sharedBit *dst, uint32_t src, int width) const {
  for (int i = 0 ; i < width ; i++) {
    dst[i] = src & 1;
    src = src >> 1;
  }
}


template<int QL, int degree, uint64_t w>
template<int8_t ringSize, int n>
void fheKey<QL, degree, w>::cryptoBackends::batchMul(
    typename ring<ringSize>::template element<1>* dst,
    typename ring<ringSize>::template element<1>* src1,
    typename ring<ringSize>::template element<1>* src2) {
  mulTupleStack<ringSize, n> tupleGenerator;
  tupleGenerator.generateTuples(degree, this);

  
  rnsArithmetic<ringSize, 1>* valuesToOpen;
  rnsArithmetic<ringSize, 0>* valuesOpened;
  mulTuple<ringSize, n>** tuplesToUse;

  valuesToOpen = new rnsArithmetic<ringSize, 1>[(n + 1) * degree];
  valuesOpened = new rnsArithmetic<ringSize, 0>[(n + 1) * degree];
  tuplesToUse = new mulTuple<ringSize, n>*[degree];
  
  for (int i = 0 ; i < degree ; i++) {
    tuplesToUse[i] = tupleGenerator.getNextTuple();
    keySet->addRns(&(valuesToOpen[(n + 1) * i]), src2->getValue(i),
                   &(tuplesToUse[i]->b), 0);
    for (int j = 0 ; j < n ; j++) {
      keySet->addRns(&(valuesToOpen[(n + 1) * i + j]), src1[j].getValue(i),
                     &(tuplesToUse[i]->a[j]), 0);
    }
  }
    
  io->batchOpenRns(valuesOpened, valuesToOpen, (n + 1) * degree,
                   keySet->numberOfParty);
  
  delete[] valuesToOpen;
  rnsArithmetic<ringSize, 1> tmp[2];
    // xy = c + (x - a) * b + x * (y - b)
  for (int i = 0 ; i < degree ; i++) {
     for (int j = 0 ; j < n ; j++) {
       keySet->mulRns(&tmp[0], &(valuesOpened[(n + 1) * i]),
                      src1[j].getValue(i));
       keySet->mulRns(&tmp[1], &(valuesOpened[(n + 1) * i + j]),
                      src2->getValue(i));
       keySet->addRns(&tmp[2], &tmp[2], &tmp[1], 1);
       keySet->addRns(dst[j].getWritableValue(i), &tmp[2],
                      &(tuplesToUse[i]->c[j]), 1);
     }
  }
  delete[] tuplesToUse;
  delete[] valuesOpened;
}

#include "tuples_impl.h"
#include "secretkeysampling_impl.h"
#include "errorsampling_impl.h"
#include "network_impl.h"
#include "ot_impl.h"
