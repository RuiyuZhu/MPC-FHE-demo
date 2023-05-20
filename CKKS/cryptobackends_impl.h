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

template<int L, int degree>
class fheKey<L, degree>::cryptoBackends {
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

  void openRingElement(typename ring<1>::template element<1>* src,
                       typename ring<1>::template element<1>* dst = nullptr);
  void printAndResetBW() const {
    io->printAndResetBW();
  }
  void resetBW() const {
    io->resetBW();
  }
private:
  class obliviousTransfer;
  
  template<typename TupleType, int8_t ringSize = 0, int vecLen = 0>
  class tupleStack;
  
  
  typedef unsigned char sharedBit;
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
  
  struct d4Tuple;
//  class d4TupleStack;
  using d4TupleStack = tupleStack<d4Tuple>;
  
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


  d2TupleStack<QL>* d2TupleOnRQLGen;
  d2TupleStack<p0QL>* d2TupleOnRP0QLGen;
  d4TupleStack* d4TupleOnRP0QLGen;
  bitTupleStack* bitTupleGen;
  
  network* io;
  fheKey* keySet;
  obliviousTransfer* OT;
  uint64_t randomIndex = 0;
  std::mutex randomIndexMutex;
  __m128i masterKey;
  AES_KEY maskerAESKey;
};

template<int L, int degree>
fheKey<L, degree>::cryptoBackends::cryptoBackends(fheKey* parent, int myID,
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
  d2TupleOnRP0QLGen = new d2TupleStack<p0QL>[level];
  d4TupleOnRP0QLGen = new d4TupleStack[level];
  bitTupleGen = new bitTupleStack;
  
  int totalBitTuple = (degree * (numberOfThreshold *
                                 (lengthOfThreshold - 1) + 56)) * (L + 1);
//  auto time0 = clock_start();
  bitTupleGen->generateTuples(totalBitTuple * 2, this);
  
  int t = 2;
  for (int i = 0 ; i < level ; i++) {
    d2TupleOnRQLGen[i].setPartySize(t);
    d2TupleOnRP0QLGen[i].setPartySize(t);
    d4TupleOnRP0QLGen[i].setPartySize(t);
    
    d2TupleOnRQLGen[i].generateTuples(degree * widthOfError, this);
    if (t < numberOfParty) {
      d2TupleOnRP0QLGen[i].generateTuples(degree * widthOfError * (L + 1), this);
    } else {
      d2TupleOnRP0QLGen[i].generateTuples(degree * widthOfError * (L + 1) + degree,
                                          this);
    }
    d4TupleOnRP0QLGen[i].generateTuples(degree, this);
    t *= 2;
  }
//  int time1 = time_from(time0);
//  printf("Offline time = %lf\n", time1 * 1.0 / 1000000);
//  printf("Offline BW\n");
//  printAndResetBW();
}

template<int L, int degree>
fheKey<L, degree>::cryptoBackends::~cryptoBackends(){
  delete io;
  delete[] d2TupleOnRQLGen;
  delete[] d2TupleOnRP0QLGen;
  delete[] d4TupleOnRP0QLGen;
  delete bitTupleGen;
  delete[] OT;
}

template<int L, int degree>
template<int8_t ringSize>
void fheKey<L, degree>::cryptoBackends::squareBatchRns(
    rnsArithmetic<ringSize, 1>* dst, const rnsArithmetic<ringSize, 1>* src,
    size_t size, int numberOfPartyThisRound){
//  static_assert((ringSize == QL) or  (ringSize == p0QL));
  rnsArithmetic<ringSize, 1>* valuesToOpen;
  rnsArithmetic<ringSize, 0>* valuesOpened;
  d2Tuple<ringSize>** tuplesToUse;

  valuesToOpen = new rnsArithmetic<p0QL, 1>[size];
  valuesOpened = new rnsArithmetic<p0QL, 0>[size];
  tuplesToUse = new d2Tuple<ringSize>*[size];

  int level = log2(numberOfPartyThisRound) - 1;

  for (int i = 0 ; i < size ; i++) {
    if constexpr(ringSize == p0QL) {
      tuplesToUse[i] = d2TupleOnRP0QLGen[level].getNextTuple();
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

template<int L, int degree>
void fheKey<L, degree>::cryptoBackends::prg(__m128i* dst, size_t size,
                                            AES_KEY* Key, uint64_t keyIndex) {
  for (int i = 0 ; i < size ; i++) {
    dst[i] = _mm_set_epi32(keyIndex + i, 0, 0, 1);
  }
  AES_ecb_encrypt_blks(dst, size, Key);
  for (int i = 0 ; i < size ; i++) {
    dst[i] = _mm_xor_si128(dst[i], _mm_set_epi32(keyIndex + i, 0, 0, 1));
  }
}


template<int L, int degree>
void fheKey<L, degree>::cryptoBackends::generateRandomBytes(unsigned char* dst,
                                                            size_t size) {
  assert(size % 16 == 0);
  uint64_t index;
  randomIndexMutex.lock();
  index = randomIndex;
  randomIndex += size / 16;
  randomIndexMutex.unlock();
  prg((__m128i*)dst, size / 16, &maskerAESKey, index);
  
}


template<int L, int degree>
template<int8_t ringSize>
void fheKey<L, degree>::cryptoBackends::generateRandomShares(
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

template<int L, int degree>
void fheKey<L, degree>::cryptoBackends::openRingElement(
    typename ring<1>::template element<1>* src,
    typename ring<1>::template element<1>* dst) {
  
  if (keySet->myID != 0) {
    for (int j = 0 ; j < degree ; j++) {
      io->sendToParty((unsigned char*)src->getValue(j), sizeof(rnsArithmetic<1, 1>), 0);
    }
  } else {
    std::future<int> future[keySet->numberOfParty - 1];
    typename ring<1>::template element<1>* tmp = new typename ring<1>::template element<1>[keySet->numberOfParty - 1];
    for (int i = 1 ; i < keySet->numberOfParty ; i++) {
      future[i - 1] = io->pool->enqueue([](network* io,
                                       typename ring<1>::template element<1>* buffer,
                                       int ID) -> int {
        for (int j = 0 ; j < degree ; j++) {
          io->receiveFromParty((unsigned char*)buffer->getWritableValue(j), sizeof(rnsArithmetic<1, 1>), ID);
        }
        return 1;
      }, io, &(tmp[i - 1]), i);
    }
    future[0].get();
    keySet->Rq0->addElement(dst, src, &tmp[0]);
    for (int i = 2 ; i < keySet->numberOfParty ; i++) {
      future[i - 1].get();
       keySet->Rq0->addElement(dst, src, &tmp[i - 1]);
    }
    delete[] tmp;
  }
}
template<int L, int degree>
template<int8_t ringSize, int n>
void fheKey<L, degree>::cryptoBackends::batchMul(
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
  rnsArithmetic<ringSize, 1> tmp[3];
    // xy = c + (x - a) * b + x * (y - b)
  for (int i = 0 ; i < degree ; i++) {
     for (int j = 0 ; j < n ; j++) {
       keySet->mulRns(&tmp[0], &(valuesOpened[(n + 1) * i]),
                      src1[j].getValue(i));
       keySet->mulRns(&tmp[1], &(valuesOpened[(n + 1) * i + j]),
                      src2->getValue(i));
       keySet->addRns(&tmp[2], &tmp[0], &tmp[1], 1);
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
