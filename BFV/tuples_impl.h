#pragma once
//#define OnlineOnly

const int bufferCap = 1024;
static const int bitTupleScaler = 1024;//bit tuple buffer is larger

template<int QL, int degree, uint64_t w>
class fheKey<QL, degree, w>::cryptoBackends::bitTuple {
public:
  bool getA() const{
    return value & 1;
  }
  bool getB() const{
    return (value >> 1) & 1;
  }
  bool getC() const{
    return (value >> 2) & 1;
  }
  void setValue(unsigned char v) {
    value = v;
  }
private:
  unsigned char value = 0;
};

template<int QL, int degree, uint64_t w>
template<int8_t ringSize>
struct fheKey<QL, degree, w>::cryptoBackends::d2Tuple {
  rnsArithmetic<ringSize, 1> v[2];
};

template<int QL, int degree, uint64_t w>
template<int8_t ringSize, int vecLen>
struct fheKey<QL, degree, w>::cryptoBackends::mulTuple {
  rnsArithmetic<ringSize, 1> a[vecLen];
  rnsArithmetic<ringSize, 1> b;
  rnsArithmetic<ringSize, 1> c[vecLen];
};


template<int QL, int degree, uint64_t w>
template<typename TupleType, int8_t ringSize, int vecLen>
class fheKey<QL, degree, w>::cryptoBackends::tupleStack {
  static_assert(std::is_same<TupleType, d2Tuple<ringSize>>::value or
                std::is_same<TupleType, mulTuple<ringSize, vecLen>>::value or
                std::is_same<TupleType, bitTuple>::value
                );
public:
  tupleStack() {
    maximumBufferSize = bufferCap;
    if constexpr(std::is_same<TupleType, bitTuple>::value) {
      maximumBufferSize = bufferCap * bitTupleScaler;
    }
  }
  ~tupleStack() {
    if (tuples != nullptr) {
      delete[] tuples;
    }
    printf("remaining tuple : %d %d\n", tupleToGenerate + index,
           std::is_same<TupleType, d2Tuple<ringSize>>::value);
  }
  
  void generateTuples(int n, cryptoBackends* backend);
  int tupleToGet() const{
    return index + tupleToGenerate;
  }

  TupleType* getNextTuple();
  
  void setPartySize(int n) {
    static_assert(std::is_same<TupleType, d2Tuple<ringSize>>::value);
    numberOfPartyThisStack = n;
  }
  

private:
  int maximumBufferSize;
  int numberOfPartyThisStack = 0;
  int index = 0;
  TupleType* tuples = nullptr;
  int tupleToGenerate = 0;
  cryptoBackends* backend = nullptr;
  void fillTheBuffer();
  void fillTheBufferForBitTuple();
  void fillTheBufferForD2Tuple();
  void fillTheBufferForMulTuple();
};


template<int QL, int degree, uint64_t w>
template<typename TupleType, int8_t ringSize, int vecLen>
TupleType* fheKey<QL, degree, w>::cryptoBackends::tupleStack<TupleType, ringSize, vecLen>::getNextTuple() {
  if (index == 0) {
    if ((tupleToGenerate < maximumBufferSize) || (maximumBufferSize == 0)) {
      index = (tupleToGenerate + 63) / 64 * 64;
    } else {
      index = maximumBufferSize;
    }
    fillTheBuffer();
  }
  
  assert(index > 0);
  index--;
  return &tuples[index];
}


template<int QL, int degree, uint64_t w>
template<typename TupleType, int8_t ringSize, int vecLen>
void fheKey<QL, degree, w>::cryptoBackends::tupleStack<TupleType, ringSize, vecLen>::generateTuples(int n, cryptoBackends* bc) {
  backend = bc;
  if (tuples != nullptr) {
      delete[] tuples;
    }
    tupleToGenerate = n;
    
    if ((tupleToGenerate < maximumBufferSize) || (maximumBufferSize == 0)) {
      index = tupleToGenerate;
    } else {
      index = maximumBufferSize;
    }
    
    tuples = new TupleType[index];
    
    fillTheBuffer();
}


template<int QL, int degree, uint64_t w>
template<typename TupleType, int8_t ringSize, int vecLen>
void fheKey<QL, degree, w>::cryptoBackends::tupleStack<TupleType, ringSize, vecLen>::fillTheBuffer() {
  #ifdef OnlineOnly
    memset(tuples, 0 , sizeof(TupleType) * index);
    tupleToGenerate -= index;
    return;
  #endif
  if constexpr (std::is_same<TupleType, d2Tuple<ringSize>>::value) {
    fillTheBufferForD2Tuple();
  }
  if constexpr (std::is_same<TupleType, mulTuple<ringSize, vecLen>>::value) {
    fillTheBufferForMulTuple();
  }
  if constexpr (std::is_same<TupleType, bitTuple>::value) {
    fillTheBufferForBitTuple();
  }
  tupleToGenerate -= index;
}


template<int QL, int degree, uint64_t w>
template<typename TupleType, int8_t ringSize, int vecLen>
void fheKey<QL, degree, w>::cryptoBackends::tupleStack<TupleType, ringSize, vecLen>::fillTheBufferForBitTuple() {
//  printf("Party %d bitTupleGeneration %d\n", backend->keySet->myID, index);
  
  unsigned char* tmp = new unsigned char[index];
  backend->io->batchRandomBitMultiplication(tmp, index);
  for (int i = 0 ; i < index ; i++) {
    unsigned char v = tmp[i];
    v = (v & 1) ^ ((v >> 1) & 1);
    v = v << 2;
    tuples[i].setValue(tmp[i] ^ v);
  }
  delete[] tmp;
}

template<int QL, int degree, uint64_t w>
template<typename TupleType, int8_t ringSize, int vecLen>
void fheKey<QL, degree, w>::cryptoBackends::tupleStack<TupleType, ringSize, vecLen>::fillTheBufferForD2Tuple() {
//  printf("Party %d d2TupleGeneration %d\n", backend->keySet->myID, index);
  rnsArithmetic<ringSize, 0>* input;
  input = new rnsArithmetic<ringSize, 0> [index];
  
  rnsArithmetic<ringSize, 1>* output;
  output = new rnsArithmetic<ringSize, 1> [index];
  
  backend->generateRandomShares(input, index);
  backend->io->batchMultiplicationDegree2(output, input, index,
                                          numberOfPartyThisStack);
  for(int i = 0 ; i < index ; i++) {
    memcpy(&(tuples[i].v[0]), &input[i],
           sizeof(rnsArithmetic<ringSize, 1>));

    backend->keySet->mulRns(&(tuples[i].v[1]), &input[i], &input[i]);
    backend->keySet->addRns(&(tuples[i].v[1]), &(tuples[i].v[1]),
                            &output[i], 1);
    backend->keySet->addRns(&(tuples[i].v[1]), &(tuples[i].v[1]),
                            &output[i], 1);
  }
  delete[] output;
  delete[] input;
}


template<int QL, int degree, uint64_t w>
template<typename TupleType, int8_t ringSize, int vecLen>
void fheKey<QL, degree, w>::cryptoBackends::tupleStack<TupleType, ringSize, vecLen>::fillTheBufferForMulTuple() {
//  printf("Party %d MulTupleGeneration %d\n", backend->keySet->myID, index);
   rnsArithmetic<ringSize, 0>* inputL;
   inputL = new rnsArithmetic<ringSize, 0> [vecLen * index];

   rnsArithmetic<ringSize, 0>* inputR;
   inputR = new rnsArithmetic<ringSize, 0> [index];

   rnsArithmetic<ringSize, 1>* output;
   output = new rnsArithmetic<ringSize, 1> [vecLen * index];
   
   backend->generateRandomShares(inputL, vecLen * index);
   backend->generateRandomShares(inputR, index);
   
   backend->io->template batchGeneralMultiplication<ringSize, vecLen>(output,
                                                                      inputL,
                                                                      inputR, index);
   
   for (int i = 0 ; i < index ; i++) {
     memcpy(&(tuples[i].b), &inputR[i], sizeof(rnsArithmetic<ringSize, 0>));
     memcpy(tuples[i].a, &inputL[i * vecLen],
            sizeof(rnsArithmetic<ringSize, 0>) * vecLen);
     for (int j = 0 ; j < vecLen ; j++) {
       backend->keySet->mulRns(&(tuples[i].c[j]), &inputL[vecLen * i + j],
                               &inputR[j]);
       backend->keySet->addRns(&(tuples[i].c[j]), &output[vecLen * i + j],
                               &(tuples[i].c[j]));
     }
   }
   delete[] inputR;
   delete[] inputL;
   delete[] output;
}
