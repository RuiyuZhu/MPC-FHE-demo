#pragma once
#include<array>
#include <openssl/sha.h>
#include <assert.h>
#include <math.h>
#include <string.h>
#include "ThreadPool.h"
#include "aes.h"
#include <immintrin.h>
#include <type_traits>
#include <mutex>
#include "timing.h"

template<int L, int degree>
class fheKey {
  static const int8_t q0 = 1;
  static const int8_t QL = L + 1;
  static const int8_t p0QL = L + 2;
  typedef uint64_t arithmeticNum;
  // p indicates if it is on rnsQL or rnsP0QL
  template<int8_t ringSize, bool secret>
  // if this is a shared secret or not
  // for a shared secret s, party i holds si such that \sum si = s
  // for a public vaule p, each party holds p
  class rnsArithmetic;
  
  // p indicates if it is on rnsQL or rnsP0QL
  template<int8_t ringSize, bool secret>
  class poly;
  
  // p indicates if it is on rnsQL or rnsP0QL
  template<int8_t ringSize> class ring;

public:
  //q0 - qL, p0 , q
  typedef std::array<arithmeticNum, L + 3> rnsBasePrime;
  
  typedef poly<QL, 1> pvtKeyInPoly;
  
  struct pvtKeyOnRing{
    typename ring<1>::template element<1> s;
  };
  
  class swKey{
  public:
    typename ring<p0QL>::template element<0> a[L + 1];
    typename ring<p0QL>::template element<0> b[L + 1];
  };
  
  class pubKey {
  public:
    typename ring<QL>::template element<0> a;
    typename ring<QL>::template element<0> b;
  };
  
  class ciphertext {
  public:
    ciphertext(int n):length(n) {
      c0 = new typename ring<1>::template element<0>[n];
      c1 = new typename ring<1>::template element<0>[n];
    }
    ~ciphertext() {
      delete[] c0;
      delete[] c1;
    }
    const int length;
    typename ring<1>::template element<0>* c0;
    typename ring<1>::template element<0>* c1;
  };
  
  class plaintext {
  public:
    plaintext(int n):length(n) {
      message = new typename ring<1>::template element<1>[n];
    }
    ~plaintext() {
      delete[] message;
    }
    const int length;
    typename ring<1>::template element<1>* message;
  };
  
  fheKey(const rnsBasePrime base, int ID, int numberOfParty,
         const char** address, int defaultPortNo, __m128i maskerKey);
  ~fheKey();
  
  void keyGen(pvtKeyOnRing* pvtKey, swKey* switchKey, pubKey* publicKey);
  
  template<int n>
  void dec(plaintext* dst, ciphertext* src, pvtKeyOnRing* key);
  
  template<int8_t ringSize>
  void open(rnsArithmetic<ringSize, 1>* shared);
  
  
  template<int8_t ringSize, bool secret>
  void print(rnsArithmetic<ringSize, secret>* v) {
    if (myID == 0) {
      for (int i = 0 ; i < ringSize ; i++) {
        printf("%llu ", v->getValue(i));
      }
      printf("\n");
    }
  }
  
private:
  class cryptoBackends;
  
  void sampleSecretKey(poly<p0QL, 1>* dst);
  
  template<int d>
  void truncate(poly<d, 1>* dst, const poly<p0QL, 1>* src);
  
  template <int8_t ringSize>
  void sampleError(poly<ringSize, 1>* dst);
  
  template<int8_t ringSize>
  void addPoly(poly<ringSize, 1>* dst, const poly<ringSize, 1>* src1, poly<ringSize, 1>* src2) const;
  
  
  template <int8_t ringSize, bool s1, bool s2, bool s3>
  void mulRns(rnsArithmetic<ringSize, s3>* dst,
              const rnsArithmetic<ringSize, s1>* src1,
              const rnsArithmetic<ringSize, s2>* src2) const;
  
  template <int8_t ringSize, bool s1, bool s2, bool s3>
  void addRns(rnsArithmetic<ringSize, s3>* dst,
              const rnsArithmetic<ringSize, s1>* src1,
              const rnsArithmetic<ringSize, s2>* src2,
              const bool sign = 1) const;
  
  template <int8_t ringSize, bool s>
  void copyRns(rnsArithmetic<ringSize, s>* dst, const rnsArithmetic<ringSize, s>* src) const;
  
  template <int8_t ringSize>
  void setConstRns(rnsArithmetic<ringSize, 0>* dst, const int v) const;
  
  template <int8_t ringSize>
  void setSecretRns(rnsArithmetic<ringSize, 1>* dst, const int v) const;
  
  arithmeticNum mulArithmetic(const arithmeticNum src1,
                              const arithmeticNum src2, const int i) const;
  
  arithmeticNum addArithmetic(const arithmeticNum src1,
                              const arithmeticNum src2, const int i,
                              const bool sign = 1) const;
  
  arithmeticNum get2Power(arithmeticNum p, int i) const;

  const arithmeticNum powerBase = 3;
  const rnsBasePrime rnsBase;
  poly<p0QL, 1>* s; // the secret key represented on p0QL
  
  ring<1>* Rq0;
  ring<QL>* RQL;
  ring<p0QL>* RP0QL;
  
  const int myID;
  const int numberOfParty;
  cryptoBackends* backend;
};




static const int testL = 7;
static const int testDegree = 16384;
static const fheKey<testL, testDegree>::rnsBasePrime testPrimes = {
  0x80000000080001, 0x80000000130001, 0x7fffffffe90001, 0x80000000190001,
  0x800000001d0001, 0x7fffffffbf0001, 0x7fffffffbd0001, 0x80000000440001,
  0x7fffffffba0001};//, 0x80000000490001, 0x80000000500001, 0x7fffffffaa0001,
//  0x7fffffffa50001, 0x800000005e0001, 0x7fffffff9f0001};
static const int primeWidth = 55;

const int numberOfThreshold = 23;
const int widthOfError = 6;
const int lengthOfThreshold = 40;
const uint64_t normalThreshold[numberOfThreshold] = {
  136519798713, 396650641573, 621602882943, 798174370862, 923974704546,
  1005327567948, 1053079646861, 1078520891892, 1090823835196, 1096223936726,
  1098375303435, 1099153239101, 1099408560073, 1099484617121, 1099505180713,
  1099510226875, 1099511350760, 1099511577944, 1099511619623, 1099511626563,
  1099511627612, 1099511627756, 1099511627774
};

#include "arithmetic_impl.h"
#include "cryptobackends_impl.h"
#include "polynomialRing_impl.h"
#include "fhekey_impl.h"


