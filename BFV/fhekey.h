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

template<int QL, int degree, uint64_t w>
class fheKey {
  typedef uint64_t arithmeticNum;
  // p indicates if it is on rnsQL or rnsQL
  template<int8_t ringSize, bool secret>
  // if this is a shared secret or not
  // for a shared secret s, party i holds si such that \sum si = s
  // for a public vaule p, each party holds p
  class rnsArithmetic;
  
  // p indicates if it is on rnsQL or rnsQL
  template<int8_t ringSize, bool secret>
  class poly;
  
  // p indicates if it is on rnsQL or rnsQL
  template<int8_t ringSize> class ring;

public:
  //q0 - qL, p0 , q
  typedef std::array<arithmeticNum, QL> rnsBasePrime;
  
  typedef poly<QL, 1> pvtKeyInPoly;
  
  struct pvtKeyOnRing{
    typename ring<QL>::template element<1> s;
  };
  
  class swKey{
  public:
    typename ring<QL>::template element<0>* a;
    typename ring<QL>::template element<0>* b;
    swKey(fheKey<QL, degree, w>* keySet) {
      int ell = keySet->ell;
      assert(ell > 0);
      a = new typename ring<QL>::template element<0>[ell + 1];
      b = new typename ring<QL>::template element<0>[ell + 1];
    }
    ~swKey() {
      delete[] a;
      delete[] b;
    }
  };
  
  class pubKey {
  public:
    typename ring<QL>::template element<0> a;
    typename ring<QL>::template element<0> b;
  };
  
  class ciphertext {
  public:
    typename ring<QL>::template element<0> c0;
    typename ring<QL>::template element<0> c1;
  };
  
  class plaintext {
  public:
    poly<1, 1> m;
  };
  
  fheKey(const rnsBasePrime base, int ID, int numberOfParty,
         const char** address, int defaultPortNo, __m128i maskerKey);
  ~fheKey();
  
  void keyGen(pvtKeyOnRing* pvtKey, swKey* switchKey, pubKey* publicKey);
  
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
  int maxLen;
  
  const rnsBasePrime rnsBase;
    int ell = 0;
  int getell() {
    int ell = 0;
    for (int i = 0 ; i < QL ; i++) {
      ell += log(rnsBase[i])/log(w);
    }
    return ell;
  }
  
  class cryptoBackends;
  
  void sampleSecretKey(poly<QL, 1>* dst);
  
  template<int d>
  void truncate(poly<d, 1>* dst, const poly<QL, 1>* src);
  
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
  poly<QL, 1>* s; // the secret key represented on QL
  
  ring<QL>* RQL;
  
  const int myID;
  const int numberOfParty;
  cryptoBackends* backend;
};


static const int testL = 15;
static const int testDegree = 32768;
static const uint64_t testW = 1073741824;
//static const int totalWidth = 9;

static const fheKey<testL, testDegree, testW>::rnsBasePrime testPrimes = {
  0x80000000080001, 0x80000000130001, 0x7fffffffe90001, 0x80000000190001
  ,0x800000001d0001, 0x7fffffffbf0001, 0x7fffffffbd0001, 0x80000000440001
  ,0x7fffffffba0001, 0x80000000490001, 0x80000000500001, 0x7fffffffaa0001
  ,0x7fffffffa50001, 0x800000005e0001, 0x7fffffff9f0001};
static const int primeWidth = 55;

const int numberOfThreshold = 46;
const int widthOfError = 6;
const int lengthOfThreshold = 40;
const uint64_t normalThreshold[numberOfThreshold] = {
  1, 10, 82, 606, 4076, 24916, 138508, 700451, 3223532, 13505328,
  51533852, 179194338, 568162171, 1643845525, 4343896290, 10495367942,
  23215990458, 47092029914, 87768461615, 150668628457, 238954372416,
  351430493101, 481495914531, 618015713245, 748081134675, 860557255360,
  948842999319, 1011743166161, 1052419597862, 1076295637318,
  1089016259834, 1095167731486, 1097867782251, 1098943465605,
  1099332433438, 1099460093924, 1099498122448, 1099508404244,
  1099510927325, 1099511489268, 1099511602860, 1099511623700,
  1099511627170, 1099511627694, 1099511627766, 1099511627775};

#include "arithmetic_impl.h"
#include "cryptobackends_impl.h"
#include "polynomialRing_impl.h"
#include "fhekey_impl.h"


