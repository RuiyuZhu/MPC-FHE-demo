#pragma once

template<int QL, int degree, uint64_t w>
template<int8_t ringSize, bool secret>
// if this is a shared secret or not
// for a shared secret s, party i holds si such that \sum si = s
// for a public vaule p, each party holds p
class fheKey<QL, degree, w>::rnsArithmetic {
public:
  rnsArithmetic() {
    memset(values, 0, sizeof(arithmeticNum) * ringSize);
  }
  void setValue(const int i, const arithmeticNum v) {
    values[i] = v;
  }
  const arithmeticNum getValue(const int i) const {
    return values[i];
  }
private:
  arithmeticNum values[ringSize];
};

template<int QL, int degree, uint64_t w>
template<int8_t ringSize, bool secret>
class fheKey<QL, degree, w>::poly {
public:
  poly() {
    coefficient = new rnsArithmetic<ringSize, secret>[degree];
  }
  ~poly() {
    delete[] coefficient;
  }
  rnsArithmetic<ringSize, secret>* getWritableCoefficient(const int i) {
    return &(coefficient[i]);
  }
  const rnsArithmetic<ringSize, secret>* getCoefficient(const int i) const {
    return &(coefficient[i]);
  }
private:
  rnsArithmetic<ringSize,secret>* coefficient = nullptr;
};


template<int QL, int degree, uint64_t w>
template<int8_t ringSize, bool s1, bool s2, bool s3>
void fheKey<QL, degree, w>::mulRns(rnsArithmetic<ringSize, s3>* dst,
                               const rnsArithmetic<ringSize, s1>* src1,
                               const rnsArithmetic<ringSize, s2>* src2) const {
  static_assert(!(s1 and s2));
    // secret * const; const * const
  for (int i = 0 ; i < ringSize ; i++) {
    dst->setValue(i, mulArithmetic(src1->getValue(i), src2->getValue(i), i));
  }
}

template<int QL, int degree, uint64_t w>
template<int8_t ringSize, bool s1, bool s2, bool s3>
void fheKey<QL, degree, w>::addRns(rnsArithmetic<ringSize, s3>* dst,
                               const rnsArithmetic<ringSize, s1>* src1,
                               const rnsArithmetic<ringSize, s2>* src2,
                               const bool sign) const{
  if constexpr (s1 == s2) {
    // secret + secret; const + const
    for (int i = 0 ; i < ringSize ; i++) {
      dst->setValue(i, addArithmetic(src1->getValue(i), src2->getValue(i), i,
                                     sign));
    }
  } else {
    if (myID == 0) {
      for (int i = 0 ; i < ringSize ; i++) {
        dst->setValue(i, addArithmetic(src1->getValue(i), src2->getValue(i), i,
                                     sign));
      }
    }
  }
}

template<int QL, int degree, uint64_t w>
template<int8_t ringSize, bool secret>
void fheKey<QL, degree, w>::copyRns(rnsArithmetic<ringSize, secret>* dst,
                                const rnsArithmetic<ringSize, secret>* src) const {
  for (int i = 0 ; i < ringSize ; i++) {
    dst->setValue(i, src->getValue(i));
  }
}

template<int QL, int degree, uint64_t w>
template<int8_t ringSize>
void fheKey<QL, degree, w>::setConstRns(rnsArithmetic<ringSize, 0>* dst,
                                    const int v) const {
  for (int i = 0 ; i < ringSize ; i++) {
    arithmeticNum tmp;
    if (v < 0) {
      tmp = rnsBase[i] + v;
    } else {
      tmp = v;
    }
    dst->setValue(i, tmp);
  }
}

template<int QL, int degree, uint64_t w>
template<int8_t ringSize>
void fheKey<QL, degree, w>::setSecretRns(rnsArithmetic<ringSize, 1>* dst,
                                     const int v) const {
  for (int i = 0 ; i < ringSize ; i++) {
    arithmeticNum tmp;
    if (v > 0) {
      tmp = rnsBase[i] + v;
    } else {
      tmp = v;
    }
    dst->setValue(i, tmp);
  }
}

template<int QL, int degree, uint64_t w>
typename fheKey<QL, degree, w>::arithmeticNum fheKey<QL, degree, w>::
  mulArithmetic(const arithmeticNum src1, const arithmeticNum src2,
                const int i) const {
  unsigned __int128 result;
  result = src1 * src2;
  result = result % rnsBase[i];
  return result & (0xFFFFFFFFFFFFFFFF); // only preserve the last 64 bits
}

template<int QL, int degree, uint64_t w>
typename fheKey<QL, degree, w>::arithmeticNum fheKey<QL, degree, w>::
  addArithmetic(const arithmeticNum src1, const arithmeticNum src2, const int i,
                const bool sign) const {
  arithmeticNum result;
  if (sign) {
    result = src1 + src2;
  } else {
    result = src1 + rnsBase[i] - src2;
  }
  if (result >= rnsBase[i]) {
    result -= rnsBase[i];
  }
  return result;
}

template<int QL, int degree, uint64_t w>
typename fheKey<QL, degree, w>::arithmeticNum fheKey<QL, degree, w>::
    get2Power(arithmeticNum p, int i) const{
  if (p == 0) {
    return 1;
  } else if (p == 1) {
    return powerBase;
  } else {
    arithmeticNum result = get2Power(p >> 1, i);
    result = mulArithmetic(result, result, i);
    if ((p & 1) == 1) {
      result = mulArithmetic(result, powerBase, i);
    }
    return result;
  }
}
