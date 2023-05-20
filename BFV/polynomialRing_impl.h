#pragma once

template<int QL, int degree, uint64_t w>
template<int8_t ringSize>
class fheKey<QL, degree, w>::ring {
public:
  ring(const fheKey* k);
  ~ring() {
    delete[] roots;
  }
  template<bool secret>
  class element {
  public:
    element() {
      values = new rnsArithmetic<ringSize, secret>[degree];
    }
    ~element() {
      delete[] values;
    }
    rnsArithmetic<ringSize, secret>* getWritableValue(const int i) {
      return &(values[i]);
    }
    const rnsArithmetic<ringSize, secret>* getValue(const int i) const {
      return &(values[i]);
    }
  private:
    rnsArithmetic<ringSize, secret>* values = nullptr;
  };
  
  void sampleUniformElement(element<0>* dst) const;
  void setConstElement(element<0>* dst, int c) const;
  
  template<bool s1, bool s2, bool s3>
  void mulElement(element<s3>* dst, const element<s1>* src1,
                  const element<s2>* src2) const;
  
  void copyElement(element<1>* dst, const element<1>* src1) const;
  
  void squareElement(element<1>* dst, const element<1>* src1) const;
  
  template<bool s1, bool s2, bool s3>
  void addElement(element<s3>* dst, const element<s1>* src1,
                  const element<s2>* src2, const bool sign = 1) const;
  
  template<bool secret>
  void convert(element<secret>* dst, const poly<ringSize, secret>* src) const;
  
  template<bool secret>
  void InverseConvert(poly<ringSize, secret>* dst, const element<secret>* src) const;
  
  void truncateElementWithP(element<1>* dst, const element<1>* src,
                            const int i) const;
  
  
  
private:
  template<bool secret>
  void evalAtPoint(rnsArithmetic<ringSize, secret>* dst,
                   const rnsArithmetic<ringSize, 0>* x,
                   const poly<ringSize, secret>* src);
  void setRoot0(rnsArithmetic<ringSize, 0>* dst);
  rnsArithmetic<ringSize, 0>* roots = nullptr;
  const fheKey *keySet;
  
  template<bool secret>
  void nTT(int offset, rnsArithmetic<ringSize, secret>* dst,
           rnsArithmetic<ringSize, secret>* src) const;
  
};


template<int QL, int degree, uint64_t w>
template<int8_t ringSize>
void fheKey<QL, degree, w>::addPoly(poly<ringSize, 1>* dst, const poly<ringSize, 1>* src1,
                                poly<ringSize, 1>* src2) const {
  for (int i = 0 ; i < degree ; i++) {
    addRns(dst->getWritableCoefficient(i), src1->getCoefficient(i),
           src2->getCoefficient(i));
  }
}

template<int QL, int degree, uint64_t w>
template<int8_t ringSize>
fheKey<QL, degree, w>::ring<ringSize>::ring(const fheKey* k): keySet(k) {
  roots = new rnsArithmetic<ringSize, 0>[degree];
  setRoot0(roots);
  rnsArithmetic<ringSize, 0> tmp;
  keySet->mulRns(&tmp, &(roots[0]), &(roots[0]));
  for (int i = 1; i < degree ; i++) {
    keySet->mulRns(&(roots[i]), &(roots[i - 1]), &tmp);
  }
}

template<int QL, int degree, uint64_t w>
template<int8_t ringSize>
void fheKey<QL, degree, w>::ring<ringSize>::setRoot0(rnsArithmetic<ringSize, 0>* dst) {
  for (int i = 0 ; i < ringSize ; i ++) {
    arithmeticNum power = (keySet->rnsBase[i] - 1) / 2 / degree;
    dst->setValue(i, keySet->get2Power(power, i));
  }
}

template<int QL, int degree, uint64_t w>
template<int8_t ringSize>
template<bool secret>
void fheKey<QL, degree, w>::ring<ringSize>::convert(element<secret>* dst,
                                         const poly<ringSize, secret>* src) const {
  rnsArithmetic<ringSize, secret>* tmp1;
  rnsArithmetic<ringSize, secret>* tmp2;
  tmp1 = new rnsArithmetic<ringSize, secret>[degree];
  tmp2 = new rnsArithmetic<ringSize, secret>[degree];
  for (int i = 0 ; i < degree ; i++) {
    keySet->copyRns(&tmp2[i], src->getCoefficient(i));
  }
  int offset = degree;
  do {
    nTT(offset, tmp1, tmp2);
    rnsArithmetic<ringSize, secret>* tmp = tmp1;
    tmp1 = tmp2;
    tmp2 = tmp;
    offset /= 2;
  } while(offset > 1);
  for (int i = 0 ; i < degree ; i++) {
    keySet->copyRns(dst->getWritableValue(i), &tmp2[i]);
  }
  delete[] tmp1;
  delete[] tmp2;
}

template<int QL, int degree, uint64_t w>
template<int8_t ringSize>
template<bool secret>
void fheKey<QL, degree, w>::ring<ringSize>::nTT(int offset, rnsArithmetic<ringSize, secret>* dst,
                                     rnsArithmetic<ringSize, secret>* src) const {
  int newOffset = offset / 2;
  int newSizeOfBatch = degree / newOffset;
  int sizeOfBatch = newSizeOfBatch / 2;
  rnsArithmetic<ringSize, secret> tmp;
  for (int i = 0 ; i < newOffset ; i++) {
    for (int j = 0 ; j < newSizeOfBatch ; j++) {
      int index = j < sizeOfBatch ? j : j - sizeOfBatch;
      keySet->mulRns(&tmp, &roots[j],
                              &src[i * newSizeOfBatch + sizeOfBatch + index]);
      keySet->addRns(&dst[i * newSizeOfBatch + j],
                              &src[i * newSizeOfBatch + index], &tmp,
                              j < sizeOfBatch);
    }
  }
}

template<int QL, int degree, uint64_t w>
template<int8_t ringSize>
template<bool secret>
void fheKey<QL, degree, w>::ring<ringSize>::InverseConvert(
      poly<ringSize, secret>* dst, const element<secret>* src) const {
  poly<ringSize, secret> tmp1;
  for (int i = 0 ; i < degree ; i++) {
    *(tmp1.getWritableCoefficient(i)) = *(src->getValue(degree - 1 - i));
  }
  element<secret> tmp2;
  convert(&tmp2, &tmp1);
  for (int i = 0 ; i < degree - 1; i++) {
    *(dst->getWritableCoefficient(i + 1)) = *(tmp2.getValue(i));
  }
  *(dst->getWritableCoefficient(0)) = *(tmp2.getValue(degree - 1));
}


template<int QL, int degree, uint64_t w>
template<int8_t ringSize>
template<bool secret>
void fheKey<QL, degree, w>::ring<ringSize>::evalAtPoint(rnsArithmetic<ringSize, secret>* dst,
                                             const rnsArithmetic<ringSize, 0>* x,
                                             const poly<ringSize, secret>* src) {
  *dst = *(src -> getCoefficient(0));
  for (int i = 1 ; i < degree ; i++) {
    keySet->addRns<ringSize>(dst, dst, src -> getCoefficient(i));
    keySet->mulRns<ringSize>(dst, dst, x);
  }
}

template<int QL, int degree, uint64_t w>
template<int8_t ringSize>
void fheKey<QL, degree, w>::ring<ringSize>::sampleUniformElement(element<0>* dst) const {
  for (int i = 0 ; i < degree ; i++) {
    for (int j = 0 ; j < ringSize ; j++) {
      arithmeticNum tmp = rand() % keySet->rnsBase[j];
      dst->getWritableValue(i)->setValue(j, tmp);
    }
  }
}


template<int QL, int degree, uint64_t w>
template<int8_t ringSize>
void fheKey<QL, degree, w>::ring<ringSize>::setConstElement(element<0>* dst,
                                                 const int c) const {
  for (int i = 0 ; i < degree ; i++) {
    keySet->setConstRns(dst->getWritableValue(i), c);
  }
}

template<int QL, int degree, uint64_t w>
template<int8_t ringSize>
void fheKey<QL, degree, w>::ring<ringSize>::squareElement(element<1>* dst,
                                            const element<1>* src) const {
  rnsArithmetic<QL, 1>* valuesSquared;
  keySet->backend->squareBatchRns(dst->getWritableValue(0), src->getValue(0),
                                  degree, keySet->numberOfParty);
}


template<int QL, int degree, uint64_t w>
template<int8_t ringSize>
template<bool s1, bool s2, bool s3>
void fheKey<QL, degree, w>::ring<ringSize>::mulElement(element<s3>* dst,
                                            const element<s1>* src1,
                                            const element<s2>* src2) const {
  static_assert(!(s1 and s2));
  for (int i = 0 ; i < degree ; i++) {
    keySet->mulRns(dst->getWritableValue(i), src1->getValue(i),
                   src2->getValue(i));
  }
}

template<int QL, int degree, uint64_t w>
template<int8_t ringSize>
template<bool s1, bool s2, bool s3>
void fheKey<QL, degree, w>::ring<ringSize>::addElement(element<s3>* dst,
                                            const element<s1>* src1,
                                            const element<s2>* src2,
                                            const bool sign) const {
  for (int i = 0 ; i < degree ; i++) {
    keySet->addRns(dst->getWritableValue(i), src1->getValue(i),
                   src2->getValue(i), sign);
  }
}

template<int QL, int degree, uint64_t w>
template<int8_t ringSize>
void fheKey<QL, degree, w>::ring<ringSize>::truncateElementWithP(element<1>* dst,
                                                      const element<1>* src,
                                                      const int index) const {
}

