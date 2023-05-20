#pragma once

template<int L>
class bigNum {
public:
  bigNum() {
    for (int i = 0 ; i < L ; i++) {
      data[i] = 0;
    }
  }
  uint32_t data[L];
  
  void setValue(uint64_t v) {
    data[0] = v;
  }
  void addMod(bigNum<L> const &obj, bigNum<L> const &mod) {
    *this = *this + obj;
    if (*this >= mod) {
      *this = *this - mod;
    }
  }
  bigNum<L> operator + (bigNum<L> const &obj) {
    bigNum<L> res;
    uint32_t carry = 0;
    for (int i = 0 ; i < L ; i++) {
      uint64_t tmp = carry;
      tmp = tmp + (uint64_t)data[i] + (uint64_t)obj.data[i];
      res.data[i] = tmp & 0xFFFFFFFF;
      carry = (tmp >> 32);
    }
    return res;
  }
  void operator += (bigNum<L> const &obj) {
    uint32_t carry = 0;
    for (int i = 0 ; i < L ; i++) {
      uint64_t tmp = carry;
      tmp = tmp + (uint64_t)data[i] + (uint64_t)obj.data[i];
      data[i] = tmp & 0xFFFFFFFF;
      carry = (tmp >> 32);
    }
  }
  
  bigNum<L> operator - (bigNum<L> const &obj) {
    bigNum<L> res;
    uint32_t carry = 0;
    for (int i = 0 ; i < L ; i++) {
      uint64_t tmp = carry;
      tmp = tmp + data[i] - obj.data[i];
      res.data[i] = tmp & 0xFFFFFFFF;
      carry = (tmp >> 32);
    }
    return res;
  }
  
  
  void operator -= (bigNum<L> const &obj) {
    uint32_t carry = 0;
    for (int i = 0 ; i < L ; i++) {
      uint64_t tmp = carry;
      tmp = tmp + data[i] - obj.data[i];
      data[i] = tmp & 0xFFFFFFFF;
      carry = (tmp >> 32);
    }
  }
  
  bool operator >= (bigNum<L> const &obj) {
    for (int i = L - 1 ; i >= 0 ; i--) {
      if (data[i] > obj.data[i]) {
        return true;
      }
      if (data[i] < obj.data[i]) {
        return false;
      }
    }
    return true;
  }
  
  bigNum<L> operator * (const uint64_t &obj) {
    bigNum<L> res;
    uint64_t tmp = 0;
    uint32_t* t = (uint32_t*)&obj;
    uint32_t carry;
    carry = 0;
    
    for (int j = 0 ; j < L; j++) {
      tmp = carry;
      tmp = tmp + (uint64_t)data[j] * (uint64_t)t[0];
      res.data[j] = tmp & 0xFFFFFFFF;
      carry = (tmp >> 32);
    }
    carry = 0;
    for (int j = 0 ; j < L - 1; j++) {
      tmp = res.data[j + 1] + carry;
      tmp = tmp + (uint64_t)data[j] * (uint64_t)t[1];
      res.data[j + 1] = tmp & 0xFFFFFFFF;
      carry = (tmp >> 32);
    }
    
    return res;
  }
};
