#pragma once
inline unsigned char extract(__m256i src, const int index) {
  unsigned char* pointer = (unsigned char*)&src;
  unsigned char byte = pointer[index / 8];
  return (byte >> (index & 0x111)) & 1;
}

static const int OTSeedSizeLarge = 240;
static const int OTSeedSizeStandard = 128;
template<int L, int degree>
class fheKey<L, degree>::cryptoBackends::obliviousTransfer {
public:
  void setup(cryptoBackends* backend, int ID);

  void biByteOT(unsigned char* src, unsigned char* dst, unsigned char* choice,
                size_t size);
  void biOT(uint64_t* src, uint64_t* dst, unsigned char* choice,
            size_t size);
  template<int n>
  void biHeavyOT(uint64_t* src, uint64_t* dst, unsigned char* choice,
            size_t size);
  void doubleBiOT(uint64_t* src64, __m128i* src128, uint64_t* dst64,
                  __m128i* dst128, unsigned char* choice1,
                  unsigned char* choice2, size_t size);
private:
  int dstID = -1;
  cryptoBackends* backend = nullptr;
  __m128i deltaStandard;
  __m256i deltaLarge;
  __m128i sendT0[OTSeedSizeLarge];
  __m128i sendT1[OTSeedSizeLarge];
  __m128i receiveT[OTSeedSizeLarge];
  AES_KEY sendT0Key[OTSeedSizeLarge];
  AES_KEY sendT1Key[OTSeedSizeLarge];
  AES_KEY receiveTKey[OTSeedSizeLarge];
  uint64_t index = 0;

  __m128i XOR(__m128i a, __m128i b) const {
    return _mm_xor_si128(a, b);
  }
  
  __m256i XOR(__m256i a, __m256i b) const {
    return (__m256i)_mm256_xor_ps((__m256)a, (__m256)b);
  }
  
  __m128i AND(__m128i a, __m128i b) const {
    return _mm_and_si128(a, b);
  }
  
  __m256i AND(__m256i a, __m256i b) const {
    return (__m256i)_mm256_and_ps((__m256)a, (__m256)b);
  }
  
  template<typename T>
  void transpose(T* dst, __m128i** src, size_t size);
  
  template<typename T>
  T getChoice(unsigned char choice) const{
    if constexpr (std::is_same<T, __m128i>::value) {
      assert(choice <= 1);
      return binaryChoice[choice];
    } else {
      assert(choice <= 15);
      return byteChoice[choice];
    }
  }
  
  
  void prg(__m128i* dst, int size, AES_KEY* Key, int keyIndex);
  
  template<unsigned char Mode, typename T, int vecLen = 0>
  void otBackend(T* src, __m128i* src128, T* dst, __m128i* dst128,
                 unsigned char* choice, unsigned char* choice128, size_t size);
};

template<int L, int degree>
void fheKey<L, degree>::cryptoBackends::obliviousTransfer::setup(cryptoBackends* backend, int ID) {
  this->backend = backend;
  dstID = ID;
  //baseOT
  //TODO
  backend->generateRandomBytes((unsigned char*)sendT0,
                               OTSeedSizeLarge * sizeof(__m128i));
  backend->generateRandomBytes((unsigned char*)sendT1,
                               OTSeedSizeLarge * sizeof(__m128i));
  backend->generateRandomBytes((unsigned char*)&deltaLarge, 32);
  memcpy((unsigned char*)&deltaStandard, (unsigned char*)&deltaLarge, 16);
  __m128i* tmprcv[2];
  tmprcv[0] = new __m128i[OTSeedSizeLarge];
  tmprcv[1] = new __m128i[OTSeedSizeLarge];
  if (dstID > backend->keySet->myID) {
    backend->io->sendToParty(sendT0, sizeof(__m128i) * OTSeedSizeLarge, dstID);
    backend->io->sendToParty(sendT1, sizeof(__m128i) * OTSeedSizeLarge, dstID);
    backend->io->receiveFromParty(tmprcv[0], sizeof(__m128i) * OTSeedSizeLarge,
                                  dstID);
    backend->io->receiveFromParty(tmprcv[1], sizeof(__m128i) * OTSeedSizeLarge,
                                  dstID);
  } else {
    backend->io->receiveFromParty(tmprcv[0], sizeof(__m128i) * OTSeedSizeLarge,
                                  dstID);
    backend->io->receiveFromParty(tmprcv[1], sizeof(__m128i) * OTSeedSizeLarge,
                                  dstID);
    backend->io->sendToParty(sendT0, sizeof(__m128i) * OTSeedSizeLarge, dstID);
    backend->io->sendToParty(sendT1, sizeof(__m128i) * OTSeedSizeLarge, dstID);
  }
  
  for (int i = 0 ; i < OTSeedSizeLarge ; i++) {
    receiveT[i] = tmprcv[extract(deltaLarge, i)][i];
    AES_set_encrypt_key(sendT0[i], &sendT0Key[i]);
    AES_set_encrypt_key(sendT1[i], &sendT1Key[i]);
    AES_set_encrypt_key(receiveT[i], &receiveTKey[i]);
  }
  delete[] tmprcv[0];
  delete[] tmprcv[1];
}

template<int L, int degree>
void fheKey<L, degree>::cryptoBackends::obliviousTransfer::biByteOT(
  unsigned char* src, unsigned char* dst, unsigned char* choice, size_t size) {
//  printf("byteOT %zu\n", size);
  otBackend<0, unsigned char>(src, nullptr, dst, nullptr, choice, nullptr,
                              size);
}


template<int L, int degree>
void fheKey<L, degree>::cryptoBackends::obliviousTransfer::biOT(uint64_t* src, uint64_t* dst, unsigned char* choice, size_t size) {
//  printf("biOT %zu\n", size);
  otBackend<1, uint64_t>(src, nullptr, dst, nullptr, choice, nullptr,
                         size);
}

template<int L, int degree>
template<int vecLen>
void fheKey<L, degree>::cryptoBackends::obliviousTransfer::biHeavyOT(uint64_t* src, uint64_t* dst, unsigned char* choice, size_t size) {
  otBackend<3, uint64_t, vecLen>(src, nullptr, dst, nullptr, choice, nullptr,
                         size);
}

template<int L, int degree>
void fheKey<L, degree>::cryptoBackends::obliviousTransfer::doubleBiOT(
  uint64_t* src64, __m128i* src128, uint64_t* dst64, __m128i* dst128,
  unsigned char* choice64, unsigned char* choice128, size_t size) {
//  printf("doubleBiOT %zu\n", size);
  otBackend<2, uint64_t>(src64, src128, dst64, dst128, choice64, choice128,
                         size);
}


template<int L, int degree>
template<typename T>
void fheKey<L, degree>::cryptoBackends::obliviousTransfer::transpose(T* dst, __m128i** src, size_t size) {
  const int length = (std::is_same<T, __m128i>::value) ? 128 : 240;
  for (int count = 0 ; count < size ; count++) {
    __m128i r[4][length];
    
    int offset = length / 2;
    for(int i = 0 ; i < offset ; i++) {
      r[0][i] = _mm_unpackhi_epi8(src[2 * i + 1][count], src[2 * i][count]);
    }

    for(int i = 0 ; i < offset ; i++) {
      r[0][offset + i] = _mm_unpacklo_epi8(src[2 * i + 1][count],
                                           src[2 * i][count]);
    }
        
    for(int j = 0 ; j < 2 ; j++) {
      for(int i = 0 ; i < offset / 2 ; i++) {
        r[1][i + j * offset] = _mm_unpackhi_epi16(r[0][2 * i + 1 + j * offset],
                                                  r[0][2 * i + j * offset]);
      }

      for(int i = 0 ; i < offset / 2 ; i++) {
        r[1][offset / 2 + i + j * offset] = _mm_unpacklo_epi16(
                                              r[0][2 * i + 1 + j * offset],
                                              r[0][2 * i + j * offset]);
      }
    }
    
    offset = offset / 2;
    for(int j = 0 ; j < 4 ; j++) {
      for(int i = 0 ; i < offset / 2 ; i++) {
        r[2][i + j * offset] = _mm_unpackhi_epi32(r[1][2 * i + 1 + j * offset],
                                                  r[1][2 * i + j * offset]);
      }
            
      for(int i = 0 ; i < offset / 2 ; i++) {
        r[2][offset / 2 + i + j * offset] = _mm_unpacklo_epi32(
                                              r[1][2 * i + 1 + j * offset],
                                              r[1][2 * i + j * offset]);
      }
    }

    offset = offset / 2;
    for(int j = 0 ; j < 8 ; j++) {
      for(int i = 0 ; i < offset / 2 ; i++) {
        r[3][i + j * offset] = _mm_unpackhi_epi64(r[2][2 * i + 1 + j * offset],
                                                  r[2][2 * i + j * offset]);
      }
    
      for(int i = 0 ; i < offset / 2 ; i++) {
        r[3][offset / 2 + i + j * offset] = _mm_unpacklo_epi64(
                                              r[2][2 * i + 1 + j * offset],
                                              r[2][2 * i + j * offset]);
      }
    }
    
    for(int i = 0 ; i < 8 ; i++) {
      for(int j = 0 ; j < 16 ; j++) {
        if constexpr (std::is_same<T, __m128i>::value) {
          dst[127 - (j * 8 + i) + count * 128] = _mm_set_epi16(
            _mm_movemask_epi8(r[3][j * 8]),
            _mm_movemask_epi8(r[3][j * 8 + 1]),
            _mm_movemask_epi8(r[3][j * 8 + 2]),
            _mm_movemask_epi8(r[3][j * 8 + 3]),
            _mm_movemask_epi8(r[3][j * 8 + 4]),
            _mm_movemask_epi8(r[3][j * 8 + 5]),
            _mm_movemask_epi8(r[3][j * 8 + 6]),
            _mm_movemask_epi8(r[3][j * 8 + 7]));
        } else {
          dst[127 - (j * 8 + i) + count * 128] = _mm256_set_epi16(
            _mm_movemask_epi8(r[3][j * 15]),
            _mm_movemask_epi8(r[3][j * 15 + 1]),
            _mm_movemask_epi8(r[3][j * 15 + 2]),
            _mm_movemask_epi8(r[3][j * 15 + 3]),
            _mm_movemask_epi8(r[3][j * 15 + 4]),
            _mm_movemask_epi8(r[3][j * 15 + 5]),
            _mm_movemask_epi8(r[3][j * 15 + 6]),
            _mm_movemask_epi8(r[3][j * 15 + 7]),
            _mm_movemask_epi8(r[3][j * 15 + 8]),
            _mm_movemask_epi8(r[3][j * 15 + 9]),
            _mm_movemask_epi8(r[3][j * 15 + 10]),
            _mm_movemask_epi8(r[3][j * 15 + 11]),
            _mm_movemask_epi8(r[3][j * 15 + 12]),
            _mm_movemask_epi8(r[3][j * 15 + 13]),
            _mm_movemask_epi8(r[3][j * 15 + 14]), 0);
        }
      }
      for(int j = 0 ; j < length ; j++) {
        r[3][j] = _mm_slli_epi16(r[3][j], 1);
      }
    }
  }
  
}


//mode 0 = byte OT
//mode 1 = bi OT
//mode 2 = double bi OT
//mode 3 = heavy bi OT

template<int L, int degree>
template<unsigned char Mode, typename T, int vecLen>
void fheKey<L, degree>::cryptoBackends::obliviousTransfer::otBackend(
    T* src, __m128i* src128, T* dst, __m128i* dst128,
    unsigned char* choice, unsigned char* choice128, size_t size) {
  assert((Mode == 2) || ((src128 == nullptr) && (dst128 == nullptr) && (choice128 == nullptr)));
  
  typedef typename std::conditional<Mode != 0,__m128i, __m256i>::type MaskType;
  __m128i** prgOutputs;
  
  int OTWidth;
  int OTSize;
  
  if constexpr (Mode == 0) {
    OTWidth = OTSeedSizeLarge;
  } else {
    OTWidth = OTSeedSizeStandard;
  }
  
  if constexpr (Mode == 2) {
    OTSize = 2 * size;
  } else {
    OTSize = size;
  }
  
  int prgSize = (OTSize + 127) / 128;
  OTSize = prgSize * 128;
  prgOutputs = new __m128i* [OTWidth * 3];
  for (int i = 0 ; i < OTWidth ; i++) {
    prgOutputs[i] = new __m128i[prgSize];
    backend->prg(prgOutputs[i], prgSize, &sendT0Key[i], index);
    prgOutputs[OTWidth + i] = new __m128i[prgSize];
    backend->prg(prgOutputs[OTWidth + i], prgSize, &sendT1Key[i], index);
    prgOutputs[OTWidth * 2 + i] = new __m128i[prgSize];
    backend->prg(prgOutputs[OTWidth * 2 + i], prgSize, &receiveTKey[i], index);
  }
  index += prgSize;
  
  MaskType* send0Mask = new MaskType[OTSize];
  MaskType* send1Mask = new MaskType[OTSize];
  MaskType* receiveMask = new MaskType[OTSize];
  transpose(send0Mask, prgOutputs, prgSize);
  transpose(send1Mask, &(prgOutputs[OTWidth]), prgSize);
  transpose(receiveMask, &(prgOutputs[OTWidth * 2]), prgSize);
  
  for (int i = 0 ; i < OTWidth * 3; i++) {
    delete[] prgOutputs[i];
  }
  delete[] prgOutputs;
  
  for (int i = 0 ; i < OTSize ; i++) {
    send1Mask[i] = XOR(send0Mask[i], send1Mask[i]);
  }
  for (int i = 0 ; i < size ; i++) {
    MaskType tmp;
    tmp = getChoice<MaskType>(choice[i]);
    send1Mask[i] = XOR(send1Mask[i], tmp);
    if constexpr (Mode == 2) {
      tmp = getChoice<MaskType>(choice128[i]);
      send1Mask[i + size] = XOR(send1Mask[i + size], tmp);
    }
  }
  MaskType* send1Mask1 = new MaskType[OTSize];
  if constexpr (Mode != 0) {
    if (dstID < backend->keySet->myID) {
      backend->io->sendToParty(send1Mask, sizeof(MaskType) * OTSize, dstID);
      backend->io->receiveFromParty(send1Mask1, sizeof(MaskType) * OTSize, dstID);
    } else {
      backend->io->receiveFromParty(send1Mask1, sizeof(MaskType) * OTSize, dstID);
      backend->io->sendToParty(send1Mask, sizeof(MaskType) * OTSize, dstID);
    }
  } else {
    if (dstID < backend->keySet->myID) {
      for (int i = 0 ; i < OTSize ; i++) {
        backend->io->sendToParty((unsigned char*)&(send1Mask[i]), 30, dstID);
      }
      for (int i = 0 ; i < OTSize ; i++) {
         backend->io->receiveFromParty((unsigned char*)&(send1Mask1[i]), 30,
                                       dstID);
      }
    } else {
      for (int i = 0 ; i < OTSize ; i++) {
         backend->io->receiveFromParty((unsigned char*)&(send1Mask1[i]), 30,
                                       dstID);
      }
      for (int i = 0 ; i < OTSize ; i++) {
        backend->io->sendToParty((unsigned char*)&(send1Mask[i]), 30, dstID);
      }
    }
  }
  delete[] send1Mask;
  
  for (int i = 0 ; i < OTSize ; i++) {
    if constexpr (Mode == 0) {
      send1Mask1[i] = AND(deltaLarge, send1Mask1[i]);
    } else {
      send1Mask1[i] = AND(deltaStandard, send1Mask1[i]);
    }
    receiveMask[i] = XOR(receiveMask[i], send1Mask1[i]);
  }
  delete[] send1Mask1;
  
  if constexpr(Mode == 0) {
    unsigned char* offsetSend = new unsigned char[size * 16];
    unsigned char* offsetReceive = new unsigned char[size * 16];
    unsigned char SHAoutput[SHA256_DIGEST_LENGTH];
    
    __m256i tmp;
    for (int i = 0 ; i < size ; i++) {
      for (int j = 0 ; j < 16 ; j++) {
        tmp = XOR(receiveMask[i], getChoice<__m256i>(j));
        SHA256((unsigned char*)&tmp, 30, SHAoutput);
        offsetSend[i * 16 + j] = src[i * 16 + j] ^ SHAoutput[0];
      }
    }
    
    if (dstID < backend->keySet->myID) {
      backend->io->sendToParty(offsetSend, 16 * size, dstID);
      backend->io->receiveFromParty(offsetReceive, 16 * size, dstID);
    } else {
      backend->io->receiveFromParty(offsetReceive, 16 * size, dstID);
      backend->io->sendToParty(offsetSend, 16 * size, dstID);
    }
    delete[] offsetSend;
    delete[] receiveMask;
    
    for (int i = 0 ; i < size ; i++) {
      SHA256((unsigned char*)&send0Mask[i], 30, SHAoutput);
      dst[i] = SHAoutput[0] ^ offsetReceive[16 * i + choice[i]];
    }
    delete[] offsetReceive;
    delete[] send0Mask;
  }
  if constexpr (Mode == 3) {
    uint64_t* offsetSend = new uint64_t[vecLen * size * 2];
    uint64_t* offsetReceive = new uint64_t[vecLen * size * 2];
    
    uint64_t SHAoutput[SHA256_DIGEST_LENGTH / 8];
    __m128i tmp[2];
    for (int i = 0 ; i < size ; i++) {
      for (int j = 0 ; j < 2 ; j++)  {
        tmp[1] = XOR(receiveMask[i], getChoice<__m128i>(j));
        for (int l = 0 ; l < vecLen ; l++) {
          tmp[0] = _mm_set_epi32(0, 0, 0, l);
          tmp[0] = _mm_xor_si128(tmp[1], tmp[0]);
          SHA256((unsigned char*)tmp, sizeof(__m128i),
                 (unsigned char*)SHAoutput);
          offsetSend[(i * 2 + j) * vecLen + l] = src[(i * 2 + j) * vecLen + l] ^
                                                 SHAoutput[0];
        }
      }
    }
    if (dstID < backend->keySet->myID) {
      backend->io->sendToParty(offsetSend, vecLen * 2 * sizeof(uint64_t) * size,
                               dstID);
      backend->io->receiveFromParty(offsetReceive,
                                    vecLen * 2 * sizeof(uint64_t) * size,
                                    dstID);
    } else {
      backend->io->receiveFromParty(offsetReceive,
                                    vecLen * 2 * sizeof(uint64_t) * size,
                                    dstID);
      
      backend->io->sendToParty(offsetSend, vecLen * 2 * sizeof(uint64_t) * size,
                               dstID);
    }
  
    delete[] offsetSend;
    delete[] receiveMask;
    for (int i = 0 ; i < size ; i++) {
      __m128i tmp;
      for (int l = 0 ; l < vecLen ; l++) {
        tmp = _mm_set_epi32(0, 0, 0, l);
        tmp = _mm_xor_si128(tmp, send0Mask[i]);
        SHA256((unsigned char*)&tmp, sizeof(__m128i),
               (unsigned char*)SHAoutput);
        dst[i * vecLen + l] = SHAoutput[0] ^
          offsetReceive[2 * i * vecLen + l + choice[i]];
      }
    }
    
    delete[] offsetReceive;
    delete[] send0Mask;
  }
  
  if constexpr ((Mode == 1) or (Mode == 2)) {
    uint64_t* offsetSend = new uint64_t[size * 2];
    uint64_t* offsetReceive = new uint64_t[size * 2];
    __m128i* offsetSend128 = nullptr;
    __m128i* offsetReceive128 = nullptr;
    
    uint64_t SHAoutput[SHA256_DIGEST_LENGTH / 8];
    __m128i tmp;
    for (int i = 0 ; i < size ; i++) {
      for (int j = 0 ; j < 2 ; j++) {
        tmp = XOR(receiveMask[i], getChoice<__m128i>(j));
        SHA256((unsigned char*)&tmp, sizeof(__m128i),
               (unsigned char*)SHAoutput);
        offsetSend[i * 2 + j] = src[i * 2 + j] ^ SHAoutput[0];
      }
    }
    if constexpr(Mode == 2) {
      __m128i SHAoutput[SHA256_DIGEST_LENGTH / 16];
      __m128i tmp;
      offsetSend128 = new __m128i[size * 2];
      offsetReceive128 = new __m128i[size * 2];
      for (int i = 0 ; i < size ; i++) {
        for (int j = 0 ; j < 2 ; j++) {
          tmp = XOR(receiveMask[i], getChoice<__m128i>(j));
          SHA256((unsigned char*)&tmp, sizeof(__m128i),
                 (unsigned char*)SHAoutput);
          offsetSend128[i * 2 + j] = XOR(src128[i * 2 + j], SHAoutput[0]);
        }
      }
    }
    
    if (dstID < backend->keySet->myID) {
      backend->io->sendToParty(offsetSend, 2 * sizeof(uint64_t) * size,
                               dstID);
      if constexpr(Mode == 2) {
         backend->io->sendToParty(offsetSend128, 2 * sizeof(__m128i) * size,
                                  dstID);
      }
      
      backend->io->receiveFromParty(offsetReceive,
                                    2 * sizeof(uint64_t) * size,
                                    dstID);
      if constexpr(Mode == 2) {
         backend->io->receiveFromParty(offsetReceive128,
                                       2 * sizeof(__m128i) * size,
                                       dstID);
      }
    } else {
      backend->io->receiveFromParty(offsetReceive,
                                    2 * sizeof(uint64_t) * size,
                                    dstID);
      if constexpr(Mode == 2) {
         backend->io->receiveFromParty(offsetReceive128,
                                       2 * sizeof(__m128i) * size,
                                       dstID);
      }
      
      backend->io->sendToParty(offsetSend, 2 * sizeof(uint64_t) * size,
                               dstID);
      if constexpr(Mode == 2) {
         backend->io->sendToParty(offsetSend128, 2 * sizeof(__m128i) * size,
                                  dstID);
      }
    }
    delete[] offsetSend;
    delete[] receiveMask;
    if constexpr(Mode == 2) {
      delete[] offsetSend128;
    }

    
    for (int i = 0 ; i < size ; i++) {
      SHA256((unsigned char*)&send0Mask[i], sizeof(__m128i),
             (unsigned char*)SHAoutput);
      dst[i] = SHAoutput[0] ^ offsetReceive[2 * i + choice[i]];
      if constexpr(Mode == 2) {
        __m128i SHAoutput128[SHA256_DIGEST_LENGTH / 16];
        SHA256((unsigned char*)&send0Mask[i + size], sizeof(__m128i),
               (unsigned char*)SHAoutput128);
        dst128[i] = XOR(SHAoutput128[0], offsetReceive128[2 * i + choice[i]]);
      }
    }
    
    delete[] offsetReceive;
    if constexpr(Mode == 2) {
      delete[] offsetReceive128;
    }
    delete[] send0Mask;
  }
}
