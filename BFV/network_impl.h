#pragma once
#define Local
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <type_traits>
#include <mutex>

#ifndef Local
#define Address0 "149.165.157.162"
#define Address1 "149.165.156.114"
#define Address2 "149.165.168.107"
#define Address3 "149.165.169.218"
#define Address4 "149.165.168.213"
#define Address5 "149.165.169.155"
#define Address6 "149.165.169.192"
#define Address7 "149.165.170.9"
#define Address8 "149.165.169.133"
#define Address9 "149.165.169.207"
#define AddressA "149.165.169.166"
#define AddressB "149.165.168.242"
#define AddressC "149.165.169.58"
#define AddressD "149.165.170.23"
#define AddressE "149.165.168.234"
#define AddressF "149.165.169.83"
#else
#define Address0 "127.0.0.1"
#define Address1 "127.0.0.1"
#define Address2 "127.0.0.1"
#define Address3 "127.0.0.1"
#define Address4 "127.0.0.1"
#define Address5 "127.0.0.1"
#define Address6 "127.0.0.1"
#define Address7 "127.0.0.1"
#define Address8 "127.0.0.1"
#define Address9 "127.0.0.1"
#define AddressA "127.0.0.1"
#define AddressB "127.0.0.1"
#define AddressC "127.0.0.1"
#define AddressD "127.0.0.1"
#define AddressE "127.0.0.1"
#define AddressF "127.0.0.1"
#endif

const char *HostAddress[16]={Address0, Address1, Address2, Address3, Address4,
  Address5, Address6, Address7, Address8, Address9, AddressA, AddressB,
  AddressC, AddressD, AddressE, AddressF};

template<int QL, int degree, uint64_t w>
class fheKey<QL, degree, w>::cryptoBackends::network {
  template<int l, int d, uint64_t w1>
  using Network = typename fheKey<QL, d, w1>::cryptoBackends::network;
public:
  network(const char** add, int ID, int n, int port, cryptoBackends* back);
  ~network();
  void exchange(unsigned char** dst, unsigned char* src, size_t size);
  
  template<int8_t ringSize>
  void batchOpenRns(rnsArithmetic<ringSize, 0>* dst, rnsArithmetic<ringSize, 1>* src,
                 size_t size, int numberOfPartyThisRound);
  
  void batchOpenBytes(unsigned char* dst, unsigned char* src, size_t size, int numberOfPartyThisRound = 0);
  
  void batchRandomBitMultiplication(unsigned char* dst, size_t size);
  
  // computes \sum_{i < j} src_isrc_j
  template<int8_t ringSize>
  void batchMultiplicationDegree2(rnsArithmetic<ringSize, 1>* dst,
                                  rnsArithmetic<ringSize, 0>* src,
                                  size_t size,
                                  int numberOfPartyThisRound);
  
  // computes (\sum_{i < j} src_isrc_j, \sum_{i < j} src^2_isrc_j+src_isrc^2_j
  //
  void batchMultiplicationDegree4(rnsArithmetic<QL, 1>* dst,
                                  rnsArithmetic<QL, 0>* src,
                                  size_t size,
                                  int numberOfPartyThisRound);
  
  template<int8_t ringSize, int vecLen>
  void batchGeneralMultiplication(rnsArithmetic<ringSize, 1>* dst,
                                  rnsArithmetic<ringSize, 0>* inputL,
                                  rnsArithmetic<ringSize, 0>* inputR, int n);
  
  void sendToParty(const void* src, size_t size, int ID);
  void receiveFromParty(void* dst, size_t size, int ID);
  void printAndResetBW() const {
    for (int i = 0 ; i < numberOfParty ; i++) {
      if (myID != i) {
        printf("Party %d to party %d incoming/outgoing: %llu %llu\n",
               myID, i, incoming[i], outgoing[i]);
        incoming[i] = 0;
        outgoing[i] = 0;
      }
    }
  }
private:
  cryptoBackends* backend;
  std::mutex flushMutex;
//  void sendToParty(const void* src, size_t size, int ID);
//  void receiveFromParty(void* dst, size_t size, int ID);
  template<int8_t ringSize, bool square>
  void expandRnsSource(rnsArithmetic<ringSize, 0>* dst,
                       rnsArithmetic<ringSize, 0>* src, size_t size);
  
  template<int8_t ringSize, bool square>
  void expandRnsChoice(unsigned char* dst, rnsArithmetic<ringSize, 0>* src,
                 size_t size);
  template<int8_t ringSize, bool secret>
  void sendRNSToParty(rnsArithmetic<ringSize, secret>* src, int ID);
  
  template<int8_t ringSize, bool secret>
  void receiveRNSFromParty(rnsArithmetic<ringSize, secret>* dst, int ID);
  
  template<typename Tdst, typename Tsrc>
  void batchOpen(Tdst* dst, Tsrc* src, size_t size,
                 int numberOfPartyThisRound);
  
  int minimumPartyID(int numberOfPartyThisRound);
  int maximumPartyID(int numberOfPartyThisRound);
  
  
  struct biDirectionPort {
    FILE* inPort;
    FILE* outPort;
  };
  
  void openPortServer(biDirectionPort* dst, int portNo);
  void openPortClient(biDirectionPort* dst, const char* serverAddress,
                      int portNo);
  const int defaultPortNum;
  int myID;
  const int numberOfParty;
  uint64_t* incoming;
  uint64_t* outgoing;
  const char** addresses;
  biDirectionPort* ports;
  ThreadPool* pool;
};

template<int QL, int degree, uint64_t w>
fheKey<QL, degree, w>::cryptoBackends::network::network(const char** add, int ID,
                                                    int n, int port,
                                                    cryptoBackends* back):
    addresses(add), myID(ID), numberOfParty(n), defaultPortNum(port),
    backend(back){
  pool = new ThreadPool(numberOfParty - 1);
  ports = new biDirectionPort[numberOfParty];
  int offset = 0;
  for (int i = 0 ; i < n ; i++) {
    for (int j = i + 1 ; j < n ; j++) {
      if (ID == i) {
        openPortServer(&(ports[j]), defaultPortNum + offset);
      } else if (ID == j) {
        openPortClient(&(ports[i]), addresses[i], defaultPortNum + offset);
      }
      offset++;
    }
  }
  incoming = new uint64_t[numberOfParty];
  outgoing = new uint64_t[numberOfParty];
  for (int i = 0 ; i < numberOfParty ; i++) {
    incoming[i] = 0;
    outgoing[i] = 0;
  }
}

template<int QL, int degree, uint64_t w>
fheKey<QL, degree, w>::cryptoBackends::network::~network() {
  for (int i = 0 ; i < numberOfParty ; i++) {
    if (i != myID) {
      fclose(ports[i].inPort);
      fclose(ports[i].outPort);
    }
  }
  delete[] ports;
  delete pool;
  delete[] incoming;
  delete[] outgoing;
}

template<int QL, int degree, uint64_t w>
void fheKey<QL, degree, w>::cryptoBackends::network::openPortServer(biDirectionPort* dst, int portNo) {
  int sockfd, newsockfd,newsockfddup;
  socklen_t clilen;
  struct sockaddr_in serv_addr, cli_addr;
  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) {
    perror("ERROR opening socket");
    exit(EXIT_FAILURE);
  }
  memset((char*)&serv_addr, 0, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = INADDR_ANY;
  serv_addr.sin_port = htons(portNo);
  int on=1;
  if((setsockopt(sockfd,SOL_SOCKET,SO_REUSEADDR,&on,sizeof(on)))<0) {
     perror("setsockopt failed");
     exit(EXIT_FAILURE);
  }
  if (bind(sockfd, (struct sockaddr*) &serv_addr, sizeof(serv_addr)) < 0) {
    perror("ERROR on binding");
    exit(EXIT_FAILURE);
  }
  listen(sockfd,5);
  clilen = sizeof(cli_addr);
  newsockfd = accept(sockfd, (struct sockaddr*) &cli_addr, &clilen);
  if (newsockfd < 0) {
    perror("ERROR on accept");
    exit(EXIT_FAILURE);
  }
  newsockfddup = dup(newsockfd);
  if (newsockfddup < 0) {
    perror("ERROR on DUP");
    exit(EXIT_FAILURE);
  }
  close(sockfd);
  dst->outPort = fdopen(newsockfd, "w");
  dst->inPort = fdopen(newsockfddup,"r");
  printf("connected Server at %d\n", portNo);
  return;
}


template<int QL, int degree, uint64_t w>
void fheKey<QL, degree, w>::cryptoBackends::network::openPortClient(biDirectionPort* dst, const char* serverAddress, int portNo) {
  int sockfd,sockfddup;
  struct sockaddr_in serv_addr;
  struct hostent *server;
  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) {
    perror("ERROR opening socket");
    exit(EXIT_FAILURE);
  }
  server = gethostbyname(serverAddress);
  memset((char*)&serv_addr, 0, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  memcpy((char*)&serv_addr.sin_addr.s_addr, (char*)server->h_addr,
        server->h_length);
  serv_addr.sin_port = htons(portNo);
  while(connect(sockfd,(struct sockaddr*)&serv_addr,sizeof(serv_addr)) == -1) {
    usleep(1000);
  }
  sockfddup = dup(sockfd);
  if (sockfddup < 0) {
    perror("ERROR on DUP");
    exit(EXIT_FAILURE);
  }
  dst->inPort = fdopen(sockfd, "r");
  dst->outPort = fdopen(sockfddup, "w");
  printf("connected Clinet at %d\n",portNo);
  return;
}

template<int QL, int degree, uint64_t w>
void fheKey<QL, degree, w>::cryptoBackends::network::sendToParty(const void* src,
                                                             size_t size,
                                                             int ID) {
  size_t s;
  s = fwrite((unsigned char*)src, sizeof(unsigned char), size,
             ports[ID].outPort);
  assert(s == size);
  outgoing[ID] += size;
  fflush(ports[ID].outPort);
}

template<int QL, int degree, uint64_t w>
void fheKey<QL, degree, w>::cryptoBackends::network::receiveFromParty(void* dst,
                                                                  size_t size,
                                                                  int ID) {
  size_t s;
  s = fread((unsigned char*)dst, sizeof(unsigned char), size,
             ports[ID].inPort);
  assert(s == size);
  incoming[ID]+= size;
}

template<int QL, int degree, uint64_t w>
void fheKey<QL, degree, w>::cryptoBackends::network::exchange(unsigned char** dst,
                                                          unsigned char* src,
                                                          size_t size) {
  
  std::future<int> future[numberOfParty];
  
  for (int i = 0 ; i < numberOfParty ; i++) {
    if (i != myID) {
      int j = i;
      if (i > myID) {
        j--;
      }
      future[i] = pool->enqueue([](Network<QL, degree, w>* io, void* src, void* dst,
                                   size_t size, int ID, bool order) -> int {
        if (order) {
          io->sendToParty(src, size, ID);
          io->receiveFromParty(dst, size, ID);
        } else {
          io->receiveFromParty(dst, size, ID);
          io->sendToParty(src, size, ID);
        }
        return 1;
      }, this, src, dst[j], size, i, i < myID);
    }
  }
  for (int i = 0 ; i < numberOfParty ; i++) {
    if (i != myID) {
      future[i].get();
    }
  }
}

template<int QL, int degree, uint64_t w>
template<typename Tdst, typename Tsrc>
void fheKey<QL, degree, w>::cryptoBackends::network::batchOpen(Tdst* dst, Tsrc* src,
                                                           size_t size,
                                                           int numberOfPartyThisRound) {
  memcpy(dst, src, sizeof(Tsrc) * size);
  int start = minimumPartyID(numberOfPartyThisRound);
  int end = maximumPartyID(numberOfPartyThisRound);
  Tdst* tmp[end - start - 1];
  std::future<int> future[end - start - 1];
  for (int i = start ; i < end ; i++) {
    if (i != myID) {
      int j = i;
      if (j > myID){
        j--;
      }
      tmp[j - start] = new Tdst[size];
      future[j - start] = pool->enqueue([](Network<QL, degree, w>* io,
                                           unsigned char* dst,
                                           unsigned char* src, size_t size,
                                           int ID, bool order) -> int {
        if (order) {
          io->sendToParty(src, size * sizeof(Tsrc), ID);
          io->receiveFromParty(dst, size * sizeof(Tsrc), ID);
        } else {
          io->receiveFromParty(dst, size * sizeof(Tsrc), ID);
          io->sendToParty(src, size * sizeof(Tsrc), ID);
        }
        return 1;
      }, this, (unsigned char*)(tmp[j - start]), (unsigned char*)src, size, i,
                                i > myID);
    }
  }
  
  for (int i = start ; i < end ; i++) {
     if (i != myID) {
       int j = i;
       if (j > myID){
         j--;
       }
       future[j - start].get();
       for (int t = 0 ; t < size ; t++) {
         if constexpr((std::is_same<Tsrc, rnsArithmetic<QL, 1>>::value) ||
                      (std::is_same<Tsrc, rnsArithmetic<QL, 1>>::value)) {
           backend->keySet->addRns(&dst[t], &dst[t], &tmp[j - start][t], 1);
         }
         if constexpr(std::is_same<Tsrc, unsigned char>::value) {
           dst[t] ^= tmp[j - start][t];
         }
       }
       delete[] tmp[j - start];
     }
   }
}


template<int QL, int degree, uint64_t w>
template<int8_t ringSize>
void fheKey<QL, degree, w>::cryptoBackends::network::batchOpenRns(rnsArithmetic<ringSize, 0>* dst, rnsArithmetic<ringSize, 1>* src, size_t size, int numberOfPartyThisRound) {
  batchOpen(dst, src, size, numberOfPartyThisRound);
}


template<int QL, int degree, uint64_t w>
void fheKey<QL, degree, w>::cryptoBackends::network::batchOpenBytes(unsigned char* dst, unsigned char* src, size_t size, int numberOfPartyThisRound) {
  if (numberOfPartyThisRound != 0) {
    batchOpen(dst, src, size, numberOfPartyThisRound);
  } else {
    batchOpen(dst, src, size, numberOfParty);
  }
}

template<int QL, int degree, uint64_t w>
int fheKey<QL, degree, w>::cryptoBackends::network::minimumPartyID(int numberOfPartyThisRound) {
  int bits = log2(numberOfPartyThisRound);
  int x = (1 << bits) - 1;
  return myID - (myID & x);
}

template<int QL, int degree, uint64_t w>
int fheKey<QL, degree, w>::cryptoBackends::network::maximumPartyID(int numberOfPartyThisRound) {
    int bits = log2(numberOfPartyThisRound);
       int x = (1 << bits) - 1;
       return myID - (myID & x) + (1 << bits);
}


template<int QL, int degree, uint64_t w>
template<int8_t ringSize, bool square>
void fheKey<QL, degree, w>::cryptoBackends::network::expandRnsSource(rnsArithmetic<ringSize, 0>* dst,
                                  rnsArithmetic<ringSize, 0>* src, size_t size) {
  rnsArithmetic<ringSize, 0>* constants = new rnsArithmetic<ringSize, 0>[primeWidth];
  for (int i = 0 ; i < primeWidth ; i++) {
    backend->keySet->setConstRns(&constants[i], 1 << i);
  }

  for (int i = 0 ; i < size ; i++) {
    rnsArithmetic<ringSize, 0> tmp;
    if constexpr(square) {
      backend->keySet->mulRns(&tmp, &(src[i]), &(src[i]));
    } else {
      tmp = src[i];
    }
    
    for (int j = 0 ; j < primeWidth ; j++) {
      backend->keySet->mulRns(&dst[i * primeWidth + j], &tmp,
                              &(constants[j]));
    }
  }
  delete[] constants;
}


template<int QL, int degree, uint64_t w>
template<int8_t ringSize, bool square>
void fheKey<QL, degree, w>::cryptoBackends::network::expandRnsChoice(
  unsigned char* dst, rnsArithmetic<ringSize, 0>* src, size_t size) {
  for (int i = 0 ; i < size ; i++) {
    rnsArithmetic<ringSize, 0> tmp;
    if constexpr(square) {
      backend->keySet->mulRns(&tmp, &(src[i]), &(src[i]));
    } else {
      tmp = src[i];
    }
    for (int j = 0 ; j < primeWidth ; j++) {
      for(int k = 0 ; k < ringSize ; k++) {
        // (y >> i) ^ 1
        arithmeticNum tmpValue = tmp.getValue(k);
        int index = i * ringSize * primeWidth + j * ringSize + k;
        dst[index] = tmpValue & 1;
        tmpValue = tmpValue >> 1;
        tmp.setValue(k, tmpValue);
      }
    }
  }
}

template<int QL, int degree, uint64_t w>
void fheKey<QL, degree, w>::cryptoBackends::network::batchRandomBitMultiplication(
    unsigned char* dst, size_t size) {
  assert(size % 4 == 0);
  backend->generateRandomBytes(dst, size);
  unsigned char** outputs = new unsigned char* [numberOfParty];
  for (int i = 0 ; i < size ; i++) {
    dst[i] &= 0x11;
  }
  
  std::future<int> future[numberOfParty];
  for (int i = 0 ; i < numberOfParty ; i++) {
    if (i != myID) {
      outputs[i] = new unsigned char[size];
      future[i] = pool->enqueue([](cryptoBackends* backend,
                                   unsigned char* threadDst,
                                   unsigned char* send,
                                   int size, int ID)->int {
        unsigned char* tmpMask = new unsigned char[size / 4];
        backend->generateRandomBytes(tmpMask, size / 4);
        for (int i = 0 ; i < size / 4 ; i++) {
          tmpMask[i] &= 0x1111;
        }
        unsigned char* src = new unsigned char[size / 4 * 16];
        unsigned char* choice = new unsigned char[size / 4];
        for (int i = 0 ; i < size / 4 ; i++) {
          unsigned char tmp[8];
          for (int j = 0 ; j < 4 ; j++) {
            threadDst[i * 4 + j] = (tmpMask[i] >> j) & 1;
            tmp[2 * j] = (tmpMask[i] >> j) & 1;
            tmp[2 * j + 1] = (send[i * 4 + j] & 1) ^ tmp[2 * j];
            tmp[2 * j] = tmp[2 * j] << j;
            tmp[2 * j +1] = tmp[2 * j + 1] << j;
          }
          for (int j = 0 ; j < 16 ; j++) {
            src[i * 16 + j] = 0;
            for (int k = 0 ; k < 4; k++) {
              src[i * 16 + j] ^= tmp[2 * k + ((j >> k) & 1)];
            }
          }
          
          choice[i] = 0;
          for (int k = 3 ; k >= 0 ; k--) {
            choice[i] = choice[i] + ((send[i * 4 + k] >> 1) & 1);
            choice[i] = choice[i] << 1;
          }
        }
        
        delete[] tmpMask;
        unsigned char* rcv = new unsigned char[size / 4];
        backend->OT[ID].biByteOT(src, rcv, choice, size / 4);
        delete[] src;
        delete[] choice;
        for (int i = 0 ; i < size / 4 ; i++) {
          for (int j = 0 ; j < 4 ; j++) {
            threadDst[i * 4 + j] = (threadDst[i * 4 + j] ^
                                    ((rcv[i] >> j) & 1)) << 2;
          }
        }
        delete[] rcv;
        return 1;
      }, backend, outputs[i], dst, size, i);
    }
  }
  
  for (int i = 0 ; i < numberOfParty ; i++) {
    if (i != myID) {
      future[i].get();
      for (int j = 0 ; j < size ; j++) {
        dst[j] ^= outputs[i][j];
      }
      delete[] outputs[i];
    }
  }
  delete[] outputs;
}

template<int QL, int degree, uint64_t w>
template<int8_t ringSize>
void fheKey<QL, degree, w>::cryptoBackends::network::batchMultiplicationDegree2(
    rnsArithmetic<ringSize, 1>* dst, rnsArithmetic<ringSize, 0>* src, size_t size,
    int numberOfPartyThisRound) {
  assert(size % 2 == 0);
  for (int i = 0 ; i < size ; i++) {
    backend->keySet->setSecretRns(&(dst[i]), 0);
  }
  
  int numberOfOT = size * primeWidth * ringSize;
  
  rnsArithmetic<ringSize, 0>* sendNumber = new rnsArithmetic<ringSize, 0>[size * primeWidth];
  unsigned char* receiveChoice = new unsigned char[numberOfOT];
  expandRnsSource<ringSize, 0>(sendNumber, src, size);
  expandRnsChoice<ringSize, 0>(receiveChoice, src, size);
  
  //OT
  int end = maximumPartyID(numberOfPartyThisRound);
  int start = minimumPartyID(numberOfPartyThisRound);
  rnsArithmetic<ringSize, 0>** outputs = new rnsArithmetic<ringSize, 0>* [end - start];
  std::future<int> future[end - start];
  
  for (int i = start ; i < end ; i++) {
    if (i != myID) {
      outputs[i - start] = new rnsArithmetic<ringSize, 0> [size];
      future[i - start] = pool->enqueue([](cryptoBackends* backend,
                                           rnsArithmetic<ringSize, 0>* dst,
                                           rnsArithmetic<ringSize, 0>* sendNumber,
                                           unsigned char* choice,
                                           int size, int ID, int myID)->int {
        size_t offset1 = ID > myID ? 0 : size / 2;
        size_t offset2 = ID < myID ? 0 : size / 2;

        int numberOfBiOT = size * primeWidth * ringSize / 2;
        rnsArithmetic<ringSize, 0>* tmpMask =
          new rnsArithmetic<ringSize, 0> [size / 2 * primeWidth];
        backend->generateRandomShares(tmpMask, size / 2 * primeWidth);

        //add up the random masks, they are the offsets
        for (int j = 0 ; j < size / 2 ; j++) {
         for (int k = 0 ; k < primeWidth ; k++) {
           backend->keySet->addRns(&dst[j + offset1], &dst[j + offset1],
                                   &tmpMask[j * primeWidth + k], 0);
         }
        }

        uint64_t* src = new uint64_t[numberOfBiOT * 2];

        for (int j = 0 ; j < size / 2 * primeWidth ; j++) {
         rnsArithmetic<ringSize, 0> tmpSum;
         backend->keySet->addRns(&tmpSum, &tmpMask[j],
                                 &sendNumber[j + offset1], 1);
         
         for (int k = 0 ; k < ringSize ; k++) {
           arithmeticNum tmpNum1 = tmpMask[j].getValue(k);
           arithmeticNum tmpNum2 = tmpSum.getValue(k);
           memcpy(&src[2 * (j * ringSize + k)], &tmpNum1,
                  sizeof(arithmeticNum));
           memcpy(&src[2 * (j * ringSize + k) + 1], &tmpNum2,
                  sizeof(arithmeticNum));
         }
        }
        uint64_t* rcv = new uint64_t[numberOfBiOT];
        backend->OT[ID].biOT(src, rcv,
                            &choice[offset2 * primeWidth * ringSize],
                            numberOfBiOT);
        delete[] src;

        for (int j = 0 ; j < size / 2 * primeWidth ; j++) {
         for (int k = 0 ; k < ringSize ; k++) {
           arithmeticNum tmpNum;
           memcpy(&tmpNum, &rcv[j * ringSize + k], sizeof(arithmeticNum));
           tmpMask[j].setValue(k, tmpNum);
         }
        }
        delete[] rcv;
        for (int j = 0 ; j < size / 2; j++) {
         for (int k = 0 ; k < primeWidth ; k++) {
           backend->keySet->addRns(&dst[j + offset2], &dst[j],
                                   &tmpMask[j * primeWidth + k], 1);
         }
        }
        delete[] tmpMask;
        return 1;
        }, backend, outputs[i - start], sendNumber, receiveChoice, size, i,
                                        myID);

    }
  }
  
  for (int i = start ; i < end ; i++) {
    if (i != myID) {
      future[i - start].get();
      for (int j = 0 ; j < size ; j++) {
        backend->keySet->addRns(&dst[j], &dst[j],
                                &outputs[i - start][j], 1);
      }
      delete[] outputs[i - start];
    }
  }
  delete[] outputs;
  delete[] sendNumber;
  delete[] receiveChoice;
}



template<int QL, int degree, uint64_t w>
void fheKey<QL, degree, w>::cryptoBackends::network::batchMultiplicationDegree4(
    rnsArithmetic<QL, 1>* dst, rnsArithmetic<QL, 0>* src, size_t size,
                                                                                int numberOfPartyThisRound) {}

template<int QL, int degree, uint64_t w>
template<int8_t ringSize, int vecLen>
void fheKey<QL, degree, w>::cryptoBackends::network::batchGeneralMultiplication(rnsArithmetic<ringSize, 1>* dst, rnsArithmetic<ringSize, 0>* inputL,
     rnsArithmetic<ringSize, 0>* inputR, int size) {
  assert(size % 2 == 0);
  for (int i = 0 ; i < size ; i++) {
    backend->keySet->setSecretRns(&(dst[i]), 0);
  }
       
  int numberOfOT = size * primeWidth * ringSize;
       
  rnsArithmetic<ringSize, 0>* sendNumber = new rnsArithmetic<ringSize, 0>[size * primeWidth * vecLen];
  unsigned char* receiveChoice = new unsigned char[numberOfOT];
  expandRnsSource<ringSize, 0>(sendNumber, inputL, size * vecLen);
  expandRnsChoice<ringSize, 0>(receiveChoice, inputR, size);
  rnsArithmetic<ringSize, 0>** outputs =
      new rnsArithmetic<ringSize, 0>* [numberOfParty];
  std::future<int> future[numberOfParty];
  for (int i = 0 ; i < numberOfParty ; i++) {
    if (i != myID) {
      outputs[i] = new rnsArithmetic<ringSize, 0> [size * vecLen];
      future[i] = pool->enqueue([](cryptoBackends* backend,
                                   rnsArithmetic<ringSize, 0>* dst,
                                   rnsArithmetic<ringSize, 0>* sendNumber,
                                   unsigned char* choice, int size, int ID,
                                   int myID)->int {
        size_t offset1 = ID > myID ? 0 : size / 2;
        size_t offset2 = ID < myID ? 0 : size / 2;

        int numberOfOT = size * primeWidth * ringSize / 2;

        rnsArithmetic<ringSize, 0>* tmpMask =
          new rnsArithmetic<ringSize, 0> [size * vecLen * primeWidth / 2];
        backend->generateRandomShares(tmpMask, size * vecLen
                                      * primeWidth / 2);

        for (int j = 0 ; j < size / 2 ; j++) {
          for (int l = 0 ; l < vecLen ; l++) {
            for (int k = 0 ; k < primeWidth ; k++) {
              backend->keySet->addRns(&dst[(j + offset1) * vecLen + l],
                                      &dst[(j + offset1) * vecLen + l],
                                      &tmpMask[(j * vecLen + l) * primeWidth + k], 0);
            }
          }
        }

        uint64_t* src = new uint64_t[numberOfOT * vecLen * 2];

        for (int j = 0 ; j < size / 2 * primeWidth ; j++) {
          for (int l = 0 ; l < vecLen ; l++) {
              for (int k = 0 ; k < ringSize ; k++) {
                arithmeticNum tmpNum = tmpMask[j].getValue(k);
                memcpy(&src[2 * (j * vecLen + l) * ringSize + k], &tmpNum,
                       sizeof(arithmeticNum));
              }
          }

          for (int l = 0 ; l < vecLen ; l++) {
            rnsArithmetic<ringSize, 0> tmpSum;
            backend->keySet->addRns(&tmpSum, &tmpMask[j * vecLen + l],
                                    &sendNumber[(j + offset1) * vecLen + l],
                                    1);
            for (int k = 0 ; k < ringSize ; k++) {
              arithmeticNum tmpNum = tmpSum.getValue(k);
              memcpy(&src[2 * (j * vecLen + l) * ringSize + ringSize + k],
                     &tmpNum, sizeof(arithmeticNum));
            }
          }
        }
        uint64_t* rcv = new uint64_t[numberOfOT * vecLen];

        backend->OT[ID].template biHeavyOT<vecLen>(src, rcv,
                            &choice[offset2 * primeWidth * ringSize],
                            numberOfOT);
        delete[] src;

        for (int j = 0 ; j < size / 2 * primeWidth ; j++) {
          for (int l = 0 ; l < vecLen ; l++) {
            for (int k = 0 ; k < ringSize ; k++) {
              arithmeticNum tmpNum;
              memcpy(&tmpNum, &rcv[(j * vecLen + l) * ringSize + k],
                     sizeof(arithmeticNum));
              tmpMask[j * vecLen + l].setValue(k, tmpNum);
            }
          }
        }
        delete[] rcv;
        for (int j = 0 ; j < size / 2; j++) {
          for (int l = 0 ; l < vecLen ; l++) {
            for (int k = 0 ; k < primeWidth ; k++) {
              backend->keySet->addRns(&dst[(j + offset2) * vecLen + l],
                                      &dst[(j + offset2) * vecLen + l],
                                      &tmpMask[(j * vecLen + l) * primeWidth + k],
                                      1);
            }
          }
        }
        delete[] tmpMask;
        
        return 1;
      }, backend, outputs[i], sendNumber, receiveChoice, size, i, myID);
    }
  }
  for (int i = 0 ; i < numberOfParty ; i++) {
    if (i != myID) {
      future[i].get();
      for (int j = 0 ; j < size * vecLen ; j++) {
        backend->keySet->addRns(&dst[j], &dst[j], &outputs[i][j], 1);
      }
      delete[] outputs[i];
     }
   }
   delete[] outputs;
   delete[] sendNumber;
  delete[] receiveChoice;

}

