All: test online BM

flag=-maes -march=corei7-avx -std=c++17 -lcrypto -pthread -O3

header=fhekey.h aes.h
impl=ot_impl.h network_impl.h secretkeysampling_impl.h errorsampling_impl.h  cryptobackends_impl.h tuples_impl.h fhekey_impl.h polynomialRing_impl.h arithmetic_impl.h


online: online.out

online.out: main.cpp $(header) $(impl)
	g++ main.cpp -D OnlineOnly -o online.out $(flag)

BM: BM.out

BM.out: main.cpp $(header) $(impl)
	g++ main.cpp -D BM -o BM.out $(flag)

test: test.out

test.out: main.cpp $(header) $(impl)
	g++ main.cpp -o test.out $(flag)

clean: 
	rm -f *.out 
