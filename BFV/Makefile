All: test online

flag=-maes -march=corei7-avx -std=c++17 -lcrypto -pthread -lgmpxx -lgmp -O3

header=fhekey.h aes.h
impl=ot_impl.h network_impl.h committedexchange_impl.h secretkeysampling_impl.h errorsampling_impl.h  cryptobackends_impl.h tuples_impl.h fhekey_impl.h polynomialRing_impl.h arithmetic_impl.h


online: online.out

online.out: main.cpp $(header) $(impl)
	g++ main.cpp -D onlineonly -o online.out $(flag)


test: test.out

test.out: main.cpp $(header) $(impl)
	g++ main.cpp -o test.out $(flag)

clean: 
	rm -f *.out 
