
#ifndef TRUNC_H_
#define TRUNC_H_

#include "Mod2M.h"
#include "Operation.h"
#include "../MaliciousSMC.h"
#include "../Debug.h"

class Trunc: public Operation {
public:
	Trunc(NodeNetwork nodeNet, std::map<std::string, std::vector<int> > poly, int nodeID, SecretShare *s, mpz_t coeficients[]);
	Trunc(NodeNetwork nodeNet, std::map<std::string, std::vector<int> > poly, int nodeID, SecretShare *s, mpz_t coeficients[], MaliciousSMC *malicious);
	virtual ~Trunc();
	void doOperation(mpz_t* result, mpz_t* shares, int K, int M, int size, int threadID);
	void doOperation_mal(mpz_t** result, mpz_t** shares, int K, int M, int size, int threadID);

private:
	Mod2M *Mod;
	MaliciousSMC *ms;
	Debug *D;
};

#endif /* TRUNC_H_ */
