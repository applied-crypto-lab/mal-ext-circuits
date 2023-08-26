#ifndef BITEQ_H_
#define BITEQ_H_

#include "Mult.h"
#include "Operation.h"
#include "../MaliciousSMC.h"
#include "../Debug.h"

class BitEq : public Operation{
public:
        BitEq(NodeNetwork nodeNet, std::map<std::string, std::vector<int> > poly, int nodeID, SecretShare *s, mpz_t coeficients[], Mult *M);
        BitEq(NodeNetwork nodeNet, std::map<std::string, std::vector<int> > poly, int nodeID, SecretShare *s, mpz_t coeficients[], MaliciousSMC *malicious, Mult *M);
        virtual ~BitEq();
        void doOperation(mpz_t** A, mpz_t** B, mpz_t* S, int size, int batch_size, int threadID);
        void recursiveOp(mpz_t** p, int size, int batch_size, int threadID);
        void doOperation_mal(mpz_t*** A, mpz_t*** B, mpz_t** S, int size, int batch_size, int threadID);
        void recursiveOp_mal(mpz_t*** p, int size, int batch_size, int threadID);
private:
        Mult *Mul;
		Debug *D;
		MaliciousSMC *ms;
};

#endif /* BITEQ_H_ */
