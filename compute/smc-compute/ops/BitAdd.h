#ifndef BITADD_H_
#define BITADD_H_

#include "Mult.h"
#include "Operation.h"
#include "../MaliciousSMC.h"
#include "../Debug.h"

class BitAdd : public Operation{

public:
		BitAdd(NodeNetwork nodeNet, int NodeID, SecretShare *s, Mult *M);
        BitAdd(NodeNetwork nodeNet, std::map<std::string, std::vector<int> > poly, int nodeID, SecretShare *s, mpz_t coeficients[], Mult *M);
        BitAdd(NodeNetwork nodeNet, std::map<std::string, std::vector<int> > poly, int nodeID, SecretShare *s, mpz_t coeficients[], MaliciousSMC *malicious, Mult *M);

        virtual ~BitAdd();
		void doOperation(mpz_t **input_A, mpz_t **input_B, mpz_t **output, int size, int batch_size, int threadID);
		void doOperation(mpz_t **input_A, mpz_t **input_B, mpz_t **output, int *sizes, int batch_size, int threadID);

		void prefixCarry(mpz_t **p, mpz_t **g,  int *sizes, int batch_size, int threadID);

		void twosComplement(mpz_t **input_A, mpz_t **output, int sizes, int batch_size, int threadID);
		void twosComplement(mpz_t **input_A, mpz_t **output, int *sizes, int batch_size, int threadID);

		void doOperation_mal(mpz_t ***input_A, mpz_t ***input_B, mpz_t ***output, int size, int batch_size, int threadID);
		void doOperation_mal(mpz_t ***input_A, mpz_t ***input_B, mpz_t ***output, int *sizes, int batch_size, int threadID);

		void prefixCarry_mal(mpz_t ***p, mpz_t ***g,  int *sizes, int batch_size, int threadID);

		void twosComplement_mal(mpz_t ***input_A, mpz_t ***output, int size, int batch_size, int threadID);
		void twosComplement_mal(mpz_t ***input_A, mpz_t ***output, int *sizes, int batch_size, int threadID);

private:
        Mult *Mul;
		MaliciousSMC *ms;
};

#endif /* BITADD_H_ */
