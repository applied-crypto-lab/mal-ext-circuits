#ifndef BITSUM_H_
#define BITSUM_H_

#include "BitAdd.h"
#include "Operation.h"
#include "../MaliciousSMC.h"
#include "../Debug.h"

class BitSum : public Operation{

public:
        BitSum(NodeNetwork nodeNet, std::map<std::string, std::vector<int> > poly, int nodeID, SecretShare *s, mpz_t coeficients[], Mult *M);
        BitSum(NodeNetwork nodeNet, std::map<std::string, std::vector<int> > poly, int nodeID, SecretShare *s, mpz_t coeficients[], MaliciousSMC *malicious, Mult *M);

        virtual ~BitSum();
        void doOperation(mpz_t **input_A, mpz_t *output, int in_bit_len, int num_elements, int out_bit_len, int threadID);
        void doOperation(mpz_t **input_A, mpz_t *output, int *in_bit_lens, int num_elements, int out_bit_len, int threadID);
        void doOperation_mal(mpz_t ***input_A, mpz_t **output, int size, int num_elements, int out_bit_len, int threadID);
        void doOperation_mal(mpz_t ***input_A, mpz_t **output, int *in_bit_lens, int num_elements, int out_bit_len, int threadID);

private:
		Mult *Mul;
		BitAdd *BitA;
		Debug *D;
		MaliciousSMC *ms;
};

#endif /* BITSUM_H_ */
