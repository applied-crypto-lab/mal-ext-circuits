#ifndef BITMUL_H_
#define BITMUL_H_

#include "Mult.h"
#include "BitAdd.h"
#include "Operation.h"
#include "../MaliciousSMC.h"
#include "../Debug.h"

class BitMul : public Operation{
public:
  BitMul(NodeNetwork nodeNet, std::map<std::string, std::vector<int> > poly, int nodeID, SecretShare *s, mpz_t coeficients[], Mult *M);
  BitMul(NodeNetwork nodeNet, std::map<std::string, std::vector<int> > poly, int nodeID, SecretShare *s, mpz_t coeficients[], MaliciousSMC *malicious, Mult *M);

  virtual ~BitMul();
  void doOperation(mpz_t **input_A, mpz_t **input_B, mpz_t **output, int in_bit_len, int batch_size, int threadID);
  void doOperation(mpz_t **input_A, mpz_t **input_B, mpz_t **output, int in_bit_len, int batch_size, int out_bit_len, int threadID);

  void doOperation_mal(mpz_t ***input_A, mpz_t ***input_B, mpz_t ***output, int in_bit_len, int batch_size, int threadID);
  void doOperation_mal(mpz_t ***input_A, mpz_t ***input_B, mpz_t ***output, int in_bit_len, int batch_size, int out_bit_len, int threadID);

private:
  BitAdd *BitA;
  Mult *Mul;
  MaliciousSMC *ms;
  //Debug *D;
};

#endif /* BITMUL_H_ */
