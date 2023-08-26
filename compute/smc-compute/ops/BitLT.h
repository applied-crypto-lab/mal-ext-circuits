#ifndef BITCOMP_H_
#define BITCOMP_H_

#include "Mult.h"
#include "Operation.h"
#include "../MaliciousSMC.h"
#include "../Debug.h"

class BitLT : public Operation{
public:
  BitLT(NodeNetwork nodeNet, std::map<std::string, std::vector<int> > poly, int nodeID, SecretShare *s, mpz_t coeficients[], Mult *M);
  BitLT(NodeNetwork nodeNet, std::map<std::string, std::vector<int> > poly, int nodeID, SecretShare *s, mpz_t coeficients[], MaliciousSMC *malicious, Mult *M);

  virtual ~BitLT();
  void doOperation(mpz_t* A, mpz_t* B, mpz_t S, int size, int threadID);
  void recursiveOp(mpz_t* p, mpz_t* g,  int size, int threadID);

  void doOperation(mpz_t** A, mpz_t** B, mpz_t* S, int size, int batch_size, int threadID);
  void recursiveOp(mpz_t** p, mpz_t** g,  int size, int batch_size, int threadID);

  void doOperation_mal(mpz_t** A, mpz_t** B, mpz_t* S, int size, int threadID);
  void recursiveOp_mal(mpz_t** p, mpz_t** g,  int size, int threadID);

  void doOperation_mal(mpz_t*** A, mpz_t*** B, mpz_t** S, int size, int batch_size, int threadID);
  void recursiveOp_mal(mpz_t*** p, mpz_t*** g,  int size, int batch_size, int threadID);
private:
  Mult *Mul;
  MaliciousSMC *ms;
  //Debug *D;
};

#endif /* BITCOMP_H_ */
