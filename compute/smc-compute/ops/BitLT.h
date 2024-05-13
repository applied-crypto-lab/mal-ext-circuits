/*
	Efficiently Compiling Secure Computation Protocols From Passive to
	Active Security: Beyond Arithmetic Circuits
	Copyright (C) 2024  Marina Blanton and Dennis Murphy,
	University at Buffalo, State University of New York.

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

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
