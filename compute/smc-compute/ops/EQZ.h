/*
 *   PICCO: A General Purpose Compiler for Private Distributed Computation
 ** Copyright (C) 2013 PICCO Team
 ** Department of Computer Science and Engineering, University of Notre Dame
 *
 *   PICCO is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   PICCO is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with PICCO. If not, see <http://www.gnu.org/licenses/>.
 */

/* NOTE This file has been modified from its original form for use in the applied-crypto-lab/biom-auth codebase */

#ifndef EQZ_H_
#define EQZ_H_

#include "Random.h"
#include "PrefixMultiplication.h"
#include "Operation.h"
#include "../MaliciousSMC.h"

class EQZ : public Operation{
public:
  EQZ(NodeNetwork nodeNet, std::map<std::string, std::vector<int> > poly, int nodeID, SecretShare *s, mpz_t coeficients[],  MaliciousSMC *malicious);
  EQZ(NodeNetwork nodeNet, std::map<std::string, std::vector<int> > poly, int nodeID, SecretShare *s, mpz_t coeficients[]);
  virtual ~EQZ();

  void doOperation(mpz_t* shares, mpz_t* result, int K, int size, int threaID);
  void doOperation_mal(mpz_t** shares, mpz_t** result, int K, int size, int threadID);
private:
  PrefixMultiplication *PreMul;
  Random  *Rand;
  Mult *Mul;
  MaliciousSMC *ms;
};


#endif /* EQZ_H_ */
