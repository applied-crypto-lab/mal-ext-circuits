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

#ifndef MOD2M_H_
#define MOD2M_H_

#include "BitLTC.h"
#include "Random.h"
#include "Operation.h"
#include "../MaliciousSMC.h"

class Mod2M: public Operation {
public:
  Mod2M(NodeNetwork nodeNet, std::map<std::string, std::vector<int> > poly, int nodeID, SecretShare *s, mpz_t coeficients[]);
  Mod2M(NodeNetwork nodeNet, std::map<std::string, std::vector<int> > poly, int nodeID, SecretShare *s, mpz_t coeficients[], MaliciousSMC *malicious);
  virtual ~Mod2M();
  void doOperation(mpz_t* result, mpz_t* shares, int K, int M, int size, int threadID);
  void doOperation_mal(mpz_t** result, mpz_t** shares, int K, int M, int size, int threadID);
private:
  BitLTC *B;
  Random *Rand;
  Mult *Mul;
  MaliciousSMC *ms;
};

#endif /* MOD2M_H_ */
