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

#ifndef LTZ_H_
#define LTZ_H_

#include "Trunc.h"
#include "Operation.h"
#include "../MaliciousSMC.h"
#include "../Debug.h"

class LTZ: public Operation {

public:
  LTZ(NodeNetwork nodeNet, std::map<std::string, std::vector<int> > poly, int nodeID, SecretShare *s, mpz_t coeficients[]);
  LTZ(NodeNetwork nodeNet, std::map<std::string, std::vector<int> > poly, int nodeID, SecretShare *s, mpz_t coefficients[], MaliciousSMC *malicious);
  virtual ~LTZ();
  void doOperation(mpz_t* result, mpz_t* shares, int K, int size, int threadID);
  void doOperation_mal(mpz_t** result, mpz_t** shares, int K, int size, int threadID);
private:
  Trunc *T;
  MaliciousSMC *ms;
  Debug *D;
};

#endif /* LTZ_H_ */
