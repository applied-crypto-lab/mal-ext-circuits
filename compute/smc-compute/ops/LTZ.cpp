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

#include "LTZ.h"

LTZ::LTZ(NodeNetwork nodeNet, std::map<std::string, std::vector<int> > poly, int nodeID, SecretShare *s, mpz_t coefficients[]){
  ss = s;
  T = new Trunc(nodeNet,poly,nodeID,s,coefficients);
  net = nodeNet;
  polynomials = poly;
  id = nodeID;
  for (int i = 0; i < 9; i++){
    mpz_init(coef[i]);
    mpz_set(coef[i],coefficients[i]);
  }
  D = new Debug();
}

LTZ::LTZ(NodeNetwork nodeNet, std::map<std::string, std::vector<int> > poly, int nodeID, SecretShare *s, mpz_t coefficients[], MaliciousSMC *malicious){
  ss = s;
  T = new Trunc(nodeNet,poly,nodeID,s,coefficients, malicious);
  net = nodeNet;
  ms = malicious;
  polynomials = poly;
  id = nodeID;
  for (int i = 0; i < 9; i++){
    mpz_init(coef[i]);
    mpz_set(coef[i],coefficients[i]);
  }
}

LTZ::~LTZ() {}

void LTZ::doOperation(mpz_t* result, mpz_t* shares, int K, int size, int threadID)
{
  mpz_t const0;
  mpz_init_set_ui(const0, 0);
  T->doOperation(result, shares, K, K-1, size, threadID);
  ss->modSub(result, const0, result, size);
  mpz_clear(const0);
}

void LTZ::doOperation_mal(mpz_t** result, mpz_t** shares, int K, int size, int threadID)
{
  mpz_t const0;
  mpz_init_set_ui(const0, 0);
  T->doOperation_mal(result, shares, K, K-1, size, threadID);
  ss->modSub(result[0], const0, result[0], size);
  ss->modSub(result[1], const0, result[1], size);
  mpz_clear(const0);
}




