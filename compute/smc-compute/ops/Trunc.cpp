/*
*  PICCO: A General Purpose Compiler for Private Distributed Computation
** Copyright (C) 2013 PICCO Team
** Department of Computer Science and Engineering, University of Notre Dame
*
*  PICCO is free software: you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation, either version 3 of the License, or
*  (at your option) any later version.
*
*  PICCO is distributed in the hope that it will be useful,
*  but WITHOUT ANY WARRANTY; without even the implied warranty of
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*  GNU General Public License for more details.
*
*  You should have received a copy of the GNU General Public License
*  along with PICCO. If not, see <http://www.gnu.org/licenses/>.
*/

/* NOTE This file has been modified from its original form for use in the applied-crypto-lab/biom-auth codebase */

#include "Trunc.h"

Trunc::Trunc(NodeNetwork nodeNet, std::map<std::string, std::vector<int> > poly, int nodeID, SecretShare *s, mpz_t coeficients[]){

  ss = s;
  Mod = new Mod2M(nodeNet,poly,nodeID,s,coeficients);
  net = nodeNet;
  polynomials = poly;
  id = nodeID;
  for (int i = 0; i < 9; i++){
    mpz_init(coef[i]);
    mpz_set(coef[i],coeficients[i]);
  }
  D = new Debug();
}

Trunc::Trunc(NodeNetwork nodeNet, std::map<std::string, std::vector<int> > poly, int nodeID, SecretShare *s, mpz_t coeficients[], MaliciousSMC *malicious){

  ss = s;
  Mod = new Mod2M(nodeNet,poly,nodeID,s,coeficients, malicious);
  net = nodeNet;
  polynomials = poly;
  ms = malicious;
  id = nodeID;
  for (int i = 0; i < 9; i++){
    mpz_init(coef[i]);
    mpz_set(coef[i],coeficients[i]);
  }

}

Trunc::~Trunc() {}

void Trunc::doOperation(mpz_t* result, mpz_t* shares1, int K, int M, int size, int threadID){

  #ifdef COMM_COUNTER
  D->push_CC(this_class);
  #endif

  mpz_t* shares = (mpz_t*)malloc(sizeof(mpz_t) * size);
  mpz_t const2, power, const2M, constInv2M;
  //initialization
  mpz_init(const2M);
  mpz_init(constInv2M);
  mpz_init_set_ui(const2, 2);
  mpz_init_set_ui(power, M);
  ss->modPow(const2M, const2, power);
  ss->modInv(constInv2M, const2M);

  //initialization
  for(int i = 0; i < size; i++)
    mpz_init_set(shares[i], shares1[i]);

  //start computation
  Mod->doOperation(result, shares, K, M, size, threadID);

  ss->modSub(result, shares, result, size);
  ss->modMul(result, result, constInv2M, size);

  //free memory
  for(int i = 0; i < size; i++)
    mpz_clear(shares[i]);
  free(shares);

  mpz_clear(const2);
  mpz_clear(power);
  mpz_clear(const2M);
  mpz_clear(constInv2M);
}


void Trunc::doOperation_mal(mpz_t** result, mpz_t** shares1, int K, int M, int size, int threadID){
  mpz_t** shares = (mpz_t**)malloc(sizeof(mpz_t*) * 2);

  mpz_t const2, power, const2M, constInv2M;
  //initialization
  mpz_init(const2M);
  mpz_init(constInv2M);
  mpz_init_set_ui(const2, 2);
  mpz_init_set_ui(power, M);
  ss->modPow(const2M, const2, power);
  ss->modInv(constInv2M, const2M);
  //initialization
  for(int i = 0; i < 2; i++){
    shares[i] = (mpz_t*)malloc(sizeof(mpz_t) * size);
    for(int j = 0; j < size; j++){
      mpz_init_set(shares[i][j], shares1[i][j]);
    }
  }
  //start computation
  Mod->doOperation_mal(result, shares, K, M, size, threadID);
  ss->modSub(result[0], shares[0], result[0], size);
  ss->modSub(result[1], shares[1], result[1], size);

  ss->modMul(result[0], result[0], constInv2M, size);
  ss->modMul(result[1], result[1], constInv2M, size);

  //free memory
  for(int i = 0; i < 2; i++){
    for(int j = 0; j < size; j++)
      mpz_clear(shares[i][j]);
    free(shares[i]);
  }
  free(shares);

  mpz_clear(const2);
  mpz_clear(power);
  mpz_clear(const2M);
  mpz_clear(constInv2M);
}
