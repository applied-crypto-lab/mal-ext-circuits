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

#ifndef MALICIOUSSMC_H_
#define MALICIOUSSMC_H_

#include "stdint.h"
#include <vector>
#include <math.h>
#include <iostream>
#include <cstdlib>
#include <gmp.h>
#include "NodeNetwork.h"
#include "SecretShare.h"
#include "ops/Mult.h"
#include "ops/Random.h"
#include "ops/Open.h"
#include "Debug.h"

class MaliciousSMC
{
public:

  MaliciousSMC(NodeConfiguration *nodeConfig, NodeNetwork nodeNet, SecretShare* s, int p, int t, Random *Rand, Mult *M);
  MaliciousSMC();
  virtual ~MaliciousSMC();

  // malicious functions
  void init_mal();
  void clean_mal();
  void verify();
  void pushBuffer(mpz_t *result, mpz_t *resultR, int size);
  bool checkBuffer(int size);
  void check_ver(mpz_t **buf, int buf_size);

  int getcurRow();
  void malBufferReset();
  void computeLagrangeWeight_mal();
  void computeLagrangeWeight_2();
  void reconstructSecretCheck(mpz_t *result, mpz_t **y, int size, bool isMultiply);

  mpz_t r;
  mpz_t **buffer_mal;
  int curPoint_mal; // the last avaiavle element in a row
  int curRow_mal;   // current last used row
  int curCap_mal;   // row intitalized
  int maxCapacity_mal; // total capacity limitation
  int maxRow_mal;   // max number of rows
  int rowCap_mal;   // size of each row
  int curCapacity_mal;
  unsigned long VerificationTimer;

  mpz_t** lagrangeWeight_mal;

  NodeNetwork net;
  SecretShare *ss;
  Random *rand;

  int peers;
  int threshhold;
  int id;

  int error_count = 0;
  int verify_count = 0;

private:

  NodeConfiguration *config;
  mpz_t *rand_seed;
  gmp_randstate_t verifyRandomState;
  int rand_state_initialized = 0;
  mpz_t *lagrangeWeight2;

  Mult *Mul;
  Debug *D;


};

#endif /* MALICIOUSSMC_H_ */



