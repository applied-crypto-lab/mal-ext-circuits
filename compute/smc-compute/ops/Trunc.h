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

#ifndef TRUNC_H_
#define TRUNC_H_

#include "Mod2M.h"
#include "Operation.h"
#include "../MaliciousSMC.h"
#include "../Debug.h"

class Trunc: public Operation {
public:
  Trunc(NodeNetwork nodeNet, std::map<std::string, std::vector<int> > poly, int nodeID, SecretShare *s, mpz_t coeficients[]);
  Trunc(NodeNetwork nodeNet, std::map<std::string, std::vector<int> > poly, int nodeID, SecretShare *s, mpz_t coeficients[], MaliciousSMC *malicious);
  virtual ~Trunc();
  void doOperation(mpz_t* result, mpz_t* shares, int K, int M, int size, int threadID);
  void doOperation_mal(mpz_t** result, mpz_t** shares, int K, int M, int size, int threadID);

private:
  Mod2M *Mod;
  MaliciousSMC *ms;
  Debug *D;
};

#endif /* TRUNC_H_ */
