/*
   PICCO: A General Purpose Compiler for Private Distributed Computation
   ** Copyright (C) from 2013 PICCO Team
   ** Department of Computer Science and Engineering, University of Notre Dame
   ** Department of Computer Science and Engineering, University of Buffalo (SUNY)

   PICCO is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   PICCO is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with PICCO. If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef OPEN_H_
#define OPEN_H_

#include "Operation.h"

int Open_semih_3(mpz_t var, int threadID, NodeNetwork net, int id, SecretShare *ss);
int Open_semih(mpz_t var, int threadID, NodeNetwork net, int id, SecretShare *ss);
int Open_mal(mpz_t var, int threadID, NodeNetwork net, int id, SecretShare *ss);
void reveal(mpz_t *var, int size, int threadID, NodeNetwork net, int id, SecretShare *ss);


#endif	/*OPEN_H_*/
