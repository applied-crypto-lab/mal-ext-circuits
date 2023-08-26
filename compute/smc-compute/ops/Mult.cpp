/*
   PICCO: A General Purpose Compiler for Private Distributed Computation
   ** Copyright (C) 2013 PICCO Team
   ** Department of Computer Science and Engineering, University of Notre Dame

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
#include "Mult.h"

Mult::Mult(NodeNetwork nodeNet, int nodeID, SecretShare *s) {
	net = nodeNet;
	id = nodeID;
	ss = s;
	mult_counter = 0;
}

Mult::~Mult() {}


void Mult::reset_mult_counter()
{
	mult_counter = 0;
}


void Mult::getSummary(std::string test_description, bool writing_to_file)
{
	printf("Mult Counter: %ld \n", mult_counter);

	if (writing_to_file)
	{
		std::ofstream results_file;
		results_file.open("mult_test_results_" + std::to_string(id) + ".csv", std::ios::app);

		results_file << "\n" << test_description << "," << "," << mult_counter << "\n";
		results_file.close();
	}
}


void Mult::doOperation(mpz_t* C, mpz_t* A, mpz_t* B, int size, int threadID){
	int peers = ss->getPeers();
	int id_p1;
	int id_m1;
	mpz_t *rand_id= (mpz_t*)malloc(sizeof(mpz_t) * size);
	mpz_t* temp = (mpz_t*)malloc(sizeof(mpz_t) * size);
	mpz_t** data = (mpz_t**)malloc(sizeof(mpz_t*) * peers);
	mpz_t** buffer = (mpz_t**)malloc(sizeof(mpz_t*) * peers);

	for(int i = 0; i < peers; i++){
		data[i] = (mpz_t*)malloc(sizeof(mpz_t) * size);
		buffer[i] = (mpz_t*)malloc(sizeof(mpz_t) * size);
	}
	//initialziation
	for(int i = 0; i < peers; i++){
		for(int j = 0; j < size; j++){
			mpz_init(data[i][j]);
			mpz_init(buffer[i][j]);
		}
	}

	for(int i = 0; i < size; i++){
		mpz_init(temp[i]);
		mpz_init(rand_id[i]);
	}
	//start computation
	ss->modMul(temp, A, B, size);

	id_p1 = (id + 1 + peers) % peers;
	if (id_p1 == 0) id_p1 = peers;

	id_m1 = (id - 1 + peers) % peers;
	if (id_m1 == 0) id_m1 = peers;

	ss->getShares2(temp, rand_id, data, size);
	net.multicastToPeers_Mul(data, size, threadID);

	for(int i=0;i<size;i++)
	{
		mpz_set(data[id_m1-1][i],temp[i]);
	}

	ss->reconstructSecret(C, data, size, true);

	for(int i = 0; i < peers; i++){
		for(int j = 0; j < size; j++){
			mpz_clear(data[i][j]);
			mpz_clear(buffer[i][j]);
		}
		free(data[i]);
		free(buffer[i]);
	}
	free(data);
	free(buffer);
	for(int i = 0; i < size; i++){
		mpz_clear(temp[i]);
		mpz_clear(rand_id[i]);
	}
	free(temp);
	free(rand_id);

	mult_counter += size;
}

