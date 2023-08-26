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
#include "DotProduct.h"
#include "Open.h"

DotProduct::DotProduct(NodeNetwork nodeNet, std::map<std::string, std::vector<int> > poly, int NodeID, SecretShare *s, mpz_t coeficients[])
{
  net = nodeNet;
  id =  NodeID;
  ss = s;
}

DotProduct::DotProduct(NodeNetwork nodeNet, std::map<std::string, std::vector<int> > poly, int NodeID, SecretShare *s, mpz_t coeficients[], MaliciousSMC *malicious)
{
  net = nodeNet;
  id =  NodeID;
  ss = s;
  ms = malicious;
  D = new Debug();
}

DotProduct::~DotProduct(){}

void DotProduct::doOperation(mpz_t* a, mpz_t* b, mpz_t result, int array_size, int threadID){

  //printf("Begin %s\n", __PRETTY_FUNCTION__);

  int peers = ss->getPeers();
  mpz_t** shares = (mpz_t**) malloc(sizeof(mpz_t*) * peers);
  mpz_t** buffer = (mpz_t**) malloc(sizeof(mpz_t*) * peers);
  mpz_t* data = (mpz_t*) malloc(sizeof(mpz_t));
  mpz_t tmp;

  //initialization
  for(int i = 0; i < peers; i++){
    shares[i] = (mpz_t*) malloc(sizeof(mpz_t) * 1);
    buffer[i] = (mpz_t*) malloc(sizeof(mpz_t) * 1);
    for(int j = 0; j < 1; j++){
      mpz_init(shares[i][j]);
      mpz_init(buffer[i][j]);
    }
  }
  mpz_init(tmp);
  mpz_init_set_ui(data[0], 0);

  //do computation
  for(int i = 0; i < array_size; i++){
    mpz_mul(tmp, a[i], b[i]);
    mpz_add(data[0], data[0], tmp);
  }

  ss->getShares(shares, data, 1);
  net.multicastToPeers(shares, buffer, 1, threadID);
  ss->reconstructSecret(data, buffer, 1, true);
  mpz_set(result, data[0]);

  //free the memory
  for(int i = 0; i < peers; i++){
    for(int j = 0; j < 1; j++){
      mpz_clear(shares[i][j]);
      mpz_clear(buffer[i][j]);
    }
    free(shares[i]);
    free(buffer[i]);
  }

  free(shares);
  free(buffer);
  mpz_clear(tmp);
  mpz_clear(data[0]);
  free(data);

  //printf("End %s\n", __PRETTY_FUNCTION__);
}

void DotProduct::doOperation(mpz_t** a, mpz_t** b, mpz_t* result, int batch_size, int array_size, int threadID){
  int peers = ss->getPeers();
  mpz_t** shares = (mpz_t**) malloc(sizeof(mpz_t*) * peers);
  mpz_t** buffer = (mpz_t**) malloc(sizeof(mpz_t*) * peers);
  mpz_t tmp;

  for(int i = 0; i < peers; i++){
    shares[i] = (mpz_t*) malloc(sizeof(mpz_t) * batch_size);
    buffer[i] = (mpz_t*) malloc(sizeof(mpz_t) * batch_size);
    for(int j = 0; j < batch_size; j++){
      mpz_init(shares[i][j]);
      mpz_init(buffer[i][j]);
    }
  }
  mpz_init(tmp);

  for(int i = 0; i < batch_size; i++){
    mpz_set_ui(result[i], 0);
    for(int j = 0; j < array_size; j++){
      mpz_mul(tmp, a[i][j], b[i][j]);
      mpz_add(result[i], result[i], tmp);
    }
  }

  ss->getShares(shares, result, batch_size);
  net.multicastToPeers(shares, buffer, batch_size, threadID);
  ss->reconstructSecret(result, buffer, batch_size, true);

  //free the memory
  for(int i = 0; i < peers; i++){
    for(int j = 0; j < batch_size; j++){
      mpz_clear(shares[i][j]);
      mpz_clear(buffer[i][j]);
    }
    free(shares[i]);
    free(buffer[i]);
  }
  free(shares);
  free(buffer);
  mpz_clear(tmp);
}


void DotProduct::doOperation_mal(mpz_t** a, mpz_t** b, mpz_t* result, int array_size, int threadID)
{
  //printf("Begin %s\n", __PRETTY_FUNCTION__);

  int peers = ss->getPeers();
  mpz_t **shares = (mpz_t **) malloc(sizeof(mpz_t *) * peers);
  mpz_t **buffer = (mpz_t **) malloc(sizeof(mpz_t *) * peers);
  mpz_t *data = (mpz_t *) malloc(sizeof(mpz_t) * 2);
  mpz_t *tmp = (mpz_t *) malloc(sizeof(mpz_t) * 2);

  //initialization

  for(int i = 0; i < peers; i++){
    shares[i] = (mpz_t*) malloc(sizeof(mpz_t) * 2);
    buffer[i] = (mpz_t*) malloc(sizeof(mpz_t) * 2);

    mpz_init(shares[i][0]);
    mpz_init(buffer[i][0]);
    mpz_init(shares[i][1]);
    mpz_init(buffer[i][1]);
  }

  mpz_init(tmp[0]);
  mpz_init(tmp[1]);
  mpz_init_set_ui(data[0], 0);
  mpz_init_set_ui(data[1], 0);

  //do computation
  for(int i = 0; i < array_size; i++){
    mpz_mul(tmp[0], a[0][i], b[0][i]);
    mpz_mul(tmp[1], a[0][i], b[1][i]);
    mpz_add(data[0], data[0], tmp[0]);
    mpz_add(data[1], data[1], tmp[1]);
  }

  ms->pushBuffer(&data[0], &data[1], 1);

  ss->getShares(shares, data, 2);
  net.multicastToPeers(shares, buffer, 2, threadID);
  ss->reconstructSecret(data, buffer, 2, true);

  mpz_set(result[0], data[0]);
  mpz_set(result[1], data[1]);

  //free the memory
  for(int i = 0; i < peers; i++)
  {
    mpz_clear(shares[i][0]);
    mpz_clear(buffer[i][0]);
    mpz_clear(shares[i][1]);
    mpz_clear(buffer[i][1]);

    free(shares[i]);
    free(buffer[i]);
  }
  free(shares);
  free(buffer);

  mpz_clear(tmp[0]);
  mpz_clear(tmp[1]);
  mpz_clear(data[0]);
  mpz_clear(data[1]);

  free(data);
  free(tmp);

  //printf("End %s\n", __PRETTY_FUNCTION__);
}





