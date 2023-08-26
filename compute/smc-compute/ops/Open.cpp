/*
 *   PICCO: A General Purpose Compiler for Private Distributed Computation
 ** Copyright (C) from 2013 PICCO Team
 ** Department of Computer Science and Engineering, University of Notre Dame
 ** Department of Computer Science and Engineering, University of Buffalo (SUNY)
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

#include "Open.h"



int Open_semih_3(mpz_t var, int threadID, NodeNetwork net, int id, SecretShare *ss)
{
  mpz_t results;
  mpz_init(results);

  int peers = ss->getPeers();

  mpz_t shares[4];
  for (int i = 0; i < 4; i++)
    mpz_init(shares[i]);

  mpz_set(shares[id], var);

  int id_p1 = (peers + id + 1) % peers;
  int id_m1 = (peers + id - 1) % peers;
  if (id_p1 == 0) id_p1 = peers;
  if (id_m1 == 0) id_m1 = peers;

  net.sendDataToPeer(id_m1, 1, &shares[id - 1]);
  net.getDataFromPeer(id_p1, 1, &shares[id_p1 - 1]);

  int threshold = (peers - 1) / 2;
  ss->reconstructSecret_T(results, shares, threshold);

  for (int i = 0; i < 4; i++)
    mpz_clear(shares[i]);

  int result = mpz_get_si(results);

  mpz_clear(results);
  return result;
}




int Open_semih(mpz_t var, int threadID, NodeNetwork net, int id, SecretShare *ss)
{
  mpz_t results;
  mpz_init(results);

  int peers = ss->getPeers();

  mpz_t shares[peers + 1];
  for (int i = 0; i < peers + 1; i++)
    mpz_init(shares[i]);

  mpz_set(shares[id], var);

  int id_p1 = (peers + id + 1) % peers;
  int id_m1 = (peers + id - 1) % peers;
  if (id_p1 == 0) id_p1 = peers;
  if (id_m1 == 0) id_m1 = peers;

  int threshold = (peers - 1) / 2;
  net.broadcastToPeers_T(shares[id], (mpz_t*) shares, threshold, threadID);
  ss->reconstructSecret_T(results, shares, threshold);

  for (int i = 0; i < 4; i++)
    mpz_clear(shares[i]);

  int result = mpz_get_si(results);

  mpz_clear(results);
  return result;
}



int Open_mal(mpz_t var, int threadID, NodeNetwork net, int id, SecretShare *ss)
{
  int peers = ss->getPeers();

  mpz_t *data = (mpz_t *)malloc(sizeof(mpz_t) * 1);
  mpz_t *results = (mpz_t *)malloc(sizeof(mpz_t) * 1);
  mpz_t **buffer = (mpz_t **)malloc(sizeof(mpz_t *) * peers);
  for (int i = 0; i < peers; ++i)
  {
    buffer[i] = (mpz_t *)malloc(sizeof(mpz_t));
    mpz_init(buffer[i][0]);
  }
  mpz_init(data[0]);
  mpz_init(results[0]);
  mpz_set(data[0], var);

  net.broadcastToPeers(data, 1, buffer, threadID);
  ss->reconstructSecret(results, buffer, 1, false);

  mpz_t tmp, field;
  mpz_init(tmp);
  mpz_init(field);
  ss->getFieldSize(field);
  mpz_mul_ui(tmp, results[0], 2);
  if (mpz_cmp(tmp, field) > 0)
  {
    mpz_sub(results[0], results[0], field);
  }
  int result = mpz_get_si(results[0]);

  mpz_clear(data[0]);
  mpz_clear(results[0]);
  free(data);
  free(results);
  for (int i = 0; i < peers; i++)
  {
    mpz_clear(buffer[i][0]);
    free(buffer[i]);
  }
  free(buffer);

  return result;
}



void reveal(mpz_t *var, int size, int threadID, NodeNetwork net, int id, SecretShare *ss)
{
  int i = 0;
  int res = 0;
  for (i = 0; i < size; ++i)
  {
    res = Open_mal(var[i], threadID, net, id, ss);
    printf(" %d ", res);
  }
  printf("\n");
}



