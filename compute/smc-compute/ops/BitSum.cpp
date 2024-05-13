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

#include "BitSum.h"


BitSum::BitSum(NodeNetwork nodeNet, std::map<std::string, std::vector<int>> poly, int NodeID, SecretShare *s, mpz_t coeficients[], Mult *M)
{
  Mul = M;
  BitA = new BitAdd(nodeNet, poly, NodeID, s, coeficients, Mul);
  net = nodeNet;
  id = NodeID;
  ss = s;
}

BitSum::BitSum(NodeNetwork nodeNet, std::map<std::string, std::vector<int>> poly, int NodeID, SecretShare *s, mpz_t coeficients[], MaliciousSMC *malicious, Mult *M)
{
  Mul = M;
  BitA = new BitAdd(nodeNet, poly, NodeID, s, coeficients, malicious, Mul);
  ms = malicious;
  net = nodeNet;
  id = NodeID;
  ss = s;

}

BitSum::~BitSum()
{
  delete BitA;
}


void BitSum::doOperation(mpz_t **input_A, mpz_t *output, int in_bit_len, int num_elements, int out_bit_len, int threadID)
{
  int *input_bit_lengths = (int *)malloc(sizeof(int) * num_elements);
  for (int i = 0; i < num_elements; i++)
    input_bit_lengths[i] = in_bit_len;

  doOperation(input_A, output, input_bit_lengths, num_elements, out_bit_len, threadID);

  free(input_bit_lengths);
}



void BitSum::doOperation(mpz_t **input_A, mpz_t *output, int *input_bit_lengths, int num_elements, int out_bit_len, int threadID)
{

  int sizes_sum = 0;

  for (int i = 0; i < num_elements; i++)
  {
    sizes_sum += input_bit_lengths[i];
  }

  mpz_t **sum_Buff1 = (mpz_t **)malloc(sizeof(mpz_t*) * num_elements);
  mpz_t **sum_Buff2 = (mpz_t **)malloc(sizeof(mpz_t*) * num_elements);
  mpz_t **sum_Buff3 = (mpz_t **)malloc(sizeof(mpz_t*) * num_elements);
  mpz_t **sum_Buff4 = (mpz_t **)malloc(sizeof(mpz_t*) * num_elements);

  for (int i = 0; i < num_elements; i++)
  {
    sum_Buff1[i] = (mpz_t *)malloc(sizeof(mpz_t) * out_bit_len);
    sum_Buff2[i] = (mpz_t *)malloc(sizeof(mpz_t) * out_bit_len);
    sum_Buff3[i] = (mpz_t *)malloc(sizeof(mpz_t) * out_bit_len);
    sum_Buff4[i] = (mpz_t *)malloc(sizeof(mpz_t) * out_bit_len);

    for (int j = 0; j < out_bit_len; j++)
    {
      mpz_init(sum_Buff1[i][j]);
      mpz_init(sum_Buff2[i][j]);
      mpz_init(sum_Buff3[i][j]);
      mpz_init(sum_Buff4[i][j]);
    }
  }

  for (int i = 0; i < num_elements; i++)
  {
    int this_size = std::min(input_bit_lengths[i], out_bit_len);
    for (int j = 0; j < this_size; j++)
    {
      mpz_set(sum_Buff3[i][j], input_A[i][j]);
    }
    for (int j = this_size; j < out_bit_len; j++)
    {
      mpz_set_ui(sum_Buff3[i][j], 0);
    }
  }

  int *add_sizes = (int*) malloc(num_elements * sizeof(int));
  for (int i = 0; i < num_elements; i++)
    add_sizes[i] = input_bit_lengths[i];

  int num_pairs = num_elements;
  int curr_elem = num_elements;
  int single_flag = 0;
  int single_idx = -1;

  while (num_pairs > 0)
  {
    if (num_pairs % 2)
    {	//singleton element exists
      if (!single_flag)
      {	//save for later on first occurrence
        single_idx = curr_elem - 1;
      }
      else
      {	//add both to add buffer on second
        for (int k = 0; k < add_sizes[curr_elem - 1]; k++)
        {
          mpz_set(sum_Buff3[curr_elem][k], sum_Buff3[single_idx][k]);
        }
        num_pairs++;
      }
      single_flag = 1 - single_flag;
    }

    num_pairs >>= 1;
    if (num_pairs == 0) break;

    for (int j = 0; j < num_pairs; j++)
    {
      add_sizes[j] = 1 + std::max(add_sizes[2*j], add_sizes[2*j + 1]);
      add_sizes[j] = std::min(add_sizes[j], out_bit_len);
    }

    curr_elem = 0;
    for (int j = 0; j < num_pairs; j++)
    {
      for (int k = 0; k < add_sizes[curr_elem]; k++)
      {
        mpz_set(sum_Buff1[curr_elem][k], sum_Buff3[2*curr_elem][k]);
        mpz_set(sum_Buff2[curr_elem][k], sum_Buff3[2*curr_elem + 1][k]);
      }
      curr_elem++;
    }

    BitA->doOperation(sum_Buff1, sum_Buff2, sum_Buff4, add_sizes, num_pairs, threadID);

    curr_elem = 0;
    for (int j = 0; j < num_pairs; j++)
    {
      for (int k = 0; k < add_sizes[curr_elem]; k++)
      {
        mpz_set(sum_Buff3[curr_elem][k], sum_Buff4[curr_elem][k]);
      }
      curr_elem++;
    }
  }

  for (int k = 0; k < out_bit_len; ++k)
  {
    mpz_set(output[k], sum_Buff3[0][k]);
  }

  // clear

  for (int i = 0; i < num_elements; i++)
  {
    for (int j = 0; j < out_bit_len; j++)
    {
      mpz_clear(sum_Buff1[i][j]);
      mpz_clear(sum_Buff2[i][j]);
      mpz_clear(sum_Buff3[i][j]);
      mpz_clear(sum_Buff4[i][j]);
    }
  }

  for (int i = 0; i < num_elements; i++)
  {
    free(sum_Buff1[i]);
    free(sum_Buff2[i]);
    free(sum_Buff3[i]);
    free(sum_Buff4[i]);
  }

  free(sum_Buff1);
  free(sum_Buff2);
  free(sum_Buff3);
  free(sum_Buff4);

  free(add_sizes);
}




void BitSum::doOperation_mal(mpz_t ***input_A, mpz_t **output, int in_bit_len, int num_elements, int out_bit_len, int threadID)
{
  int *input_bit_lengths = (int *)malloc(sizeof(int) * num_elements);
  for (int i = 0; i < num_elements; i++)
    input_bit_lengths[i] = in_bit_len;

  doOperation_mal(input_A, output, input_bit_lengths, num_elements, out_bit_len, threadID);

  free(input_bit_lengths);
}

void BitSum::doOperation_mal(mpz_t ***input_A, mpz_t **output, int *input_bit_lengths, int num_elements, int out_bit_len, int threadID)
{
  int sizes_sum = 0;

  for(int i = 0; i < num_elements; i++)
  {
    sizes_sum += input_bit_lengths[i];
  }

  out_bit_len = std::max(out_bit_len, 1);

  mpz_t ***sum_Buff1 = (mpz_t ***)malloc(sizeof(mpz_t**) * 2);
  mpz_t ***sum_Buff2 = (mpz_t ***)malloc(sizeof(mpz_t**) * 2);
  mpz_t ***sum_Buff3 = (mpz_t ***)malloc(sizeof(mpz_t**) * 2);
  mpz_t ***sum_Buff4 = (mpz_t ***)malloc(sizeof(mpz_t**) * 2);

  for (int mi = 0; mi < 2; mi++)
  {
    sum_Buff1[mi] = (mpz_t **)malloc(sizeof(mpz_t*) * num_elements);
    sum_Buff2[mi] = (mpz_t **)malloc(sizeof(mpz_t*) * num_elements);
    sum_Buff3[mi] = (mpz_t **)malloc(sizeof(mpz_t*) * num_elements);
    sum_Buff4[mi] = (mpz_t **)malloc(sizeof(mpz_t*) * num_elements);

    for (int i = 0; i < num_elements; i++)
    {
      sum_Buff1[mi][i] = (mpz_t *)malloc(sizeof(mpz_t) * out_bit_len);
      sum_Buff2[mi][i] = (mpz_t *)malloc(sizeof(mpz_t) * out_bit_len);
      sum_Buff3[mi][i] = (mpz_t *)malloc(sizeof(mpz_t) * out_bit_len);
      sum_Buff4[mi][i] = (mpz_t *)malloc(sizeof(mpz_t) * out_bit_len);

      for (int j = 0; j < out_bit_len; j++)
      {
        mpz_init(sum_Buff1[mi][i][j]);
        mpz_init(sum_Buff2[mi][i][j]);
        mpz_init(sum_Buff3[mi][i][j]);
        mpz_init(sum_Buff4[mi][i][j]);
      }
    }
  }

  for (int i = 0; i < num_elements; i++)
  {
    int this_size = std::min(input_bit_lengths[i], out_bit_len);
    for (int j = 0; j < this_size; j++)
    {
      mpz_set(sum_Buff3[0][i][j], input_A[0][i][j]);

      mpz_set(sum_Buff3[1][i][j], input_A[1][i][j]);
    }
    for (int j = this_size; j < out_bit_len; j++)
    {
      mpz_set_ui(sum_Buff3[0][i][j], 0);

      mpz_set_ui(sum_Buff3[1][i][j], 0);
    }
  }

  int *add_sizes = (int*) malloc(num_elements * sizeof(int));
  for (int i = 0; i < num_elements; i++)
    add_sizes[i] = input_bit_lengths[i];

  int num_pairs = num_elements;
  int curr_elem = num_pairs;
  int single_flag = 0;
  int single_idx = -1;

  while (num_pairs > 0)
  {
    //printf("NP = %i\n", num_pairs);

    if (num_pairs % 2)
    {	//singleton element exists
      if (!single_flag)
      {	//save for later on first nontrivial occurrence
        single_idx = curr_elem - 1;
      }
      else
      {	//add both to add buffer on second
        for (int k = 0; k < add_sizes[curr_elem - 1]; k++)
        {
          mpz_set(sum_Buff3[0][curr_elem][k], sum_Buff3[0][single_idx][k]);

          mpz_set(sum_Buff3[1][curr_elem][k], sum_Buff3[1][single_idx][k]);
        }
        num_pairs++;
      }
      single_flag = 1 - single_flag;
    }

    num_pairs >>= 1;
    if (num_pairs == 0) break;

    for (int j = 0; j < num_pairs; j++)
    {
      add_sizes[j] = 1 + std::max(add_sizes[2*j], add_sizes[2*j + 1]);
      add_sizes[j] = std::min(add_sizes[j], out_bit_len);
    }

    curr_elem = 0;
    for (int j = 0; j < num_pairs; j++)
    {
      for (int k = 0; k < add_sizes[curr_elem]; k++)
      {
        mpz_set(sum_Buff1[0][curr_elem][k], sum_Buff3[0][2*curr_elem][k]);
        mpz_set(sum_Buff2[0][curr_elem][k], sum_Buff3[0][2*curr_elem + 1][k]);

        mpz_set(sum_Buff1[1][curr_elem][k], sum_Buff3[1][2*curr_elem][k]);
        mpz_set(sum_Buff2[1][curr_elem][k], sum_Buff3[1][2*curr_elem + 1][k]);
      }
      curr_elem++;
    }

    BitA->doOperation_mal(sum_Buff1, sum_Buff2, sum_Buff4, add_sizes, num_pairs, threadID);

    curr_elem = 0;
    for (int j = 0; j < num_pairs; j++)
    {
      for (int k = 0; k < add_sizes[curr_elem]; k++)
      {
        mpz_set(sum_Buff3[0][curr_elem][k], sum_Buff4[0][curr_elem][k]);

        mpz_set(sum_Buff3[1][curr_elem][k], sum_Buff4[1][curr_elem][k]);
      }
      curr_elem++;
    }
  }

  for (int k = 0; k < out_bit_len; ++k)
  {
    mpz_set(output[0][k], sum_Buff3[0][0][k]);

    mpz_set(output[1][k], sum_Buff3[1][0][k]);
  }

  // clear

  for (int mi = 0; mi < 2; mi++)
  {
    for (int i = 0; i < num_elements; i++)
    {
      for (int j = 0; j < out_bit_len; j++)
      {
        mpz_clear(sum_Buff1[mi][i][j]);
        mpz_clear(sum_Buff2[mi][i][j]);
        mpz_clear(sum_Buff3[mi][i][j]);
        mpz_clear(sum_Buff4[mi][i][j]);
      }

      free(sum_Buff1[mi][i]);
      free(sum_Buff2[mi][i]);
      free(sum_Buff3[mi][i]);
      free(sum_Buff4[mi][i]);
    }

    free(sum_Buff1[mi]);
    free(sum_Buff2[mi]);
    free(sum_Buff3[mi]);
    free(sum_Buff4[mi]);
  }

  free(sum_Buff1);
  free(sum_Buff2);
  free(sum_Buff3);
  free(sum_Buff4);

  free(add_sizes);
}




