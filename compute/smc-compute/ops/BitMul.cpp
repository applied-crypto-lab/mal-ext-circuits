
#include "BitMul.h"

BitMul::BitMul(NodeNetwork nodeNet, std::map<std::string, std::vector<int>> poly, int NodeID, SecretShare *s, mpz_t coeficients[], Mult *M)
{
	Mul = M;
	BitA = new BitAdd(nodeNet, poly, NodeID, s, coeficients, Mul);
	net = nodeNet;
	id = NodeID;
	ss = s;
}

BitMul::BitMul(NodeNetwork nodeNet, std::map<std::string, std::vector<int>> poly, int NodeID, SecretShare *s, mpz_t coeficients[], MaliciousSMC *malicious, Mult *M)
{
	Mul = M;
	BitA = new BitAdd(nodeNet, poly, NodeID, s, coeficients, malicious, Mul);
	ms = malicious;
	net = nodeNet;
	id = NodeID;
	ss = s;
}

BitMul::~BitMul()
{
	delete BitA;
}



void BitMul::doOperation(mpz_t **input_A, mpz_t **input_B, mpz_t **output, int in_bit_len, int batch_size, int threadID)
{
  doOperation(input_A, input_B, output, in_bit_len, batch_size, 2 * in_bit_len, threadID);
}


void BitMul::doOperation(mpz_t **input_A, mpz_t **input_B, mpz_t **output, int in_bit_len, int batch_size, int out_bit_len, int threadID)
{
	//show(input_A[0], in_bit_len, net, id, ss);
	//show(input_B[0], in_bit_len, net, id, ss);

	mpz_t *and_Buff1 = (mpz_t *)malloc(sizeof(mpz_t) * in_bit_len * in_bit_len * batch_size);
	mpz_t *and_Buff2 = (mpz_t *)malloc(sizeof(mpz_t) * in_bit_len * in_bit_len * batch_size);
	mpz_t *and_Buff3 = (mpz_t *)malloc(sizeof(mpz_t) * in_bit_len * in_bit_len * batch_size);

	for (int i = 0; i < batch_size * in_bit_len * in_bit_len; i++)
	{
		mpz_init(and_Buff1[i]);
		mpz_init(and_Buff2[i]);
		mpz_init(and_Buff3[i]);
	}

	mpz_t **sum_Buff1 = (mpz_t **)malloc(sizeof(mpz_t*) * in_bit_len * batch_size);
	mpz_t **sum_Buff2 = (mpz_t **)malloc(sizeof(mpz_t*) * in_bit_len * batch_size);
	mpz_t **sum_Buff3 = (mpz_t **)malloc(sizeof(mpz_t*) * in_bit_len * batch_size);
	mpz_t **sum_Buff4 = (mpz_t **)malloc(sizeof(mpz_t*) * in_bit_len * batch_size);

	for (int i = 0; i < batch_size * in_bit_len; i++)
	{
		sum_Buff1[i] = (mpz_t *)malloc(sizeof(mpz_t) * (1 + out_bit_len));
		sum_Buff2[i] = (mpz_t *)malloc(sizeof(mpz_t) * (1 + out_bit_len));
		sum_Buff3[i] = (mpz_t *)malloc(sizeof(mpz_t) * (1 + out_bit_len));
		sum_Buff4[i] = (mpz_t *)malloc(sizeof(mpz_t) * (1 + out_bit_len));

		for (int j = 0; j < 1 + out_bit_len; j++)
		{
			mpz_init(sum_Buff1[i][j]);
			mpz_init(sum_Buff2[i][j]);
			mpz_init(sum_Buff3[i][j]);
			mpz_init(sum_Buff4[i][j]);
		}
	}

	int curr_elem = 0;
	for (int i = 0; i < batch_size; ++i)
	{
		for (int j = 0; j < in_bit_len; ++j)
		{
			for (int k = 0; k < in_bit_len; ++k)
			{
				mpz_set(and_Buff1[curr_elem], input_A[i][k]);
				mpz_set(and_Buff2[curr_elem++], input_B[i][j]);
			}
		}
	}

	Mul->doOperation(and_Buff3, and_Buff1, and_Buff2, in_bit_len * in_bit_len * batch_size, threadID);

	int bptr_1 = 0;
	int bptr_2 = 0;
	for (int i = 0; i < batch_size; i++)
	{
		for (int j = 0; j < in_bit_len; j++)
		{
			for (int k = 0; k < out_bit_len; k++)
			{
				if (k < in_bit_len)
					mpz_set(sum_Buff3[bptr_2][k], and_Buff3[bptr_1++]);
				else
					mpz_set_ui(sum_Buff3[bptr_2][k], 0);
			}
			bptr_2++;
		}
	}

	int offset = 1;
	int num_pairs = in_bit_len;
	int base_add_size = in_bit_len;
	int *add_sizes = (int*) malloc(in_bit_len * batch_size * sizeof(int) / 2);

	while (num_pairs > 1)
	{
		if (num_pairs % 2)
		{
			//TODO handle odd cases on alternate rounds
			//WARNING in_bit_len must be a power of two until this case is completed
		}

		num_pairs >>= 1;

		curr_elem = 0;
		for (int i = 0; i < batch_size; i++)
		{
			for (int j = 0; j < num_pairs; j++)
			{
				int trunc_bits = std::max(0, base_add_size + ((2*j + 1) * offset) - out_bit_len);
				add_sizes[curr_elem++] = base_add_size - trunc_bits + 1;
			}
		}

		curr_elem = 0;
		for (int i = 0; i < batch_size; i++)
		{
			for (int j = 0; j < num_pairs; j++)
			{
				for (int k = 0; k < add_sizes[curr_elem]; k++)
				{
					//pass through least significant sum_Buff3 values implicitly by indexing k + offset
					if (k + offset < out_bit_len)
					{
						mpz_set(sum_Buff1[curr_elem][k], sum_Buff3[2*curr_elem][k + offset]);
						mpz_set(sum_Buff2[curr_elem][k], sum_Buff3[2*curr_elem + 1][k]);

						if (k < offset)
						{
							mpz_set(sum_Buff3[curr_elem][k], sum_Buff3[2*curr_elem][k]);
						}
					}
				}
				curr_elem++;
			}
		}

		BitA->doOperation(sum_Buff1, sum_Buff2, sum_Buff4, add_sizes, num_pairs * batch_size, threadID);

		curr_elem = 0;
		for (int i = 0; i < batch_size; i++)
		{
			for (int j = 0; j < num_pairs; j++)
			{
				for (int k = 0; k < add_sizes[curr_elem]; k++)
				{
					//pass through least significant sum_Buff3 values implicitly by indexing k + offset
					if (k + offset < out_bit_len)
					{
						mpz_set(sum_Buff3[curr_elem][k + offset], sum_Buff4[curr_elem][k]);
					}
				}
				curr_elem++;
			}
		}

		base_add_size += offset;
		offset *= 2;
	}

	for (int i = 0; i < batch_size; ++i)
		for (int k = 0; k < out_bit_len; ++k)
			mpz_set(output[i][k], sum_Buff3[i][k]);


	// clear

	for (int i = 0; i < batch_size * in_bit_len * in_bit_len; i++)
	{
		mpz_clear(and_Buff1[i]);
		mpz_clear(and_Buff2[i]);
		mpz_clear(and_Buff3[i]);
	}

	free(and_Buff1);
	free(and_Buff2);
	free(and_Buff3);

	for (int i = 0; i < batch_size * in_bit_len; i++)
	{
		for (int j = 0; j < 1 + out_bit_len; j++)
		{
			mpz_clear(sum_Buff1[i][j]);
			mpz_clear(sum_Buff2[i][j]);
			mpz_clear(sum_Buff3[i][j]);
			mpz_clear(sum_Buff4[i][j]);
		}

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

	//show(output[0], out_bit_len, net, id, ss);
}



void BitMul::doOperation_mal(mpz_t ***input_A, mpz_t ***input_B, mpz_t ***output, int in_bit_len, int batch_size, int threadID)
{
  doOperation_mal(input_A, input_B, output, in_bit_len, 2 * in_bit_len, batch_size, threadID);
}


void BitMul::doOperation_mal(mpz_t ***input_A, mpz_t ***input_B, mpz_t ***output, int in_bit_len, int batch_size, int out_bit_len, int threadID)
{
	//show(input_A[0][0], in_bit_len, net, id, ss);
	//show(input_B[0][0], in_bit_len, net, id, ss);

	mpz_t *and_Buff1 = (mpz_t *)malloc(sizeof(mpz_t) * in_bit_len * in_bit_len * batch_size * 2);
	mpz_t *and_Buff2 = (mpz_t *)malloc(sizeof(mpz_t) * in_bit_len * in_bit_len * batch_size * 2);
	mpz_t *and_Buff3 = (mpz_t *)malloc(sizeof(mpz_t) * in_bit_len * in_bit_len * batch_size * 2);

	for (int i = 0; i < batch_size * in_bit_len * in_bit_len * 2; i++)
	{
		mpz_init(and_Buff1[i]);
		mpz_init(and_Buff2[i]);
		mpz_init(and_Buff3[i]);
	}

	mpz_t ***sum_Buff1 = (mpz_t ***)malloc(sizeof(mpz_t**) * 2);
	mpz_t ***sum_Buff2 = (mpz_t ***)malloc(sizeof(mpz_t**) * 2);
	mpz_t ***sum_Buff3 = (mpz_t ***)malloc(sizeof(mpz_t**) * 2);
	mpz_t ***sum_Buff4 = (mpz_t ***)malloc(sizeof(mpz_t**) * 2);

	for (int mi = 0; mi < 2; mi++)
	{
		sum_Buff1[mi] = (mpz_t **)malloc(sizeof(mpz_t *) * in_bit_len * batch_size);
		sum_Buff2[mi] = (mpz_t **)malloc(sizeof(mpz_t *) * in_bit_len * batch_size);
		sum_Buff3[mi] = (mpz_t **)malloc(sizeof(mpz_t *) * in_bit_len * batch_size);
		sum_Buff4[mi] = (mpz_t **)malloc(sizeof(mpz_t *) * in_bit_len * batch_size);

		for (int i = 0; i < batch_size * in_bit_len; i++)
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

	int curr_elem = 0;
	for (int i = 0; i < batch_size; ++i)
	{
		for (int j = 0; j < in_bit_len; ++j)
		{
			for (int k = 0; k < in_bit_len; ++k)
			{
				mpz_set(and_Buff1[curr_elem], input_A[0][i][k]);
				mpz_set(and_Buff2[curr_elem++], input_B[0][i][j]);
			}
		}
	}

	for (int i = 0; i < batch_size; ++i)
	{
		for (int j = 0; j < in_bit_len; ++j)
		{
			for (int k = 0; k < in_bit_len; ++k)
			{
				mpz_set(and_Buff1[curr_elem], input_A[0][i][k]);
				mpz_set(and_Buff2[curr_elem++], input_B[1][i][j]);
			}
		}
	}

	Mul->doOperation(and_Buff3, and_Buff1, and_Buff2, in_bit_len * in_bit_len * batch_size * 2, threadID);
	ms->pushBuffer(and_Buff3, &and_Buff3[in_bit_len * in_bit_len * batch_size], in_bit_len * in_bit_len * batch_size);

	int bptr_1 = 0;
	int bptr_2 = 0;
	for (int i = 0; i < batch_size; i++)
	{
		for (int j = 0; j < in_bit_len; j++)
		{
			for (int k = 0; k < out_bit_len; k++)
			{
				if (k < in_bit_len)
					mpz_set(sum_Buff3[0][bptr_2][k], and_Buff3[bptr_1++]);
				else
					mpz_set_ui(sum_Buff3[0][bptr_2][k], 0);
			}
			bptr_2++;
		}
	}

	bptr_2 = 0;
	for (int i = 0; i < batch_size; i++)
	{
		for (int j = 0; j < in_bit_len; j++)
		{
			for (int k = 0; k < out_bit_len; k++)
			{
				if (k < in_bit_len)
					mpz_set(sum_Buff3[1][bptr_2][k], and_Buff3[bptr_1++]);
				else
					mpz_set_ui(sum_Buff3[1][bptr_2][k], 0);
			}
			bptr_2++;
		}
	}

	int num_pairs = in_bit_len;
	int base_add_size = in_bit_len;
	int *add_sizes = (int*) malloc(num_pairs * batch_size * sizeof(int) / 2);
	int offset = 1;

	while (num_pairs > 1)
	{
		if (num_pairs % 2)
		{
			//TODO handle odd cases on alternate rounds
			//WARNING in_bit_len must be a power of two until this case is completed
		}

		num_pairs >>= 1;

		curr_elem = 0;
		for (int i = 0; i < batch_size; i++)
		{
			for (int j = 0; j < num_pairs; j++)
			{
				int trunc_bits = std::max(0, base_add_size + ((2*j + 1) * offset) - out_bit_len);
				add_sizes[curr_elem++] = base_add_size - trunc_bits + 1;
			}
		}

		curr_elem = 0;
		for (int i = 0; i < batch_size; i++)
		{
			for (int j = 0; j < num_pairs; j++)
			{
				for (int k = 0; k < add_sizes[curr_elem]; k++)
				{

					if (k + offset < out_bit_len)
					{
						//pass through least significant sum_Buff3 values implicitly by indexing k + offset
						mpz_set(sum_Buff1[0][curr_elem][k], sum_Buff3[0][2*curr_elem][k + offset]);
						mpz_set(sum_Buff2[0][curr_elem][k], sum_Buff3[0][2*curr_elem + 1][k]);

						mpz_set(sum_Buff1[1][curr_elem][k], sum_Buff3[1][2*curr_elem][k + offset]);
						mpz_set(sum_Buff2[1][curr_elem][k], sum_Buff3[1][2*curr_elem + 1][k]);

						if (k < offset)
						{
							mpz_set(sum_Buff3[0][curr_elem][k], sum_Buff3[0][2*curr_elem][k]);

							mpz_set(sum_Buff3[1][curr_elem][k], sum_Buff3[1][2*curr_elem][k]);
						}
					}
				}
				curr_elem++;
			}
		}

		BitA->doOperation_mal(sum_Buff1, sum_Buff2, sum_Buff4, add_sizes, num_pairs * batch_size, threadID);

		curr_elem = 0;
		for (int i = 0; i < batch_size; i++)
		{
			for (int j = 0; j < num_pairs; j++)
			{
				for (int k = 0; k < add_sizes[curr_elem]; k++)
				{
					if (k + offset < out_bit_len)
					{
						//pass through least significant sum_Buff3 values implicitly by indexing k + offset
						mpz_set(sum_Buff3[0][curr_elem][k + offset], sum_Buff4[0][curr_elem][k]);

						mpz_set(sum_Buff3[1][curr_elem][k + offset], sum_Buff4[1][curr_elem][k]);
					}
				}
				curr_elem++;
			}
		}

		base_add_size += offset;
		offset *= 2;
	}

	for (int i = 0; i < batch_size; ++i)
	{
		for (int k = 0; k < out_bit_len; ++k)
		{
			mpz_set(output[0][i][k], sum_Buff3[0][i][k]);

			mpz_set(output[1][i][k], sum_Buff3[1][i][k]);
		}
	}


	// clear

	for (int i = 0; i < batch_size * in_bit_len * in_bit_len * 2; i++)
	{
		mpz_clear(and_Buff1[i]);
		mpz_clear(and_Buff2[i]);
		mpz_clear(and_Buff3[i]);
	}

	for (int mi = 0; mi < 2; mi++)
	{
		for (int i = 0; i < batch_size * in_bit_len; i++)
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

	free(and_Buff1);
	free(and_Buff2);
	free(and_Buff3);

	free(add_sizes);

	//show(output[0][0], out_bit_len, net, id, ss);
}







