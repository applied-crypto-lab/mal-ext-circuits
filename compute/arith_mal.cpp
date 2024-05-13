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

#include <limits.h>
#include <float.h>
#include <malloc.h>
#include "smc-compute/SMC_Utils.h"
#include <gmp.h>
#include <omp.h>
#include "tests.h"

extern "C" int ort_initialize(int *, char ***);
extern "C" void ort_finalize(int);


SMC_Utils *__s;

int id = 0;
int num_bits = 32;
int batch_size = 10;
int rep = 1;
int mod_bits = num_bits;
int threat_model;
std::string modulus;
int secparam;
int debug_mode = 0;

std::string alg;

int __original_main(int _argc_ignored, char **_argv_ignored)
{
	struct timeval start;
	struct timeval end;
	unsigned long test_time;
	unsigned long verif_time = 0;

	mpz_t **a = (mpz_t **)malloc(sizeof(mpz_t*) * 2);
	mpz_t **b = (mpz_t **)malloc(sizeof(mpz_t*) * 2);
	mpz_t **c = (mpz_t **)malloc(sizeof(mpz_t*) * 2);
	for (int j = 0; j < 2; j++)
	{
		a[j] = (mpz_t *)malloc(sizeof(mpz_t) * (batch_size));
		b[j] = (mpz_t *)malloc(sizeof(mpz_t) * (batch_size));
		c[j] = (mpz_t *)malloc(sizeof(mpz_t) * (batch_size));
		for (int i = 0; i < batch_size; i++)
		{
			mpz_init(a[j][i]);
			mpz_init(b[j][i]);
			mpz_init(c[j][i]);
		}
	}

	mpz_t *d = (mpz_t *)malloc(sizeof(mpz_t) * 2);
	mpz_t *res = (mpz_t *)malloc(sizeof(mpz_t) * 2);
	for (int j = 0; j < 2 ; j++)
	{
		mpz_init(d[j]);
		mpz_init(res[j]);
	}

	mpz_t inp_a[2];
	mpz_init(inp_a[0]);
	mpz_init(inp_a[1]);

	mpz_t inp_b[2];
	mpz_init(inp_b[0]);
	mpz_init(inp_b[1]);

	mpz_set_ui(inp_a[0], 2);
	mpz_set_ui(inp_b[0], 3);

  if (alg == "add")
  { //verification not needed for arithmetic addition only
    printf("adding\n");
    __s->smc_input(1, inp_a, "int", -1);
    __s->smc_input(1, inp_b, "int", -1);
  }
  else
  {
    __s->smc_input_mal(inp_a, inp_b, "int", -1);
  }

	for (int i = 0; i < batch_size; i++)
	{
		{
			__s->smc_set(inp_a[0], a[0][i], num_bits, num_bits, "int", -1);
			__s->smc_set(inp_a[1], a[1][i], num_bits, num_bits, "int", -1);

			__s->smc_set(inp_b[0], b[0][i], num_bits, num_bits, "int", -1);
			__s->smc_set(inp_b[1], b[1][i], num_bits, num_bits, "int", -1);
		}
	}

	mpz_t cmp[2];
	mpz_init(cmp[0]);
	mpz_init(cmp[1]);

	__s->smc_set(inp_a[0], cmp[0], num_bits, num_bits, "int", -1);
	__s->smc_set(inp_a[1], cmp[1], num_bits, num_bits, "int", -1);

  __s->smc_reset_counters();

	gettimeofday(&start, NULL);

	if (alg == "add")
	{
		printf("start add\n");
		for (int i = 0; i < rep; i++)
		{
			__s->smc_add_mal(a, b, num_bits, num_bits, c, num_bits, batch_size, "int", -1);

      //NOTE nothing to verify here
			//__s->smc_verify();
		}
	}

	if (alg == "mul")
	{
		printf("start mult\n");
		for (int i = 0; i < rep; i++)
		{
			__s->smc_mult_mal(a, b, num_bits, num_bits, c, num_bits, batch_size, "int", -1);

			__s->smc_verify();
		}
	}

	if (alg == "lt")
	{
		printf("start LT\n");
		for (int i = 0; i < rep; i++)
		{
			__s->smc_lt_mal(a, b, num_bits, num_bits, c, num_bits, batch_size, "int", -1);

			__s->smc_verify();
		}
	}

	if (alg == "equ")
	{
		printf("start EQU\n");
		for (int i = 0; i < rep; i++)
		{
			__s->smc_eqeq_mal(a, b, num_bits, num_bits, c, num_bits, batch_size, "int", -1);

			__s->smc_verify();
		}
	}

	if (alg == "ed")
	{
		printf("start ED\n");
		for (int i = 0; i < rep; i++)
		{
			__s->smc_sub_mal(a, b, num_bits, num_bits, c, num_bits, batch_size, "int", -1);
			__s->smc_dot_mal(c, c, batch_size, d, -1);
			__s->smc_lt_mal(d, cmp, res, num_bits, num_bits, num_bits, "int", -1);

			__s->smc_verify();
		}
	}

	gettimeofday(&end, NULL);
	test_time = 1000000 * (end.tv_sec - start.tv_sec) + end.tv_usec - start.tv_usec;

	std::string test_description = alg + ",arithmetic,malicious";
	test_description += ",bitlength  = " + std::to_string(num_bits) + ",secparam =" + std::to_string(secparam);
	test_description += ",input size  = " + std::to_string(batch_size) + ",reps =" + std::to_string(rep);

	if (debug_mode)
	{
		__s->smc_get_communication_summary(test_description, true);
	}
	else
	{	//NOTE see tests.h
		get_time_summary(id, test_description, true, test_time / rep, __s->smc_get_verif_time() / rep, threat_model);
	}

	mpz_clear(inp_a[0]);
	mpz_clear(inp_a[1]);
	mpz_clear(inp_b[0]);
	mpz_clear(inp_b[1]);
	mpz_clear(cmp[0]);
	mpz_clear(cmp[1]);


	for (int i = 0; i < batch_size; i++)
	{
		for (int j = 0; j < 2; j++)
		{
			mpz_clear(a[j][i]);
			mpz_clear(b[j][i]);
			mpz_clear(c[j][i]);
		}
	}

	mpz_clear(d[0]);
	mpz_clear(d[1]);
	mpz_clear(res[0]);
	mpz_clear(res[1]);

	for(int j = 0; j< 2; j++)
	{
		free(a[j]);
		free(b[j]);
		free(c[j]);
	}

	free(a);
	free(b);
	free(c);
	free(d);
	free(res);

	return (0);
}


int main(int argc, char **argv)
{

	if (argc < 11)
	{
		fprintf(stderr, "Incorrect input parameters\n");
		fprintf(stderr, "Usage: <id> <runtime-config> <privatekey-filename> <number-of-input-parties> <number-of-output-parties> <input-share> <output> <batch_size> <rep> <alg> <debug mode>\n");
		exit(1);
	}

	id = atoi(argv[1]);

	std::string IO_files[atoi(argv[4]) + atoi(argv[5])];
	for (int i = 0; i < 2; i++)
		IO_files[i] = argv[6 + i];

	batch_size = atoi(argv[8]);
	rep = atoi(argv[9]);
	alg = argv[10];

	if ((argc > 11) && (strcmp(argv[11], "debug") == 0))
	{
		debug_mode = 1;
	}

	if ((alg == "add") || (alg == "mul"))
	{
		secparam = 48;
		modulus = PRIME_48;
	}
	else if ((alg == "lt") || (alg == "equ") || (alg == "ed"))
	{
		secparam = 80;
		modulus = PRIME_80;
	}
	else
	{
		printf("No valid algorithm selected\n");
		exit(1);
	}

	threat_model = MALICIOUS;

	__s = new SMC_Utils(atoi(argv[1]), argv[2], argv[3], atoi(argv[4]), atoi(argv[5]), IO_files, 3, 1, secparam, modulus, 1, threat_model);

	struct timeval tv1;
	struct timeval tv2;
	int _xval = 0;

	gettimeofday(&tv1, NULL);

	__s->smc_init_mal(); // generate r and initialize buffer for verification triples
	_xval = (int)__original_main(argc, argv);
	__s->smc_clean_mal();

	gettimeofday(&tv2, NULL);
	std::cout << "Time: " << __s->time_diff(&tv1, &tv2) << std::endl;

	return (_xval);
}

