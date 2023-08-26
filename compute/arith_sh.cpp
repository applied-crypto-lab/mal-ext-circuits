
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

	mpz_t *a = (mpz_t *)malloc(sizeof(mpz_t) * (batch_size));
	mpz_t *b = (mpz_t *)malloc(sizeof(mpz_t) * (batch_size));
	mpz_t *c = (mpz_t *)malloc(sizeof(mpz_t) * (batch_size));
	for (int i = 0; i < batch_size; i++)
	{
		mpz_init(a[i]);
		mpz_init(b[i]);
		mpz_init(c[i]);
	}

	mpz_t d;
	mpz_init(d);

	mpz_t res;
	mpz_init(res);

	mpz_t cmp;
	mpz_init(cmp);

	mpz_t inp_a;
	mpz_init(inp_a);
	mpz_t inp_b;
	mpz_init(inp_b);

	__s->smc_input(1, &inp_a, "int", -1);

	__s->smc_input(1, &inp_b, "int", -1);

	mpz_set_ui(inp_a, 2);
	mpz_set_ui(inp_b, 3);

	for (int i = 0; i < batch_size; i++)
	{
		{
			__s->smc_set(inp_a, a[i], num_bits, num_bits, "int", -1);
			__s->smc_set(inp_b, b[i], num_bits, num_bits, "int", -1);
		}
		i++;
	}

	//__s->smc_get_communication_summary("", false);
	__s->smc_reset_counters();

	gettimeofday(&start, NULL);

	if (alg == "add")
	{
		printf("start add\n");
		for (int i = 0; i < rep; i++)
		{
			__s->smc_add(a, b, num_bits, num_bits, c, num_bits, batch_size, "int", -1);
		}
	}

	if (alg == "mul")
	{
		printf("start mul\n");
		for (int i = 0; i < rep; i++)
		{
			__s->smc_mult(a, b, num_bits, num_bits, c, num_bits, batch_size, "int", -1);
		}
	}

	if (alg == "lt")
	{
		printf("start LT\n");
		for (int i = 0; i < rep; i++)
		{
			__s->smc_lt(a, b, num_bits, num_bits, c, num_bits, batch_size, "int", -1);

			i++;
		}
	}

	if (alg == "equ")
	{
		printf("start EQU\n");
		for (int i = 0; i < rep; i++)
		{
			__s->smc_eqeq(a, b, num_bits, num_bits, c, num_bits, batch_size, "int", -1);

			i++;
		}
	}

	if (alg == "ed")
	{
		printf("start ED\n");
		for (int i = 0; i < rep; i++)
		{
			__s->smc_sub(a, b, num_bits, num_bits, c, num_bits, batch_size, "int", -1);
			__s->smc_dot(c, c, batch_size, d, -1);
			__s->smc_lt(d, cmp, res, num_bits, num_bits, num_bits, "int", -1);
		}
	}

	gettimeofday(&end, NULL);
	test_time = 1000000 * (end.tv_sec - start.tv_sec) + end.tv_usec - start.tv_usec;

	std::string test_description = alg + ",arithmetic,semi-honest";
	test_description += ",bitlength  = " + std::to_string(num_bits) + ",secparam =" + std::to_string(secparam);
	test_description += ",input size  = " + std::to_string(batch_size) + ",reps =" + std::to_string(rep);

	if (debug_mode)
	{
		__s->smc_get_communication_summary(test_description, true);
	}
	else
	{	//NOTE see tests.h
		get_time_summary(id, test_description, true, test_time / rep, 0);
	}

	mpz_clear(inp_a);
	mpz_clear(inp_b);


	for (int i = 0; i < batch_size; i++)
	{
		mpz_clear(a[i]);
		mpz_clear(b[i]);
		mpz_clear(c[i]);
	}

	mpz_clear(d);
	mpz_clear(res);
	mpz_clear(cmp);

	free(a);
	free(b);
	free(c);

	return (0);
}


int main(int argc, char **argv)
{

	if (argc < 11)
	{
		fprintf(stderr, "Incorrect input parameters\n");
		fprintf(stderr, "Usage: <id> <runtime-config> <privatekey-filename> <number-of-input-parties> <number-of-output-parties> <input-share> <output> <bS> <rep> <alg> <debug mode>\n");
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
		secparam = 32;
		modulus = PRIME_32;
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

	threat_model = SEMIHONEST;

	__s = new SMC_Utils(atoi(argv[1]), argv[2], argv[3], atoi(argv[4]), atoi(argv[5]), IO_files, 3, 1, secparam, modulus, 1, threat_model);

	struct timeval tv1;
	struct timeval tv2;
	int _xval = 0;

	gettimeofday(&tv1, NULL);

	_xval = (int)__original_main(argc, argv);

	gettimeofday(&tv2, NULL);
	std::cout << "Time: " << __s->time_diff(&tv1, &tv2) << std::endl;

	return (_xval);
}
