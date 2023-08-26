
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

  mpz_t **a = (mpz_t **)malloc(sizeof(mpz_t *) * (batch_size));
  mpz_t **b = (mpz_t **)malloc(sizeof(mpz_t *) * (batch_size));
  for (int i = 0; i < batch_size; i++)
  {
    a[i] = (mpz_t *)malloc(sizeof(mpz_t) * (num_bits));
    b[i] = (mpz_t *)malloc(sizeof(mpz_t) * (num_bits));
    for (int j = 0; j < num_bits; ++j)
    {
      mpz_init(a[i][j]);
      mpz_init(b[i][j]);
    }
  }

  mpz_t **c = (mpz_t **)malloc(sizeof(mpz_t *) * (batch_size));
  mpz_t **d = (mpz_t **)malloc(sizeof(mpz_t *) * (batch_size));
  for (int i = 0; i < batch_size; i++)
  {
    c[i] = (mpz_t *)malloc(sizeof(mpz_t) * mod_bits);
    d[i] = (mpz_t *)malloc(sizeof(mpz_t) * mod_bits);
    for (int j = 0; j < mod_bits; ++j)
    {
      mpz_init(c[i][j]);
      mpz_init(d[i][j]);
    }
  }

  mpz_t *res = (mpz_t *)malloc(sizeof(mpz_t) * (batch_size));
  for (int i = 0; i < batch_size; i++)
  {
    mpz_init(res[i]);
  }

  mpz_t input;
  mpz_init(input);

  //__s->smc_input(1, &input, "int", -1);

  if (debug_mode)
  {
    num_bits = sizeof(input_a) / sizeof(int);

    for (int i = 0; i < batch_size; ++i)
    {
      for (int j = 0; j < num_bits; ++j)
      {
        mpz_set_ui(a[i][j], input_a[j]);
        mpz_set_ui(b[i][j], input_b[j]);
      }
    }
  }
  else
  {
    for (int i = 0; i < batch_size; i++)
    {
      for (int j = 0; j < num_bits; j++)
      {
        mpz_set_ui(a[i][j], j % 2);
        mpz_set_ui(b[i][j], j % 2);
      }
    }
  }

  //__s->smc_get_communication_summary("", false);
  __s->smc_reset_counters();

  gettimeofday(&start, NULL);

  if (alg == "add")
  {
    printf("start add\n");
    for (int i = 0; i < rep; i++)
    {
      __s->smc_bitadd(a, b, c, num_bits, batch_size, -1);
    }
  }

  if (alg == "mul")
  {
    printf("start mult\n");
    for (int i = 0; i < rep; i++)
    {
      __s->smc_bitmul(a, b, c, num_bits, batch_size, mod_bits, -1);
    }
  }

  if (alg == "lt")
  {
    printf("start LT\n");
    for (int i = 0; i < rep; i++)
    {
      __s->smc_bitlt(a, b, res, num_bits, batch_size, -1);
    }
  }

  if (alg == "equ")
  {
    printf("start EQU\n");
    for (int i = 0; i < rep; i++)
    {
      __s->smc_biteq(a, b, res, num_bits, batch_size, -1);
    }
  }

  if (alg == "ed")
  {
    printf("start ED\n");
    for (int i = 0; i < rep; i++)
    {
      __s->smc_bittwoscomp(b, b, num_bits, batch_size, -1);
      __s->smc_bitadd(a, b, c, num_bits, batch_size, -1);
      __s->smc_bitmul(c, c, d, num_bits, batch_size, mod_bits, -1);
      __s->smc_bitsum(d, c[0], num_bits, batch_size, mod_bits, -1);
      __s->smc_bitlt(c[0], b[0], res[0], mod_bits, -1);
    }
  }

  gettimeofday(&end, NULL);
  test_time = 1000000 * (end.tv_sec - start.tv_sec) + end.tv_usec - start.tv_usec;

  std::string test_description = alg + ",bitwise,semi-honest";
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

  mpz_clear(input);
  for (int i = 0; i < batch_size; ++i)
  {
  }
  for (int i = 0; i < batch_size; i++)
  {
    for (int j = 0; j < num_bits; j++)
    {
      mpz_clear(a[i][j]);
      mpz_clear(b[i][j]);
    }
    for (int j = 0; j < mod_bits; j++)
    {
      mpz_clear(c[i][j]);
      mpz_clear(d[i][j]);
    }
    mpz_clear(res[i]);
    free(a[i]);
    free(b[i]);
    free(c[i]);
    free(d[i]);
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
    fprintf(stderr, "Usage: <id> <runtime-config> <privatekey-filename> <number-of-input-parties> <number-of-output-parties> <input-share> <output> <batch_size> <rep> <alg> <debug mode> \n");
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

  secparam = 3;
  modulus = PRIME_3;
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
