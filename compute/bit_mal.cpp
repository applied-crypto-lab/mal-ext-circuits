
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
  struct timeval start1;
  struct timeval end1;
  unsigned long verif_time = 0;

  mpz_t ***a = (mpz_t ***)malloc(sizeof(mpz_t **) * 2);
  mpz_t ***b = (mpz_t ***)malloc(sizeof(mpz_t **) * 2);
  mpz_t ***c = (mpz_t ***)malloc(sizeof(mpz_t **) * 2);
  mpz_t ***d = (mpz_t ***)malloc(sizeof(mpz_t **) * 2);
  mpz_t **e = (mpz_t **)malloc(sizeof(mpz_t *) * 2);
  mpz_t **f = (mpz_t **)malloc(sizeof(mpz_t *) * 2);
  mpz_t *g = (mpz_t *)malloc(sizeof(mpz_t) * 2);

  for (int mi = 0; mi < 2; mi++)
  {
    a[mi] = (mpz_t **)malloc(sizeof(mpz_t *) * batch_size);
    b[mi] = (mpz_t **)malloc(sizeof(mpz_t *) * batch_size);
    c[mi] = (mpz_t **)malloc(sizeof(mpz_t *) * batch_size);
    d[mi] = (mpz_t **)malloc(sizeof(mpz_t *) * batch_size);
    e[mi] = (mpz_t *)malloc(sizeof(mpz_t) * mod_bits);
    f[mi] = (mpz_t *)malloc(sizeof(mpz_t) * mod_bits);

    for (int i = 0; i < batch_size; i++)
    {
      a[mi][i] = (mpz_t *)malloc(sizeof(mpz_t) * num_bits);
      b[mi][i] = (mpz_t *)malloc(sizeof(mpz_t) * num_bits);
      c[mi][i] = (mpz_t *)malloc(sizeof(mpz_t) * mod_bits);
      d[mi][i] = (mpz_t *)malloc(sizeof(mpz_t) * mod_bits);

      for (int j = 0; j < num_bits; ++j)
      {
        mpz_init(a[mi][i][j]);
        mpz_init(b[mi][i][j]);
      }
      for (int j = 0; j < mod_bits; ++j)
      {
        mpz_init(c[mi][i][j]);
        mpz_init(d[mi][i][j]);
      }
    }

    for (int j = 0; j < mod_bits; ++j)
    {
      mpz_init(e[mi][j]);
      mpz_init(f[mi][j]);
    }

    mpz_init(g[mi]);
  }

  mpz_t **res;
  res = (mpz_t **)malloc(sizeof(mpz_t *) * 2);
  for (int mi = 0; mi < 2; mi++)
  {
    res[mi] = (mpz_t *)malloc(sizeof(mpz_t) * batch_size);
    for (int i = 0; i < batch_size; i++)
      mpz_init(res[mi][i]);
  }

  mpz_t inp_a[2];
  mpz_init_set_ui(inp_a[0], 1);
  mpz_init(inp_a[1]);

  mpz_t inp_b[2];
  mpz_init_set_ui(inp_b[0], 1);
  mpz_init(inp_b[1]);

  if (debug_mode)
  {
    num_bits = sizeof(input_a) / sizeof(int);

    for (int i = 0; i < batch_size; ++i)
    {
      for (int j = 0; j < num_bits; ++j)
      {
        mpz_set_ui(a[0][i][j], input_a[j]);
        mpz_set_ui(b[0][i][j], input_b[j]);
      }
    }

    __s->smc_input_mal(a, b, batch_size, num_bits, "int", -1);
  }
  else
  {
    __s->smc_input_mal(inp_a, inp_b, "int", -1);

    for (int i = 0; i < batch_size; ++i)
    {
      for (int j = 0; j < num_bits; ++j)
      {
        mpz_set(a[0][i][j], inp_a[0]);
        mpz_set(b[0][i][j], inp_b[0]);

        mpz_set(a[1][i][j], inp_a[1]);
        mpz_set(b[1][i][j], inp_b[1]);
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
      __s->smc_bitadd_mal(a, b, c, num_bits, batch_size, -1);

      run_verification();	//NOTE see tests.h
    }
  }

  if (alg == "mul")
  {
    printf("start mult\n");
    for (int i = 0; i < rep; i++)
    {
      __s->smc_bitmul_mal(a, b, c, num_bits, batch_size, mod_bits, -1);

      run_verification();	//NOTE see tests.h
    }
  }

  if (alg == "lt")
  {
    printf("start LT\n");
    for (int i = 0; i < rep; i++)
    {
      __s->smc_bitlt_mal(a, b, res, num_bits, batch_size, -1);

      run_verification();	//NOTE see tests.h
    }
  }

  if (alg == "equ")
  {
    printf("start EQU\n");
    for (int i = 0; i < rep; i++)
    {
      __s->smc_biteq_mal(a, b, res, num_bits, batch_size, -1);

      run_verification();	//NOTE see tests.h
    }
  }

  if (alg == "ed")
  {
    printf("start ED\n");
    for (int i = 0; i < rep; i++)
    {
      __s->smc_bittwoscomp_mal(b, b, num_bits, batch_size, -1);
      __s->smc_bitadd_mal(a, b, c, num_bits, batch_size, -1);
      __s->smc_bitmul_mal(c, c, d, num_bits, batch_size, mod_bits, -1);
      __s->smc_bitsum_mal(d, e, num_bits, batch_size, mod_bits, -1);
      __s->smc_bitlt_mal(e, f, g, num_bits, -1);

      run_verification();	//NOTE see tests.h
    }
  }

  gettimeofday(&end, NULL);
  test_time = 1000000 * (end.tv_sec - start.tv_sec) + end.tv_usec - start.tv_usec;

  std::string test_description = alg + ",bitwise,malicious";
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

  for (int mi = 0; mi < 2; mi++)
  {
    for (int i = 0; i < batch_size; i++)
    {
      for (int j = 0; j < num_bits; j++)
      {
        mpz_clear(a[mi][i][j]);
        mpz_clear(b[mi][i][j]);
      }
      for (int j = 0; j < mod_bits; j++)
      {
        mpz_clear(c[mi][i][j]);
        mpz_clear(d[mi][i][j]);
      }
      free(a[mi][i]);
      free(b[mi][i]);
      free(c[mi][i]);
      free(d[mi][i]);
    }

    for (int j = 0; j < batch_size; j++)
    {
      mpz_clear(res[mi][j]);
    }

    for (int j = 0; j < mod_bits; ++j)
    {
      mpz_clear(e[mi][j]);
      mpz_clear(f[mi][j]);
    }

    mpz_clear(g[mi]);
    free(a[mi]);
    free(b[mi]);
    free(c[mi]);
    free(d[mi]);
    free(e[mi]);
    free(res[mi]);
  }

  free(a);
  free(b);
  free(c);
  free(d);
  free(e);
  free(f);
  free(g);
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

  secparam = 48;
  modulus = PRIME_48;
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
