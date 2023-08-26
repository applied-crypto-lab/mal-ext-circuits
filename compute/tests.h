
#ifndef TESTS_H_
#define TESTS_H_


#include "smc-compute/Debug.h"

#define PRIME_3 "5"
#define PRIME_32 "4294961009"
#define PRIME_48 "281474976710597"
#define PRIME_70 "1171125819614621174939"
#define PRIME_80 "1208925819614629174706111"
#define PRIME_128 "340252366920938463463374607431768211669"

#define run_verification()\
\
gettimeofday(&start1, NULL);\
__s->smc_verify();\
gettimeofday(&end1, NULL);\
verif_time += 1000000 * (end1.tv_sec - start1.tv_sec) + end1.tv_usec - start1.tv_usec;

void get_time_summary(int id, std::string test_description, bool writing_to_file, unsigned long test_time, unsigned long verif_time)
{
  printf("Total time per run= %ld us\n", test_time);
  printf("Verification time per run = %ld us\n", verif_time);

  if (writing_to_file)
  {
    std::ofstream results_file;
    results_file.open("time_test_results_" + std::to_string(id) + ".csv", std::ios::app);

    results_file << "\n" << test_description << "," << "," << test_time << "," << verif_time << "\n";
    results_file.close();
  }
}

Debug *D;

//input arrays for bitwise test debugging
//int input_a[] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
//int input_b[] = {1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0};

//int input_a[] = {1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0};
//int input_b[] = {1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0};

//int input_a[] = {0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1};
//int input_b[] = {0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1};


//int input_a[] = {0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0};
//int input_b[] = {0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0};

//int input_a[] = {1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0};
//int input_b[] = {1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0};

//int input_a[] = {1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1};
//int input_b[] = {1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1};

//int input_a[] = {1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0};
//int input_b[] = {1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1};

//int input_a[] = {0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0};
//int input_b[] = {1, 1, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1};

//int input_a[] = {1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0};
//int input_b[] = {0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 1};

//int input_a[] = {0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1};
//int input_b[] = {0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0};

//int input_a[] = {1, 1, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0};
//int input_b[] = {1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1};

//int input_a[] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
//int input_b[] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};

int input_a[] = {0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0};
int input_b[] = {0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1};

//int input_a[] = {1, 1, 0, 0, 0, 0, 0, 1};
//int input_b[] = {1, 0, 0, 0, 0, 0, 1, 0};

//int input_a[] = {1, 0, 1, 0, 1, 0, 1, 0};
//int input_b[] = {1, 1, 0, 0, 1, 0, 0, 1};

//int input_a[] = {1, 1, 0, 0, 1, 0, 0, 1};
//int input_b[] = {1, 0, 1, 0, 1, 0, 1, 0};

//int input_a[] = {1, 1, 1, 1, 1, 1, 1, 1};
//int input_b[] = {1, 1, 1, 1, 1, 1, 1, 1};

//int input_a[] = {1, 1, 1, 1};
//int input_b[] = {1, 1, 1, 1};

//int input_a[] = {0, 1, 1, 1, 0, 1, 0, 0};
//int input_b[] = {1, 1, 1, 0, 1, 0, 0, 1};

//int input_a[] = {1, 1, 1, 0, 1, 0, 0, 1};
//int input_b[] = {1, 1, 1, 0, 1, 0, 0, 1};

//int input_a[] = {0, 1, 1, 1, 0, 1, 0, 0, 1, 1, 0};
//int input_b[] = {1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1};

//int input_a[] = {1, 0, 1, 1, 0, 1, 1, 0, 0, 1, 0};
//int input_b[] = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};


#endif