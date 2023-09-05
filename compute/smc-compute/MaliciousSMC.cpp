
#include "MaliciousSMC.h"
#include <sys/time.h>

MaliciousSMC::MaliciousSMC(NodeConfiguration *nodeConfig, NodeNetwork nodeNet, SecretShare* s, int p, int t, Random *Rand, Mult *M)
//MaliciousSMC::MaliciousSMC(NodeNetwork nodeNet, SecretShare* s, int p, int t)
{
  net = nodeNet;
  ss = s;
  rand = Rand;
  config = nodeConfig;
  VerificationTimer = 0;
  peers = p;
  threshhold = t;
  id = net.getID();

  //Mul = new Mult(nodeNet, id, s);
  Mul = M;
  //D = new Debug();

  init_mal();
}

MaliciousSMC::MaliciousSMC() {}

MaliciousSMC::~MaliciousSMC() {}

// malicious functions
int MaliciousSMC::getcurRow()
{
  return curRow_mal;
}

void MaliciousSMC::init_mal()
{
  printf("Begin Malicious Mode\n");
  // This function is used to initialize all variables and buffers for malicious computation verification
  // r will be assigned a random value later in SMC

  // The verification buffer is organized as a 2-D arrays, i.e., buffer_mal[maxRow_mal][rowCap_mal].
  // In initalization, we only alloc memory for the first curCap_mal rows. At this point,
  // our buffer could contain curCap_mal * rowCap_mal elements.
  // As elements being pushed into buffer, the initalized space will run out.
  // Once that happens, we alloc memeory for more rows in the 2D buffer.

  maxRow_mal = 1000;
  rowCap_mal = 10000;
  maxCapacity_mal = maxRow_mal * rowCap_mal;
  curRow_mal = 0;
  curPoint_mal = 0;
  curCap_mal = 10;
  curCapacity_mal = curCap_mal * rowCap_mal;

  buffer_mal = (mpz_t **) malloc(sizeof(mpz_t *) * (maxRow_mal * 2));
  mpz_init(r);

  for (int i = 0; i < curCap_mal; i++)
  {
    buffer_mal[2 * i] = (mpz_t *) malloc(sizeof(mpz_t) * (rowCap_mal));
    buffer_mal[2 * i + 1] = (mpz_t *) malloc(sizeof(mpz_t) * (rowCap_mal));
    for (int j = 0; j < rowCap_mal; j++)
    {
      mpz_init(buffer_mal[2 * i][j]);
      mpz_init(buffer_mal[2 * i + 1][j]);
    }
  }

  computeLagrangeWeight_mal();

  rand_seed = (mpz_t *) malloc(sizeof(mpz_t));
  mpz_init(rand_seed[0]);
}

bool MaliciousSMC::checkBuffer(int size)
{
  if (curCapacity_mal > size)
  {
    return true;
  }
  if (curCapacity_mal + (maxRow_mal - curCap_mal) * rowCap_mal < size)
    return false;

  //printf("--Need more space \n");
  int new_row = 1;

  while (size > new_row * rowCap_mal + curCapacity_mal)
  {
    new_row++;
  }
  for (int i = 0; i < new_row; i++)
  {
    buffer_mal[curCap_mal * 2] = (mpz_t *) malloc(sizeof(mpz_t) * (rowCap_mal));
    buffer_mal[curCap_mal * 2 + 1] = (mpz_t *) malloc(sizeof(mpz_t) * (rowCap_mal));
    for (int j = 0; j < rowCap_mal; j++)
    {
      mpz_init(buffer_mal[curCap_mal * 2][j]);
      mpz_init(buffer_mal[curCap_mal * 2 + 1][j]);
    }
    curCap_mal++;
    curCapacity_mal += rowCap_mal;
  }
  return true;
}



void MaliciousSMC::pushBuffer(mpz_t *result, mpz_t *resultR, int size)
{
  //printf("push into buffer: %d\n", size);

  if (!checkBuffer(size))
  {
    printf("buffer filled, no more verification could be done\n");
    return;
  }
  // check buffer avaiablity and push results into the buffer. This function will be called inside of functions like mult_mal/add_mal
  // first fill unfilled row
  if (size <= rowCap_mal - curPoint_mal)
  {
    for (int i = 0; i < size; i++)
    {
      mpz_set(buffer_mal[curRow_mal * 2][curPoint_mal], result[i]);
      mpz_set(buffer_mal[curRow_mal * 2 + 1][curPoint_mal], resultR[i]);
      curPoint_mal++;
      curCapacity_mal--;
    }
    if (curPoint_mal == rowCap_mal)
    {
      curPoint_mal = curPoint_mal % rowCap_mal;
      curRow_mal++;
    }
    return;
  }

  int sizeP = rowCap_mal - curPoint_mal;
  for (int i = 0; i < sizeP; i++)
  {
    mpz_set(buffer_mal[curRow_mal * 2][curPoint_mal], result[i]);
    mpz_set(buffer_mal[curRow_mal * 2 + 1][curPoint_mal], resultR[i]);
    curPoint_mal++;
    curCapacity_mal--;
  }
  curPoint_mal = curPoint_mal % rowCap_mal;
  curRow_mal++;
  // fill serveral full rows
  int entireRow = (size - sizeP) / rowCap_mal;
  for (int i = 0; i < entireRow; i++)
  {
    for (int j = 0; j < rowCap_mal; j++)
    {
      mpz_set(buffer_mal[curRow_mal * 2][curPoint_mal], result[sizeP]);
      mpz_set(buffer_mal[curRow_mal * 2 + 1][curPoint_mal], resultR[sizeP]);
      curPoint_mal++;
      sizeP++;
      curCapacity_mal--;
    }
    curRow_mal++;
    curPoint_mal = 0;
  }
  // fill the rest into next row
  for (int i = sizeP; i < size; i++)
  {
    mpz_set(buffer_mal[curRow_mal * 2][curPoint_mal], result[i]);
    mpz_set(buffer_mal[curRow_mal * 2 + 1][curPoint_mal], resultR[i]);
    curPoint_mal++;
    curCapacity_mal--;
  }
}

void MaliciousSMC::verify()
{
  struct timeval start;
  struct timeval end;
  unsigned long timerp1;
  gettimeofday(&start, NULL);
  int verifySize = curRow_mal * rowCap_mal + curPoint_mal;
  //printf("Verification buffer size: %i\n", verifySize);

  mpz_t field_size;
  mpz_init(field_size);
  ss->getFieldSize(field_size);
  int curP = 0;

  mpz_t *alphaArray; // container for randomness i.e., \alphas
  mpz_t *u1;
  mpz_t *u2;
  mpz_t **a = (mpz_t **) malloc(sizeof(mpz_t *) * (2));
  for (int i = 0; i < 2; i++)
  {
    a[i] = (mpz_t *) malloc(sizeof(mpz_t) * (verifySize));
    for (int j = 0; j < verifySize; j++)
      mpz_init(a[i][j]);
  }

  for (int i = 0; i < curRow_mal; i++)
  {
    for (int j = 0; j < rowCap_mal; j++)
    {
      mpz_set(a[0][curP], buffer_mal[i * 2][j]);
      mpz_set(a[1][curP], buffer_mal[i * 2 + 1][j]);
      curP++;
    }
  }
  for (int i = 0; i < curPoint_mal; i++)
  {
    mpz_set(a[0][curP], buffer_mal[curRow_mal * 2][i]);
    mpz_set(a[1][curP], buffer_mal[curRow_mal * 2 + 1][i]);
    curP++;
  }

  mpz_t sum1;
  mpz_t sum2;

  if (verifySize == 1)
  {
    mpz_init_set(sum1, a[1][0]);
    mpz_init_set(sum2, a[0][0]);
  }
  else
  {
    rand->generateRandValue(config->getID(), config->getBits(), 1, rand_seed);
    int open_seed = Open_N(rand_seed[0], NULL, -1, net, id, ss);
    mpz_set_ui(rand_seed[0], open_seed);
    gmp_randinit_mt(verifyRandomState);
    gmp_randseed(verifyRandomState, rand_seed[0]);

    mpz_init_set_ui(sum1, 0);
    mpz_init_set_ui(sum2, 0);

    alphaArray = (mpz_t *) malloc(sizeof(mpz_t) * (verifySize));
    u1 = (mpz_t *) malloc(sizeof(mpz_t) * (verifySize));
    u2 = (mpz_t *) malloc(sizeof(mpz_t) * (verifySize));
    for (int i = 0; i < verifySize; i++)
    {
      mpz_init(alphaArray[i]);
      mpz_init(u1[i]);
      mpz_init(u2[i]);
    }

    // generate \alphas
    for (int i = 0; i < verifySize; ++i)
    {
      mpz_urandomm(alphaArray[i], verifyRandomState, field_size);
    }

    // local mult
    for (int i = 0; i < verifySize; ++i)
    {
      mpz_mul(u1[i], alphaArray[i], a[1][i]);
      mpz_mul(u2[i], alphaArray[i], a[0][i]);
      mpz_mod(u1[i], u1[i], field_size);
      mpz_mod(u2[i], u2[i], field_size);
    }

    for (int i = 0; i < verifySize; ++i)
    {
      mpz_add(sum1, sum1, u1[i]);
      mpz_add(sum2, sum2, u2[i]);
      mpz_mod(sum1, sum1, field_size);
      mpz_mod(sum2, sum2, field_size);
    }

    for (int i = 0; i < verifySize; i++)
    {
      mpz_clear(alphaArray[i]);
      mpz_clear(u1[i]);
      mpz_clear(u2[i]);
    }

    free(alphaArray);
    free(u1);
    free(u2);
  }

  Mul->doOperation(&sum2, &r, &sum2, 1, -1);
  mpz_sub(sum2, sum2, sum1);
  mpz_mod(sum2, sum2, field_size);

  mpz_t zerochk_rand[1];
  mpz_init(zerochk_rand[0]);
  rand->generateRandValue(config->getID(), config->getBits(), 1, zerochk_rand);
  Mul->doOperation(&sum2, &zerochk_rand[0], &sum2, 1, -1);
  mpz_clear(zerochk_rand[0]);

  int checkResult = Open_N(sum2, NULL, -1, net, id, ss);

  malBufferReset();
  verify_count++;

  if(checkResult == 0)
  {
    //printf("Successful on run %i\n", verify_count);
  }
  else
  {
    error_count++;
    //printf("Error on run %i\n", verify_count);
  }

  for (int i = 0; i < 2; i++)
  {
    for (int j = 0; j < verifySize; j++)
      mpz_clear(a[i][j]);
    free(a[i]);
  }
  free(a);

  gettimeofday(&end, NULL);
  VerificationTimer += 1000000 * (end.tv_sec - start.tv_sec) + end.tv_usec - start.tv_usec;
}

void MaliciousSMC::malBufferReset()
{
  curRow_mal = 0;
  curPoint_mal = 0;
  curCapacity_mal = curCap_mal * rowCap_mal;
}

void MaliciousSMC::clean_mal()
{
  //printf("total verification time is %ld us\n", VerificationTimer);
  printf("%i verification errors out of %i runs\n", error_count, verify_count);
  mpz_clear(r);

  for (int i = 0; i < 2 * curCap_mal; i++)
  {
    for (int j = 0; j < rowCap_mal; j++)
      mpz_clear(buffer_mal[i][j]);
    free(buffer_mal[i]);
  }
  free(buffer_mal);

  if (rand_state_initialized)
  {
    gmp_randclear(verifyRandomState);
    mpz_clear(rand_seed[0]);
    free(rand_seed);
  }

  printf("End Malicious Mode\n");
}


void MaliciousSMC::check_ver(mpz_t **buf, int buf_size)
{
  mpz_t *rbuf = (mpz_t *) malloc(sizeof(mpz_t) * buf_size);
  mpz_t *randomized_buf = (mpz_t *) malloc(sizeof(mpz_t) * buf_size);
  for (int i = 0; i < buf_size; i++)
  {
    mpz_init_set(rbuf[i], r);
    mpz_init(randomized_buf[i]);
  }

  Mul->doOperation(randomized_buf, buf[0], rbuf, buf_size, -1);
  ss->modSub(rbuf, randomized_buf, buf[1], buf_size);
  show(rbuf, buf_size, net, id, ss);

  for (int i = 0; i < buf_size; i++)
  {
    mpz_clear(rbuf[i]);
    mpz_clear(randomized_buf[i]);
  }
  free(rbuf);
  free(randomized_buf);
}


//TODO put in SecretShare.cpp
void MaliciousSMC::computeLagrangeWeight_mal()
{
  mpz_t nom, denom, t1, t2, temp;
  mpz_init(nom);
  mpz_init(denom);
  mpz_init(t1);
  mpz_init(t2);
  mpz_init(temp);

  lagrangeWeight_mal = (mpz_t **) malloc(sizeof(mpz_t *) * peers);

  for (int i = 0; i < peers; i++)
  {
    lagrangeWeight_mal[i] = (mpz_t *) malloc(sizeof(mpz_t) * peers);
    for (int j = 0; j < peers; ++j)
    {
      mpz_init(lagrangeWeight_mal[i][j]);
    }
  }
  for (int peer = 0; peer < peers; peer++)
  {
    for (int count = 1; count <= 2; count++)
    {
      int point = peer + 1;
      mpz_set_ui(nom, 1);
      mpz_set_ui(denom, 1);

      int l = (peer + count) % 3;
      mpz_set_ui(t1, l + 1);
      mpz_set_ui(t2, point);
      ss->modSub(temp, t1, t2);
      ss->modInv(denom, temp);

      ss->modMul(lagrangeWeight_mal[peer][l], denom, t1);
      // gmp_printf ("lagrangeWeight of [%d][%d] is %Zd\n",  peer, l, lagrangeWeight_mal[peer][l]);
    }
  }

  mpz_clear(nom);
  mpz_clear(denom);
  mpz_clear(t1);
  mpz_clear(t2);
  mpz_clear(temp);
}


//TODO put in SecretShare.cpp
void MaliciousSMC::reconstructSecretCheck(mpz_t *result, mpz_t **y, int size, bool isMultiply)
{
  mpz_t temp;
  mpz_init(temp);
  mpz_t preResult;
  mpz_init(preResult);

  for (int i = 0; i < size; i++)
    mpz_set_ui(result[i], 0);
  for (int i = 0; i < size; i++)
  {
    for (int j = 0; j < peers; ++j)
    {
      int curPoint = (j - 1 + peers) % peers;
      int nextPoint = (j + 1) % peers;
      ss->modMul(temp, y[curPoint][i], lagrangeWeight_mal[curPoint][nextPoint]);
      ss->modAdd(preResult, preResult, temp);
      ss->modMul(temp, y[nextPoint][i], lagrangeWeight_mal[nextPoint][curPoint]);
      ss->modAdd(preResult, preResult, temp);
      mpz_set(result[i], preResult);
      mpz_set_ui(preResult, 0);
      // gmp_printf ("result at is %Zd\n", result[i]);
    }
  }
  mpz_clear(temp);
  mpz_clear(preResult);
}


