
#include "BitLT.h"

BitLT::BitLT(NodeNetwork nodeNet, std::map<std::string, std::vector<int>> poly, int NodeID, SecretShare *s, mpz_t coeficients[], Mult *M)
{
  Mul = M;
  net = nodeNet;
  id = NodeID;
  ss = s;
  //D = new Debug();
}

BitLT::BitLT(NodeNetwork nodeNet, std::map<std::string, std::vector<int>> poly, int NodeID, SecretShare *s, mpz_t coeficients[], MaliciousSMC *malicious, Mult *M)
{
  Mul = M;
  ms = malicious;
  net = nodeNet;
  id = NodeID;
  ss = s;
}

BitLT::~BitLT() {}



void BitLT::doOperation(mpz_t *A, mpz_t *B, mpz_t Result, int size, int threadID)
{
  mpz_t *mult_Buff1 = (mpz_t *) malloc(sizeof(mpz_t) * size);
  mpz_t *mult_Buff2 = (mpz_t *) malloc(sizeof(mpz_t) * size);
  mpz_t *mult_Buff3 = (mpz_t *) malloc(sizeof(mpz_t) * size);

  for (int i = 0; i < size; i++)
  {
    mpz_init(mult_Buff1[i]);
    mpz_init(mult_Buff2[i]);
    mpz_init(mult_Buff3[i]);
  }

  mpz_t *s = (mpz_t *) malloc(sizeof(mpz_t) * size);
  mpz_t *o = (mpz_t *) malloc(sizeof(mpz_t) * size);
  for (int j = 0; j < size; j++)
  {
    mpz_init(s[j]);
    mpz_init(o[j]);
  }

  int buff_p1 = 0;
  int buff_p2 = 0;
  for (int j = 0; j < size; ++j)
  {
    mpz_set(mult_Buff1[buff_p1], A[j]);
    mpz_set(mult_Buff2[buff_p1++], B[j]);
  }

  Mul->doOperation(mult_Buff3, mult_Buff1, mult_Buff2, size, threadID);

  for (int j = 0; j < size; ++j)
  {
    mpz_set(o[j], B[j]);
    ss->modSub(o[j], o[j], mult_Buff3[buff_p2]);
    ss->modMul(s[j], mult_Buff3[buff_p2++], 2);
    ss->modAdd(s[j], s[j], 1);
    ss->modSub(s[j], s[j], A[j]);
    ss->modSub(s[j], s[j], B[j]);
  }

  recursiveOp(s, o, size, threadID);

  mpz_set(Result, o[0]);

  // clear
  for (int j = 0; j < size; j++)
  {
    mpz_clear(s[j]);
    mpz_clear(o[j]);
  }
  free(s);
  free(o);

  for (int i = 0; i < size; i++)
  {
    mpz_clear(mult_Buff1[i]);
    mpz_clear(mult_Buff2[i]);
    mpz_clear(mult_Buff3[i]);
  }
  free(mult_Buff1);
  free(mult_Buff2);
  free(mult_Buff3);
}

void BitLT::recursiveOp(mpz_t *s, mpz_t *o, int size, int threadID)
{
  int rounds = (int) (log2(size));
  int maxMulSize = size / 2 * 3;
  mpz_t *mult_Buff1 = (mpz_t *) malloc(sizeof(mpz_t) * maxMulSize);
  mpz_t *mult_Buff2 = (mpz_t *) malloc(sizeof(mpz_t) * maxMulSize);
  mpz_t *mult_Buff3 = (mpz_t *) malloc(sizeof(mpz_t) * maxMulSize);

  for (int i = 0; i < maxMulSize; i++)
  {
    mpz_init(mult_Buff1[i]);
    mpz_init(mult_Buff2[i]);
    mpz_init(mult_Buff3[i]);
  }

  int buff_p1 = 0;
  int buff_p2 = 0;
  int y = 0;

  int curSize = size;
  while (curSize != 1)
  {
    int curMulSize = curSize / 2;
    buff_p1 = 0;
    buff_p2 = 0;
    for (int j = 0; j < curMulSize; ++j)
    {
      mpz_set(mult_Buff1[buff_p1], s[2 * j]);
      mpz_set(mult_Buff2[buff_p1++], s[2 * j + 1]);

      mpz_set(mult_Buff1[buff_p1], s[2 * j + 1]);
      mpz_set(mult_Buff2[buff_p1++], o[2 * j + 1]);

      mpz_set(mult_Buff1[buff_p1], s[2 * j + 1]);
      mpz_set(mult_Buff2[buff_p1++], o[2 * j]);
    }

    Mul->doOperation(mult_Buff3, mult_Buff1, mult_Buff2, curMulSize * 3, threadID);

    for (int j = 0; j < curMulSize; ++j)
    {
      mpz_set(s[j], mult_Buff3[buff_p2++]);
      mpz_set(o[j], o[2 * j + 1]);

      ss->modSub(o[j], o[j], mult_Buff3[buff_p2++]);
      ss->modAdd(o[j], o[j], mult_Buff3[buff_p2++]);
    }

    if (curSize % 2 == 1)
    {
      mpz_set(s[curMulSize], s[curSize - 1]);
      mpz_set(o[curMulSize], o[curSize - 1]);
    }
    curSize = curSize / 2 + curSize % 1;
  }

  // clear
  for (int i = 0; i < maxMulSize; i++)
  {
    mpz_clear(mult_Buff1[i]);
    mpz_clear(mult_Buff2[i]);
    mpz_clear(mult_Buff3[i]);
  }
  free(mult_Buff1);
  free(mult_Buff2);
  free(mult_Buff3);
}




void BitLT::doOperation(mpz_t **A, mpz_t **B, mpz_t *Result, int size, int batch_size, int threadID)
{
  mpz_t *mult_Buff1 = (mpz_t *) malloc(sizeof(mpz_t) * size * batch_size);
  mpz_t *mult_Buff2 = (mpz_t *) malloc(sizeof(mpz_t) * size * batch_size);
  mpz_t *mult_Buff3 = (mpz_t *) malloc(sizeof(mpz_t) * size * batch_size);

  mpz_t **s = (mpz_t **) malloc(sizeof(mpz_t *) * batch_size);
  mpz_t **o = (mpz_t **) malloc(sizeof(mpz_t *) * batch_size);

  for (int i = 0; i < batch_size * size; i++)
  {
    mpz_init(mult_Buff1[i]);
    mpz_init(mult_Buff2[i]);
    mpz_init(mult_Buff3[i]);
  }

  for (int i = 0; i < batch_size; i++)
  {
    s[i] = (mpz_t *) malloc(sizeof(mpz_t) * size);
    o[i] = (mpz_t *) malloc(sizeof(mpz_t) * size);
    for (int j = 0; j < size; j++)
    {
      mpz_init(s[i][j]);
      mpz_init(o[i][j]);
    }
  }

  int buff_p1 = 0;
  int buff_p2 = 0;
  for (int i = 0; i < batch_size; ++i)
  {
    for (int j = 0; j < size; ++j)
    {
      mpz_set(mult_Buff1[buff_p1], A[i][j]);
      mpz_set(mult_Buff2[buff_p1++], B[i][j]);
    }
  }

  Mul->doOperation(mult_Buff3, mult_Buff1, mult_Buff2, size * batch_size, threadID);

  for (int i = 0; i < batch_size; ++i)
  {
    for (int j = 0; j < size; ++j)
    {
      mpz_set(o[i][j], B[i][j]);
      ss->modSub(o[i][j], o[i][j], mult_Buff3[buff_p2]);
      ss->modMul(s[i][j], mult_Buff3[buff_p2++], 2);
      ss->modAdd(s[i][j], s[i][j], 1);
      ss->modSub(s[i][j], s[i][j], A[i][j]);
      ss->modSub(s[i][j], s[i][j], B[i][j]);
    }
  }

  recursiveOp(s, o, size, batch_size, threadID);

  for (int i = 0; i < batch_size; ++i)
  {
    mpz_set(Result[i], o[i][0]);
  }

  // clear
  for (int i = 0; i < batch_size; i++)
  {
    for (int j = 0; j < size; j++)
    {
      mpz_clear(s[i][j]);
      mpz_clear(o[i][j]);
    }
    free(s[i]);
    free(o[i]);
  }
  free(s);
  free(o);

  for (int i = 0; i < size * batch_size; i++)
  {
    mpz_clear(mult_Buff1[i]);
    mpz_clear(mult_Buff2[i]);
    mpz_clear(mult_Buff3[i]);
  }
  free(mult_Buff1);
  free(mult_Buff2);
  free(mult_Buff3);
}

void BitLT::recursiveOp(mpz_t **s, mpz_t **o, int size, int batch_size, int threadID)
{
  // size represent bit len of a bitwise value, batch_size represents how many such values.
  int rounds = (int)(log2(size));
  int maxMulSize = batch_size * (size / 2 * 3);
  mpz_t *mult_Buff1 = (mpz_t *) malloc(sizeof(mpz_t) * maxMulSize);
  mpz_t *mult_Buff2 = (mpz_t *) malloc(sizeof(mpz_t) * maxMulSize);
  mpz_t *mult_Buff3 = (mpz_t *) malloc(sizeof(mpz_t) * maxMulSize);

  for (int i = 0; i < maxMulSize; i++)
  {
    mpz_init(mult_Buff1[i]);
    mpz_init(mult_Buff2[i]);
    mpz_init(mult_Buff3[i]);
  }

  int buff_p1 = 0;
  int buff_p2 = 0;
  int y = 0;

  int curSize = size;
  while (curSize != 1)
  {
    int curMulSize = curSize / 2;
    buff_p1 = 0;
    buff_p2 = 0;
    for (int i = 0; i < batch_size; ++i)
    {
      for (int j = 0; j < curMulSize; ++j)
      {
        mpz_set(mult_Buff1[buff_p1], s[i][2 * j]);
        mpz_set(mult_Buff2[buff_p1++], s[i][2 * j + 1]);

        mpz_set(mult_Buff1[buff_p1], s[i][2 * j + 1]);
        mpz_set(mult_Buff2[buff_p1++], o[i][2 * j + 1]);

        mpz_set(mult_Buff1[buff_p1], s[i][2 * j + 1]);
        mpz_set(mult_Buff2[buff_p1++], o[i][2 * j]);
      }
    }

    Mul->doOperation(mult_Buff3, mult_Buff1, mult_Buff2, curMulSize * 3 * batch_size, threadID);

    for (int i = 0; i < batch_size; ++i)
    {
      for (int j = 0; j < curMulSize; ++j)
      {
        mpz_set(s[i][j], mult_Buff3[buff_p2++]);
        mpz_set(o[i][j], o[i][2 * j + 1]);

        ss->modSub(o[i][j], o[i][j], mult_Buff3[buff_p2++]);
        ss->modAdd(o[i][j], o[i][j], mult_Buff3[buff_p2++]);
      }
    }

    if (curSize % 2 == 1)
    {
      for (int i = 0; i < batch_size; ++i)
      {
        mpz_set(s[i][curMulSize], s[i][curSize - 1]);
        mpz_set(o[i][curMulSize], o[i][curSize - 1]);
      }
    }
    curSize = curSize / 2 + curSize % 1;
  }

  // clear
  for (int i = 0; i < maxMulSize; i++)
  {
    mpz_clear(mult_Buff1[i]);
    mpz_clear(mult_Buff2[i]);
    mpz_clear(mult_Buff3[i]);
  }
  free(mult_Buff1);
  free(mult_Buff2);
  free(mult_Buff3);
}





void BitLT::doOperation_mal(mpz_t **A, mpz_t **B, mpz_t *Result, int size, int threadID)
{
  mpz_t *mult_Buff1 = (mpz_t *) malloc(sizeof(mpz_t) * size * 2);
  mpz_t *mult_Buff2 = (mpz_t *) malloc(sizeof(mpz_t) * size * 2);
  mpz_t *mult_Buff3 = (mpz_t *) malloc(sizeof(mpz_t) * size * 2);

  for (int i = 0; i < size * 2; i++)
  {
    mpz_init(mult_Buff1[i]);
    mpz_init(mult_Buff2[i]);
    mpz_init(mult_Buff3[i]);
  }

  mpz_t **s = (mpz_t **) malloc(sizeof(mpz_t *) * 2);
  mpz_t **o = (mpz_t **) malloc(sizeof(mpz_t *) * 2);

  for (int mi = 0; mi < 2; mi++)
  {
    s[mi] = (mpz_t *) malloc(sizeof(mpz_t) * size);
    o[mi] = (mpz_t *) malloc(sizeof(mpz_t) * size);

    for (int j = 0; j < size; j++)
    {
      mpz_init(s[mi][j]);
      mpz_init(o[mi][j]);
    }
  }

  int buff_p1 = 0;
  int buff_p2 = 0;
  for (int j = 0; j < size; ++j)
  {
    mpz_set(mult_Buff1[buff_p1], A[0][j]);
    mpz_set(mult_Buff2[buff_p1++], B[0][j]);
  }

  for (int j = 0; j < size; ++j)
  {
    mpz_set(mult_Buff1[buff_p1], A[0][j]);
    mpz_set(mult_Buff2[buff_p1++], B[1][j]);
  }

  Mul->doOperation(mult_Buff3, mult_Buff1, mult_Buff2, size * 2, threadID);
  ms->pushBuffer(mult_Buff3, &mult_Buff3[size], size);

  for (int j = 0; j < size; ++j)
  {
    mpz_set(o[0][j], B[0][j]);
    ss->modSub(o[0][j], o[0][j], mult_Buff3[buff_p2]);
    ss->modMul(s[0][j], mult_Buff3[buff_p2], 2);
    ss->modAdd(s[0][j], s[0][j], 1);
    ss->modSub(s[0][j], s[0][j], A[0][j]);
    ss->modSub(s[0][j], s[0][j], B[0][j]);

    mpz_set(o[1][j], B[1][j]);
    ss->modSub(o[1][j], o[1][j], mult_Buff3[buff_p2 + size]);
    ss->modMul(s[1][j], mult_Buff3[buff_p2 + size], 2);
    ss->modAdd(s[1][j], s[1][j], ms->r);
    ss->modSub(s[1][j], s[1][j], A[1][j]);
    ss->modSub(s[1][j], s[1][j], B[1][j]);

    buff_p2++;
  }

  recursiveOp_mal(s, o, size, threadID);

  mpz_set(Result[0], o[0][0]);
  mpz_set(Result[1], o[1][0]);

  // clear
  for (int mi = 0; mi < 2; ++mi)
  {
    for (int j = 0; j < size; j++)
    {
      mpz_clear(s[mi][j]);
      mpz_clear(o[mi][j]);
    }
    free(s[mi]);
    free(o[mi]);
  }
  free(s);
  free(o);

  for (int i = 0; i < size * 2; i++)
  {
    mpz_clear(mult_Buff1[i]);
    mpz_clear(mult_Buff2[i]);
    mpz_clear(mult_Buff3[i]);
  }
  free(mult_Buff1);
  free(mult_Buff2);
  free(mult_Buff3);
}

void BitLT::recursiveOp_mal(mpz_t **s, mpz_t **o, int size, int threadID)
{
  int rounds = (int) (log2(size));
  int maxMulSize = size / 2 * 3;
  mpz_t *mult_Buff1 = (mpz_t *) malloc(sizeof(mpz_t) * maxMulSize * 2);
  mpz_t *mult_Buff2 = (mpz_t *) malloc(sizeof(mpz_t) * maxMulSize * 2);
  mpz_t *mult_Buff3 = (mpz_t *) malloc(sizeof(mpz_t) * maxMulSize * 2);

  for (int i = 0; i < maxMulSize * 2; i++)
  {
    mpz_init(mult_Buff1[i]);
    mpz_init(mult_Buff2[i]);
    mpz_init(mult_Buff3[i]);
  }

  int buff_p1 = 0;
  int buff_p2 = 0;
  int y = 0;

  int curSize = size;
  while (curSize != 1)
  {
    int curMulSize = curSize / 2;
    buff_p1 = 0;
    buff_p2 = 0;
    for (int j = 0; j < curMulSize; ++j)
    {
      mpz_set(mult_Buff1[buff_p1], s[0][2 * j]);
      mpz_set(mult_Buff2[buff_p1++], s[0][2 * j + 1]);

      mpz_set(mult_Buff1[buff_p1], s[0][2 * j + 1]);
      mpz_set(mult_Buff2[buff_p1++], o[0][2 * j + 1]);

      mpz_set(mult_Buff1[buff_p1], s[0][2 * j + 1]);
      mpz_set(mult_Buff2[buff_p1++], o[0][2 * j]);
    }

    for (int j = 0; j < curMulSize; ++j)
    {
      mpz_set(mult_Buff1[buff_p1], s[0][2 * j]);
      mpz_set(mult_Buff2[buff_p1++], s[1][2 * j + 1]);

      mpz_set(mult_Buff1[buff_p1], s[0][2 * j + 1]);
      mpz_set(mult_Buff2[buff_p1++], o[1][2 * j + 1]);

      mpz_set(mult_Buff1[buff_p1], s[0][2 * j + 1]);
      mpz_set(mult_Buff2[buff_p1++], o[1][2 * j]);
    }

    Mul->doOperation(mult_Buff3, mult_Buff1, mult_Buff2, 2 * curMulSize * 3, threadID);
    ms->pushBuffer(mult_Buff3, &mult_Buff3[curMulSize * 3], curMulSize * 3);

    for (int j = 0; j < curMulSize; ++j)
    {
      mpz_set(s[0][j], mult_Buff3[buff_p2]);
      mpz_set(o[0][j], o[0][2 * j + 1]);
      mpz_set(s[1][j], mult_Buff3[buff_p2 + curMulSize * 3]);
      mpz_set(o[1][j], o[1][2 * j + 1]);
      buff_p2++;

      ss->modSub(o[0][j], o[0][j], mult_Buff3[buff_p2]);
      ss->modSub(o[1][j], o[1][j], mult_Buff3[buff_p2 + curMulSize * 3]);
      buff_p2++;
      ss->modAdd(o[0][j], o[0][j], mult_Buff3[buff_p2]);
      ss->modAdd(o[1][j], o[1][j], mult_Buff3[buff_p2 + curMulSize * 3]);
      buff_p2++;
    }

    if (curSize % 2 == 1)
    {
      mpz_set(s[0][curMulSize], s[0][curSize - 1]);
      mpz_set(o[0][curMulSize], o[0][curSize - 1]);

      mpz_set(s[1][curMulSize], s[1][curSize - 1]);
      mpz_set(o[1][curMulSize], o[1][curSize - 1]);
    }
    curSize = curSize / 2 + curSize % 1;
  }

  // clear
  for (int i = 0; i < maxMulSize * 2; i++)
  {
    mpz_clear(mult_Buff1[i]);
    mpz_clear(mult_Buff2[i]);
    mpz_clear(mult_Buff3[i]);
  }
  free(mult_Buff1);
  free(mult_Buff2);
  free(mult_Buff3);
}





void BitLT::doOperation_mal(mpz_t ***A, mpz_t ***B, mpz_t **Result, int size, int batch_size, int threadID)
{
  mpz_t *mult_Buff1 = (mpz_t *) malloc(sizeof(mpz_t) * size * batch_size * 2);
  mpz_t *mult_Buff2 = (mpz_t *) malloc(sizeof(mpz_t) * size * batch_size * 2);
  mpz_t *mult_Buff3 = (mpz_t *) malloc(sizeof(mpz_t) * size * batch_size * 2);

  for (int i = 0; i < batch_size * size * 2; i++)
  {
    mpz_init(mult_Buff1[i]);
    mpz_init(mult_Buff2[i]);
    mpz_init(mult_Buff3[i]);
  }

  mpz_t ***s = (mpz_t ***) malloc(sizeof(mpz_t **) * 2);
  mpz_t ***o = (mpz_t ***) malloc(sizeof(mpz_t **) * 2);

  for (int mi = 0; mi < 2; mi++)
  {
    s[mi] = (mpz_t **) malloc(sizeof(mpz_t *) * batch_size);
    o[mi] = (mpz_t **) malloc(sizeof(mpz_t *) * batch_size);

    for (int i = 0; i < batch_size; i++)
    {
      s[mi][i] = (mpz_t *) malloc(sizeof(mpz_t) * size);
      o[mi][i] = (mpz_t *) malloc(sizeof(mpz_t) * size);

      for (int j = 0; j < size; j++)
      {
        mpz_init(s[mi][i][j]);
        mpz_init(o[mi][i][j]);
      }
    }
  }

  int buff_p1 = 0;
  int buff_p2 = 0;
  for (int i = 0; i < batch_size; ++i)
  {
    for (int j = 0; j < size; ++j)
    {
      mpz_set(mult_Buff1[buff_p1], A[0][i][j]);
      mpz_set(mult_Buff2[buff_p1++], B[0][i][j]);
    }
  }

  for (int i = 0; i < batch_size; ++i)
  {
    for (int j = 0; j < size; ++j)
    {
      mpz_set(mult_Buff1[buff_p1], A[0][i][j]);
      mpz_set(mult_Buff2[buff_p1++], B[1][i][j]);
    }
  }

  Mul->doOperation(mult_Buff3, mult_Buff1, mult_Buff2, size * batch_size * 2, threadID);
  ms->pushBuffer(mult_Buff3, &mult_Buff3[size * batch_size], size * batch_size);

  for (int i = 0; i < batch_size; ++i)
  {
    for (int j = 0; j < size; ++j)
    {
      mpz_set(o[0][i][j], B[0][i][j]);
      ss->modSub(o[0][i][j], o[0][i][j], mult_Buff3[buff_p2]);
      ss->modMul(s[0][i][j], mult_Buff3[buff_p2], 2);
      ss->modAdd(s[0][i][j], s[0][i][j], 1);
      ss->modSub(s[0][i][j], s[0][i][j], A[0][i][j]);
      ss->modSub(s[0][i][j], s[0][i][j], B[0][i][j]);

      mpz_set(o[1][i][j], B[1][i][j]);
      ss->modSub(o[1][i][j], o[1][i][j], mult_Buff3[buff_p2 + size * batch_size]);
      ss->modMul(s[1][i][j], mult_Buff3[buff_p2 + size * batch_size], 2);
      ss->modAdd(s[1][i][j], s[1][i][j], ms->r);
      ss->modSub(s[1][i][j], s[1][i][j], A[1][i][j]);
      ss->modSub(s[1][i][j], s[1][i][j], B[1][i][j]);

      buff_p2++;
    }
  }

  recursiveOp_mal(s, o, size, batch_size, threadID);

  for (int i = 0; i < batch_size; ++i)
  {
    mpz_set(Result[0][i], o[0][i][0]);
    mpz_set(Result[1][i], o[1][i][0]);
  }

  // clear
  for (int mi = 0; mi < 2; ++mi)
  {
    for (int i = 0; i < batch_size; i++)
    {
      for (int j = 0; j < size; j++)
      {
        mpz_clear(s[mi][i][j]);
        mpz_clear(o[mi][i][j]);
      }
      free(s[mi][i]);
      free(o[mi][i]);
    }
    free(s[mi]);
    free(o[mi]);
  }
  free(s);
  free(o);

  for (int i = 0; i < size * batch_size * 2; i++)
  {
    mpz_clear(mult_Buff1[i]);
    mpz_clear(mult_Buff2[i]);
    mpz_clear(mult_Buff3[i]);
  }
  free(mult_Buff1);
  free(mult_Buff2);
  free(mult_Buff3);
}

void BitLT::recursiveOp_mal(mpz_t ***s, mpz_t ***o, int size, int batch_size, int threadID)
{
  // size represents the bit length of a bitwise value, batch_size represents how many such values.
  int rounds = (int)(log2(size));
  int maxMulSize = batch_size * (size / 2 * 3);
  mpz_t *mult_Buff1 = (mpz_t *) malloc(sizeof(mpz_t) * maxMulSize * 2);
  mpz_t *mult_Buff2 = (mpz_t *) malloc(sizeof(mpz_t) * maxMulSize * 2);
  mpz_t *mult_Buff3 = (mpz_t *) malloc(sizeof(mpz_t) * maxMulSize * 2);

  for (int i = 0; i < maxMulSize * 2; i++)
  {
    mpz_init(mult_Buff1[i]);
    mpz_init(mult_Buff2[i]);
    mpz_init(mult_Buff3[i]);
  }

  int buff_p1 = 0;
  int buff_p2 = 0;
  int y = 0;

  int curSize = size;
  while (curSize != 1)
  {
    int curMulSize = curSize / 2;
    buff_p1 = 0;
    buff_p2 = 0;
    for (int i = 0; i < batch_size; ++i)
    {
      for (int j = 0; j < curMulSize; ++j)
      {
        mpz_set(mult_Buff1[buff_p1], s[0][i][2 * j]);
        mpz_set(mult_Buff2[buff_p1++], s[0][i][2 * j + 1]);

        mpz_set(mult_Buff1[buff_p1], s[0][i][2 * j + 1]);
        mpz_set(mult_Buff2[buff_p1++], o[0][i][2 * j + 1]);

        mpz_set(mult_Buff1[buff_p1], s[0][i][2 * j + 1]);
        mpz_set(mult_Buff2[buff_p1++], o[0][i][2 * j]);
      }
    }

    for (int i = 0; i < batch_size; ++i)
    {
      for (int j = 0; j < curMulSize; ++j)
      {
        mpz_set(mult_Buff1[buff_p1], s[0][i][2 * j]);
        mpz_set(mult_Buff2[buff_p1++], s[1][i][2 * j + 1]);

        mpz_set(mult_Buff1[buff_p1], s[0][i][2 * j + 1]);
        mpz_set(mult_Buff2[buff_p1++], o[1][i][2 * j + 1]);

        mpz_set(mult_Buff1[buff_p1], s[0][i][2 * j + 1]);
        mpz_set(mult_Buff2[buff_p1++], o[1][i][2 * j]);
      }
    }

    Mul->doOperation(mult_Buff3, mult_Buff1, mult_Buff2, 2 * curMulSize * 3 * batch_size, threadID);
    ms->pushBuffer(mult_Buff3, &mult_Buff3[curMulSize * 3 * batch_size], curMulSize * 3 * batch_size);

    for (int i = 0; i < batch_size; ++i)
    {
      for (int j = 0; j < curMulSize; ++j)
      {
        mpz_set(s[0][i][j], mult_Buff3[buff_p2]);
        mpz_set(o[0][i][j], o[0][i][2 * j + 1]);
        mpz_set(s[1][i][j], mult_Buff3[buff_p2 + curMulSize * 3 * batch_size]);
        mpz_set(o[1][i][j], o[1][i][2 * j + 1]);
        buff_p2++;

        ss->modSub(o[0][i][j], o[0][i][j], mult_Buff3[buff_p2]);
        ss->modSub(o[1][i][j], o[1][i][j], mult_Buff3[buff_p2 + curMulSize * 3 * batch_size]);
        buff_p2++;
        ss->modAdd(o[0][i][j], o[0][i][j], mult_Buff3[buff_p2]);
        ss->modAdd(o[1][i][j], o[1][i][j], mult_Buff3[buff_p2 + curMulSize * 3 * batch_size]);
        buff_p2++;
      }
    }

    if (curSize % 2 == 1)
    {
      for (int i = 0; i < batch_size; ++i)
      {
        mpz_set(s[0][i][curMulSize], s[0][i][curSize - 1]);
        mpz_set(o[0][i][curMulSize], o[0][i][curSize - 1]);

        mpz_set(s[1][i][curMulSize], s[1][i][curSize - 1]);
        mpz_set(o[1][i][curMulSize], o[1][i][curSize - 1]);
      }
    }
    curSize = curSize / 2 + curSize % 1;
  }

  // clear
  for (int i = 0; i < maxMulSize * 2; i++)
  {
    mpz_clear(mult_Buff1[i]);
    mpz_clear(mult_Buff2[i]);
    mpz_clear(mult_Buff3[i]);
  }
  free(mult_Buff1);
  free(mult_Buff2);
  free(mult_Buff3);
}

