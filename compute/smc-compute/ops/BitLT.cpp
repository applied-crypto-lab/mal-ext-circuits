
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
  //D = new Debug();
}

BitLT::~BitLT() {}



void BitLT::doOperation(mpz_t *A, mpz_t *B, mpz_t Result, int size, int threadID)
{
  //show(A, size, net, id, ss);
  //show(B, size, net, id, ss);

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
    ss->modSub(B[j], 1, B[j]);
    mpz_set(mult_Buff2[buff_p1++], B[j]);
  }

  Mul->doOperation(mult_Buff3, mult_Buff1, mult_Buff2, size, threadID);

  mpz_t tmp;
  mpz_init(tmp);
  for (int j = 0; j < size; ++j)
  {
    mpz_set(o[j], mult_Buff3[buff_p2]);
    ss->modMul(tmp, mult_Buff3[buff_p2++], 2);
    ss->modAdd(s[j], A[j], B[j]);
    ss->modSub(s[j], s[j], tmp);
  }
  ss->modAdd(o[0], o[0], s[0]);

  recursiveOp(s, o, size, threadID);

  //show(&o[0], 1, net, id, ss);

  ss->modSub(Result, 1, o[0]);

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

  mpz_clear(tmp);
}


void BitLT::recursiveOp(mpz_t *s, mpz_t *o, int size, int threadID)
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
      mpz_set(mult_Buff1[buff_p1], s[2*j + 1]);
      mpz_set(mult_Buff2[buff_p1++], s[2*j]);

      mpz_set(mult_Buff1[buff_p1], s[2*j + 1]);
      mpz_set(mult_Buff2[buff_p1++], o[2*j]);
    }

    Mul->doOperation(mult_Buff3, mult_Buff1, mult_Buff2, curMulSize * 2, threadID);

    for (int j = 0; j < curMulSize; ++j)
    {
      mpz_set(s[j], mult_Buff3[buff_p2++]);
      mpz_set(o[j], o[2*j + 1]);
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



void BitLT::doOperation(mpz_t **A, mpz_t **B, mpz_t *Result, int size, int batch_size, int threadID)
{
  //show(A[0], size, net, id, ss);
  //show(B[0], size, net, id, ss);

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
      ss->modSub(B[i][j], 1, B[i][j]);
      mpz_set(mult_Buff2[buff_p1++], B[i][j]);
    }
  }

  Mul->doOperation(mult_Buff3, mult_Buff1, mult_Buff2, size * batch_size, threadID);

  mpz_t tmp;
  mpz_init(tmp);
  for (int i = 0; i < batch_size; ++i)
  {
    for (int j = 0; j < size; ++j)
    {
      mpz_set(o[i][j], mult_Buff3[buff_p2]);
      ss->modMul(tmp, mult_Buff3[buff_p2++], 2);
      ss->modAdd(s[i][j], A[i][j], B[i][j]);
      ss->modSub(s[i][j], s[i][j], tmp);
    }
    ss->modAdd(o[i][0], o[i][0], s[i][0]);
  }

  recursiveOp(s, o, size, batch_size, threadID);

  for (int i = 0; i < batch_size; ++i)
  {
    ss->modSub(Result[i], 1, o[i][0]);
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

  mpz_clear(tmp);

  //show(Result, batch_size, net, id, ss);
}


void BitLT::recursiveOp(mpz_t **s, mpz_t **o, int size, int batch_size, int threadID)
{
  // size represent bit len of a bitwise value, batch_size represents how many such values.
  mpz_t *mult_Buff1 = (mpz_t *) malloc(sizeof(mpz_t) * size * batch_size);
  mpz_t *mult_Buff2 = (mpz_t *) malloc(sizeof(mpz_t) * size * batch_size);
  mpz_t *mult_Buff3 = (mpz_t *) malloc(sizeof(mpz_t) * size * batch_size);

  for (int i = 0; i < size * batch_size; i++)
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
        mpz_set(mult_Buff1[buff_p1], s[i][2*j + 1]);
        mpz_set(mult_Buff2[buff_p1++], s[i][2*j]);

        mpz_set(mult_Buff1[buff_p1], s[i][2*j + 1]);
        mpz_set(mult_Buff2[buff_p1++], o[i][2*j]);
      }
    }

    Mul->doOperation(mult_Buff3, mult_Buff1, mult_Buff2, curMulSize * 2 * batch_size, threadID);

    for (int i = 0; i < batch_size; ++i)
    {
      for (int j = 0; j < curMulSize; ++j)
      {
        mpz_set(s[i][j], mult_Buff3[buff_p2++]);
        mpz_set(o[i][j], o[i][2*j + 1]);
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
  for (int i = 0; i < size  * batch_size; i++)
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
  //show(A[0], size, net, id, ss);
  //show(B[0], size, net, id, ss);

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
    ss->modSub(B[0][j], 1, B[0][j]);
    mpz_set(mult_Buff2[buff_p1++], B[0][j]);
  }

  for (int j = 0; j < size; ++j)
  {
    mpz_set(mult_Buff1[buff_p1], A[0][j]);
    ss->modSub(B[1][j], ms->r, B[1][j]);
    mpz_set(mult_Buff2[buff_p1++], B[1][j]);
  }

  Mul->doOperation(mult_Buff3, mult_Buff1, mult_Buff2, size * 2, threadID);
  ms->pushBuffer(mult_Buff3, &mult_Buff3[size], size);

  mpz_t tmp;
  mpz_init(tmp);
  for (int j = 0; j < size; ++j)
  {
    mpz_set(o[0][j], mult_Buff3[buff_p2]);
    ss->modMul(tmp, mult_Buff3[buff_p2++], 2);
    ss->modAdd(s[0][j], A[0][j], B[0][j]);
    ss->modSub(s[0][j], s[0][j], tmp);
  }
  ss->modAdd(o[0][0], o[0][0], s[0][0]);

  for (int j = 0; j < size; ++j)
  {
    mpz_set(o[1][j], mult_Buff3[buff_p2]);
    ss->modMul(tmp, mult_Buff3[buff_p2++], 2);
    ss->modAdd(s[1][j], A[1][j], B[1][j]);
    ss->modSub(s[1][j], s[1][j], tmp);
  }
  ss->modAdd(o[1][0], o[1][0], s[1][0]);

  recursiveOp_mal(s, o, size, threadID);

  ss->modSub(Result[0], 1, o[0][0]);
  ss->modSub(Result[1], ms->r, o[1][0]);

  // clear
  for (int mi = 0; mi < 2; mi++)
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

  mpz_clear(tmp);

  //show(Result, 1, net, id, ss);
}


void BitLT::recursiveOp_mal(mpz_t **s, mpz_t **o, int size, int threadID)
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
      mpz_set(mult_Buff1[buff_p1], s[0][2*j + 1]);
      mpz_set(mult_Buff2[buff_p1++], s[0][2*j]);

      mpz_set(mult_Buff1[buff_p1], s[0][2*j + 1]);
      mpz_set(mult_Buff2[buff_p1++], o[0][2*j]);
    }

    for (int j = 0; j < curMulSize; ++j)
    {
      mpz_set(mult_Buff1[buff_p1], s[0][2*j + 1]);
      mpz_set(mult_Buff2[buff_p1++], s[1][2*j]);

      mpz_set(mult_Buff1[buff_p1], s[0][2*j + 1]);
      mpz_set(mult_Buff2[buff_p1++], o[1][2*j]);
    }

    Mul->doOperation(mult_Buff3, mult_Buff1, mult_Buff2, curMulSize * 2 * 2, threadID);
    ms->pushBuffer(mult_Buff3, &mult_Buff3[curMulSize * 2], curMulSize * 2);

    for (int j = 0; j < curMulSize; ++j)
    {
      mpz_set(s[0][j], mult_Buff3[buff_p2++]);
      mpz_set(o[0][j], o[0][2*j + 1]);
      ss->modAdd(o[0][j], o[0][j], mult_Buff3[buff_p2++]);
    }

    for (int j = 0; j < curMulSize; ++j)
    {
      mpz_set(s[1][j], mult_Buff3[buff_p2++]);
      mpz_set(o[1][j], o[1][2*j + 1]);
      ss->modAdd(o[1][j], o[1][j], mult_Buff3[buff_p2++]);
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



void BitLT::doOperation_mal(mpz_t ***A, mpz_t ***B, mpz_t **Result, int size, int batch_size, int threadID)
{
  //show(A[0][0], size, net, id, ss);
  //show(B[0][0], size, net, id, ss);

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
      ss->modSub(B[0][i][j], 1, B[0][i][j]);
      mpz_set(mult_Buff2[buff_p1++], B[0][i][j]);
    }
  }

  for (int i = 0; i < batch_size; ++i)
  {
    for (int j = 0; j < size; ++j)
    {
      mpz_set(mult_Buff1[buff_p1], A[0][i][j]);
      ss->modSub(B[1][i][j], ms->r, B[1][i][j]);
      mpz_set(mult_Buff2[buff_p1++], B[1][i][j]);
    }
  }

  Mul->doOperation(mult_Buff3, mult_Buff1, mult_Buff2, size * batch_size * 2, threadID);
  ms->pushBuffer(mult_Buff3, &mult_Buff3[size * batch_size], size * batch_size);

  mpz_t tmp;
  mpz_init(tmp);
  for (int i = 0; i < batch_size; ++i)
  {
    for (int j = 0; j < size; ++j)
    {
      mpz_set(o[0][i][j], mult_Buff3[buff_p2]);
      ss->modMul(tmp, mult_Buff3[buff_p2++], 2);
      ss->modAdd(s[0][i][j], A[0][i][j], B[0][i][j]);
      ss->modSub(s[0][i][j], s[0][i][j], tmp);
    }
    ss->modAdd(o[0][i][0], o[0][i][0], s[0][i][0]);
  }

  for (int i = 0; i < batch_size; ++i)
  {
    for (int j = 0; j < size; ++j)
    {
      mpz_set(o[1][i][j], mult_Buff3[buff_p2]);
      ss->modMul(tmp, mult_Buff3[buff_p2++], 2);
      ss->modAdd(s[1][i][j], A[1][i][j], B[1][i][j]);
      ss->modSub(s[1][i][j], s[1][i][j], tmp);
    }
    ss->modAdd(o[1][i][0], o[1][i][0], s[1][i][0]);
  }

  recursiveOp_mal(s, o, size, batch_size, threadID);

  for (int i = 0; i < batch_size; ++i)
  {
    ss->modSub(Result[0][i], 1, o[0][i][0]);
    ss->modSub(Result[1][i], ms->r, o[1][i][0]);
  }

  // clear
  for (int mi = 0; mi < 2; mi++)
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

  mpz_clear(tmp);

  //show(Result[0], batch_size, net, id, ss);
}


void BitLT::recursiveOp_mal(mpz_t ***s, mpz_t ***o, int size, int batch_size, int threadID)
{
  // size represent bit len of a bitwise value, batch_size represents how many such values.
  mpz_t *mult_Buff1 = (mpz_t *) malloc(sizeof(mpz_t) * size * batch_size * 2);
  mpz_t *mult_Buff2 = (mpz_t *) malloc(sizeof(mpz_t) * size * batch_size * 2);
  mpz_t *mult_Buff3 = (mpz_t *) malloc(sizeof(mpz_t) * size * batch_size * 2);

  for (int i = 0; i < size * batch_size * 2; i++)
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
        mpz_set(mult_Buff1[buff_p1], s[0][i][2*j + 1]);
        mpz_set(mult_Buff2[buff_p1++], s[0][i][2*j]);

        mpz_set(mult_Buff1[buff_p1], s[0][i][2*j + 1]);
        mpz_set(mult_Buff2[buff_p1++], o[0][i][2*j]);
      }
    }

    for (int i = 0; i < batch_size; ++i)
    {
      for (int j = 0; j < curMulSize; ++j)
      {
        mpz_set(mult_Buff1[buff_p1], s[0][i][2*j + 1]);
        mpz_set(mult_Buff2[buff_p1++], s[1][i][2*j]);

        mpz_set(mult_Buff1[buff_p1], s[0][i][2*j + 1]);
        mpz_set(mult_Buff2[buff_p1++], o[1][i][2*j]);
      }
    }

    Mul->doOperation(mult_Buff3, mult_Buff1, mult_Buff2, curMulSize * 2 * batch_size * 2, threadID);
    ms->pushBuffer(mult_Buff3, &mult_Buff3[curMulSize * 2 * batch_size], curMulSize * 2 * batch_size);

    for (int i = 0; i < batch_size; ++i)
    {
      for (int j = 0; j < curMulSize; ++j)
      {
        mpz_set(s[0][i][j], mult_Buff3[buff_p2++]);
        mpz_set(o[0][i][j], o[0][i][2*j + 1]);
        ss->modAdd(o[0][i][j], o[0][i][j], mult_Buff3[buff_p2++]);
      }
    }

    for (int i = 0; i < batch_size; ++i)
    {
      for (int j = 0; j < curMulSize; ++j)
      {
        mpz_set(s[1][i][j], mult_Buff3[buff_p2++]);
        mpz_set(o[1][i][j], o[1][i][2*j + 1]);
        ss->modAdd(o[1][i][j], o[1][i][j], mult_Buff3[buff_p2++]);
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
  for (int i = 0; i < size  * batch_size * 2; i++)
  {
    mpz_clear(mult_Buff1[i]);
    mpz_clear(mult_Buff2[i]);
    mpz_clear(mult_Buff3[i]);
  }
  free(mult_Buff1);
  free(mult_Buff2);
  free(mult_Buff3);
}





