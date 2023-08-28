
#include "BitAdd.h"

BitAdd::BitAdd(NodeNetwork nodeNet, int NodeID, SecretShare *s, Mult *M)
{
  Mul = M;
  net = nodeNet;
  id = NodeID;
  ss = s;
}

BitAdd::BitAdd(NodeNetwork nodeNet, std::map<std::string, std::vector<int>> poly, int NodeID, SecretShare *s, mpz_t coeficients[], Mult *M)
{
  Mul = M;
  net = nodeNet;
  id = NodeID;
  ss = s;
}

BitAdd::BitAdd(NodeNetwork nodeNet, std::map<std::string, std::vector<int>> poly, int NodeID, SecretShare *s, mpz_t coeficients[], MaliciousSMC *malicious, Mult *M)
{
  Mul = M;
  ms = malicious;
  net = nodeNet;
  id = NodeID;
  ss = s;
}

BitAdd::~BitAdd() {}


void BitAdd::doOperation(mpz_t **input_A, mpz_t **input_B, mpz_t **output, int size, int batch_size, int threadID)
{
  int *sizes = (int *) malloc(sizeof(int) * batch_size);
  for (int i = 0; i < batch_size; i++)
    sizes[i] = size;

  doOperation(input_A, input_B, output, sizes, batch_size, threadID);

  free(sizes);
}



void BitAdd::doOperation(mpz_t **input_A, mpz_t **input_B, mpz_t **output, int *sizes, int batch_size, int threadID)
{
  //show(input_A[0], sizes[0], net, id, ss);
  //show(input_B[0], sizes[0], net, id, ss);

  int sizes_sum = 0;

  for(int i = 0; i < batch_size; i++)
  {
    sizes_sum += sizes[i];
  }

  mpz_t *mult_Buff1 = (mpz_t *) malloc(sizeof(mpz_t) * sizes_sum);
  mpz_t *mult_Buff2 = (mpz_t *) malloc(sizeof(mpz_t) * sizes_sum);
  mpz_t *mult_Buff3 = (mpz_t *) malloc(sizeof(mpz_t) * sizes_sum);

  mpz_t **p = (mpz_t **) malloc(sizeof(mpz_t *) * batch_size);
  mpz_t **p_init = (mpz_t **) malloc(sizeof(mpz_t *) * batch_size);
  mpz_t **g = (mpz_t **) malloc(sizeof(mpz_t *) * batch_size);

  for (int i = 0; i < sizes_sum; i++)
  {
    mpz_init(mult_Buff1[i]);
    mpz_init(mult_Buff2[i]);
    mpz_init(mult_Buff3[i]);
  }

  for (int i = 0; i < batch_size; i++)
  {
    p[i] = (mpz_t *) malloc(sizeof(mpz_t) * sizes[i]);
    p_init[i] = (mpz_t *) malloc(sizeof(mpz_t) * sizes[i]);
    g[i] = (mpz_t *) malloc(sizeof(mpz_t) * sizes[i]);
    for (int j = 0; j < sizes[i]; j++)
    {
      mpz_init(p[i][j]);
      mpz_init(p_init[i][j]);
      mpz_init(g[i][j]);
    }
  }

  mpz_t tmp;
  mpz_init(tmp);
  int buff_p1 = 0;
  int buff_p2 = 0;

  for (int i = 0; i < batch_size; ++i)
  {
    for (int j = 0; j < sizes[i]; ++j)
    {
      mpz_set(mult_Buff1[buff_p1], input_A[i][j]);
      mpz_set(mult_Buff2[buff_p1++], input_B[i][j]);
    }
  }

  Mul->doOperation(mult_Buff3, mult_Buff1, mult_Buff2, buff_p1, threadID);

  for (int i = 0; i < batch_size; ++i)
  {
    for (int j = 0; j < sizes[i]; ++j)
    {
      mpz_set(g[i][j], mult_Buff3[buff_p2++]);
      ss->modAdd(p[i][j], input_A[i][j], input_B[i][j]);
      ss->modMul(tmp, g[i][j], 2);
      ss->modSub(p[i][j], p[i][j], tmp);
      mpz_set(p_init[i][j], p[i][j]);
    }
  }

  prefixCarry(p, g, sizes, batch_size, threadID);

  for (int i = 0; i < batch_size; ++i)
  {
    mpz_set(output[i][0], input_A[i][0]);
    ss->modAdd(output[i][0], output[i][0], input_B[i][0]);
    ss->modMul(tmp, g[i][0], 2);
    ss->modSub(output[i][0], output[i][0], tmp);

    for (int j = 1; j < sizes[i]; ++j)
    {
      mpz_set(output[i][j], input_A[i][j]);
      ss->modAdd(output[i][j], output[i][j], input_B[i][j]);
      ss->modMul(tmp, g[i][j], 2);
      ss->modSub(output[i][j], output[i][j], tmp);
      ss->modAdd(output[i][j], output[i][j], g[i][j - 1]);
    }
  }

  mpz_clear(tmp);

  for (int i = 0; i < batch_size; i++)
  {
    for (int j = 0; j < sizes[i]; j++)
    {
      mpz_clear(p[i][j]);
      mpz_clear(p_init[i][j]);
      mpz_clear(g[i][j]);
    }
    free(p[i]);
    free(p_init[i]);
    free(g[i]);
  }
  free(p);
  free(p_init);
  free(g);

  for (int i = 0; i < sizes_sum; i++)
  {
    mpz_clear(mult_Buff1[i]);
    mpz_clear(mult_Buff2[i]);
    mpz_clear(mult_Buff3[i]);
  }
  free(mult_Buff1);
  free(mult_Buff2);
  free(mult_Buff3);

  //show(output[0], sizes[0], net, id, ss);
}



void BitAdd::prefixCarry(mpz_t **p, mpz_t **g, int *sizes, int batch_size, int threadID)
{
  int sizes_sum = 0;
  int max_size = 0;

  for(int i = 0; i < batch_size; i++)
  {
    sizes_sum += sizes[i];
    max_size = std::max(sizes[i], max_size);
  }

  int rounds = (int) ceil(log2(max_size));

  mpz_t *mult_Buff1 = (mpz_t *) malloc(sizeof(mpz_t) * sizes_sum);
  mpz_t *mult_Buff2 = (mpz_t *) malloc(sizeof(mpz_t) * sizes_sum);
  mpz_t *mult_Buff3 = (mpz_t *) malloc(sizeof(mpz_t) * sizes_sum);

  for (int i = 0; i < sizes_sum; i++)
  {
    mpz_init(mult_Buff1[i]);
    mpz_init(mult_Buff2[i]);
    mpz_init(mult_Buff3[i]);
  }

  int buff_p1 = 0;
  int buff_p2 = 0;
  int y = 0;
  mpz_t tmp;
  mpz_init(tmp);

  for (int i = 0; i < rounds; ++i)
  {
    y = (1 << i) - 1;

    buff_p1 = 0;
    while (y + 2 <= max_size)
    {
      for (int z = 1; z <= (1 << i); ++z)
      {
        for (int k = 0; k < batch_size; ++k)
        {
          if (y + z < sizes[k])
          {
            mpz_set(mult_Buff1[buff_p1], p[k][y + z]);
            mpz_set(mult_Buff2[buff_p1++], p[k][y]);

            mpz_set(mult_Buff1[buff_p1], p[k][y + z]);
            mpz_set(mult_Buff2[buff_p1++], g[k][y]);
          }
        }
      }
      y += (1 << (i + 1));
    }

    Mul->doOperation(mult_Buff3, mult_Buff1, mult_Buff2, buff_p1, threadID);

    y = (1 << i) - 1;
    buff_p1 = 0;
    buff_p2 = 0;
    while (y + 2 <= max_size)
    {
      for (int z = 1; z <= (1 << i); ++z)
      {
        for (int k = 0; k < batch_size; ++k)
        {
          if (y + z < sizes[k])
          {
            mpz_set(p[k][y + z], mult_Buff3[buff_p1++]);
            ss->modAdd(g[k][y + z], g[k][y + z], mult_Buff3[buff_p1++]);
          }
        }
      }
      y += (1 << (i + 1));
    }
  }

  mpz_clear(tmp);

  for (int i = 0; i < sizes_sum; i++)
  {
    mpz_clear(mult_Buff1[i]);
    mpz_clear(mult_Buff2[i]);
    mpz_clear(mult_Buff3[i]);
  }
  free(mult_Buff1);
  free(mult_Buff2);
  free(mult_Buff3);
}







void BitAdd::twosComplement(mpz_t **input_A, mpz_t **output, int size, int batch_size, int threadID)
{
  int *sizes = new int[batch_size];
  for (int i = 0; i < batch_size; i++)
    sizes[i] = size;

  twosComplement(input_A, output, sizes, batch_size, threadID);

  delete sizes;
}


void BitAdd::twosComplement(mpz_t **input_A, mpz_t **output, int *sizes, int batch_size, int threadID)
{
  int sizes_sum = 0;
  for(int i = 0; i < batch_size; i++)
  {
    sizes_sum += sizes[i];
  }

  mpz_t **neg_A = (mpz_t **) malloc(sizeof(mpz_t *) * batch_size);
  mpz_t **p = (mpz_t**) malloc(sizeof(mpz_t*) * batch_size);
  mpz_t **g = (mpz_t**) malloc(sizeof(mpz_t*) * batch_size);

  for (int i = 0; i < batch_size; i++)
  {
    neg_A[i] = (mpz_t *) malloc(sizeof(mpz_t) * sizes_sum);
    p[i] = (mpz_t*) malloc(sizeof(mpz_t) * sizes[i]);
    g[i] = (mpz_t*) malloc(sizeof(mpz_t) * sizes[i]);

    for (int j = 0; j < sizes[i]; j++)
    {
      mpz_init(neg_A[i][j]);
      mpz_init(p[i][j]);
      mpz_init(g[i][j]);
    }
  }

  mpz_t zero;
  mpz_t one;
  mpz_init_set_ui(zero, 0);
  mpz_init_set_ui(one, 1);

  for (int i = 0; i < batch_size; i++)
  {
    for (int j = 0; j < sizes[i]; j++)
    {
      ss->modSub(neg_A[i][j], one, input_A[i][j]);
    }
  }

  mpz_t *mult_Buff1 = (mpz_t *) malloc(sizeof(mpz_t) * sizes_sum);
  mpz_t *mult_Buff2 = (mpz_t *) malloc(sizeof(mpz_t) * sizes_sum);
  mpz_t *mult_Buff3 = (mpz_t *) malloc(sizeof(mpz_t) * sizes_sum);

  for (int i = 0; i < sizes_sum; i++)
  {
    mpz_init(mult_Buff1[i]);
    mpz_init(mult_Buff2[i]);
    mpz_init(mult_Buff3[i]);
  }

  for (int i = 0; i < batch_size; i++)
  {
    mpz_set(p[i][0], input_A[i][0]);
    mpz_set(g[i][0], neg_A[i][0]);

    for (int j = 1; j < sizes[i]; j++)
    {
      mpz_set(p[i][j], neg_A[i][j]);
      mpz_set(g[i][j], zero);
    }
  }

  prefixCarry(p, g, sizes, batch_size, threadID);

  int buff_p1 = 0;
  for (int i = 0; i < batch_size; ++i)
  {
    for (int j = 1; j < sizes[i]; ++j)
    {
      mpz_set(mult_Buff1[buff_p1], neg_A[i][j]);
      mpz_set(mult_Buff2[buff_p1++], g[i][j - 1]);
    }
  }

  Mul->doOperation(mult_Buff3, mult_Buff1, mult_Buff2, buff_p1, threadID);

  mpz_t tmp;
  mpz_init(tmp);
  buff_p1 = 0;
  for (int i = 0; i < batch_size; ++i)
  {
    mpz_set(output[i][0], input_A[i][0]);
    for (int j = 1; j < sizes[i]; ++j)
    {
      ss->modAdd(output[i][j], neg_A[i][j], g[i][j - 1]);
      ss->modMul(tmp, mult_Buff3[buff_p1++], 2);
      ss->modSub(output[i][j], output[i][j], tmp);
    }
  }

  for (int i = 0; i < batch_size; i++)
  {
    for (int j = 0; j < sizes[i]; j++)
    {
      mpz_clear(neg_A[i][j]);
      mpz_clear(p[i][j]);
      mpz_clear(g[i][j]);
    }
    free(neg_A[i]);
    free(p[i]);
    free(g[i]);
  }

  free(neg_A);
  free(p);
  free(g);

  mpz_clear(zero);
  mpz_clear(one);
  mpz_clear(tmp);

  for (int i = 0; i < sizes_sum; i++)
  {
    mpz_clear(mult_Buff1[i]);
    mpz_clear(mult_Buff2[i]);
    mpz_clear(mult_Buff3[i]);
  }
  free(mult_Buff1);
  free(mult_Buff2);
  free(mult_Buff3);
}





void BitAdd::doOperation_mal(mpz_t ***input_A, mpz_t ***input_B, mpz_t ***output, int size, int batch_size, int threadID)
{
  int *sizes = (int *) malloc(sizeof(int) * batch_size);
  for (int i = 0; i < batch_size; i++)
    sizes[i] = size;

  doOperation_mal(input_A, input_B, output, sizes, batch_size, threadID);

  free(sizes);
}


void BitAdd::doOperation_mal(mpz_t ***input_A, mpz_t ***input_B, mpz_t ***output, int *sizes, int batch_size, int threadID)
{
  //show(input_A[0][0], sizes[0], net, id, ss);
  //show(input_B[0][0], sizes[0], net, id, ss);

  int sizes_sum = 0;

  for(int i = 0; i < batch_size; i++)
  {
    sizes_sum += sizes[i];
  }

  mpz_t *mult_Buff1 = (mpz_t *) malloc(sizeof(mpz_t) * sizes_sum * 2);
  mpz_t *mult_Buff2 = (mpz_t *) malloc(sizeof(mpz_t) * sizes_sum * 2);
  mpz_t *mult_Buff3 = (mpz_t *) malloc(sizeof(mpz_t) * sizes_sum * 2);

  for (int i = 0; i < sizes_sum * 2; i++)
  {
    mpz_init(mult_Buff1[i]);
    mpz_init(mult_Buff2[i]);
    mpz_init(mult_Buff3[i]);
  }

  mpz_t ***p = (mpz_t ***) malloc(sizeof(mpz_t **) * 2);
  mpz_t ***p_init = (mpz_t ***) malloc(sizeof(mpz_t **) * 2);
  mpz_t ***g = (mpz_t ***) malloc(sizeof(mpz_t **) * 2);

  for (int mi = 0; mi < 2; mi++)
  {
    p[mi] = (mpz_t **) malloc(sizeof(mpz_t *) * batch_size);
    p_init[mi] = (mpz_t **) malloc(sizeof(mpz_t *) * batch_size);
    g[mi] = (mpz_t **) malloc(sizeof(mpz_t *) * batch_size);

    for (int i = 0; i < batch_size; i++)
    {
      p[mi][i] = (mpz_t *) malloc(sizeof(mpz_t) * sizes[i]);
      p_init[mi][i] = (mpz_t *) malloc(sizeof(mpz_t) * sizes[i]);
      g[mi][i] = (mpz_t *) malloc(sizeof(mpz_t) * sizes[i]);

      for (int j = 0; j < sizes[i]; j++)
      {
        mpz_init(p[mi][i][j]);
        mpz_init(p_init[mi][i][j]);
        mpz_init(g[mi][i][j]);
      }
    }
  }

  int buff_p1 = 0;

  for (int i = 0; i < batch_size; ++i)
  {
    for (int j = 0; j < sizes[i]; ++j)
    {
      mpz_set(mult_Buff1[buff_p1], input_A[0][i][j]);
      mpz_set(mult_Buff2[buff_p1++], input_B[0][i][j]);
    }
  }

  for (int i = 0; i < batch_size; ++i)
  {
    for (int j = 0; j < sizes[i]; ++j)
    {
      mpz_set(mult_Buff1[buff_p1], input_A[0][i][j]);
      mpz_set(mult_Buff2[buff_p1++], input_B[1][i][j]);
    }
  }

  Mul->doOperation(mult_Buff3, mult_Buff1, mult_Buff2, buff_p1, threadID);
  ms->pushBuffer(mult_Buff3, &mult_Buff3[buff_p1 / 2], buff_p1 / 2);

  mpz_t tmp;
  mpz_init(tmp);
  int buff_p2 = 0;

  for (int i = 0; i < batch_size; ++i)
  {
    for (int j = 0; j < sizes[i]; ++j)
    {
      mpz_set(g[0][i][j], mult_Buff3[buff_p2++]);
      ss->modAdd(p[0][i][j], input_A[0][i][j], input_B[0][i][j]);
      ss->modMul(tmp, g[0][i][j], 2);
      ss->modSub(p[0][i][j], p[0][i][j], tmp);
      mpz_set(p_init[0][i][j], p[0][i][j]);
    }
  }

  for (int i = 0; i < batch_size; ++i)
  {
    for (int j = 0; j < sizes[i]; ++j)
    {
      mpz_set(g[1][i][j], mult_Buff3[buff_p2++]);
      ss->modAdd(p[1][i][j], input_A[1][i][j], input_B[1][i][j]);
      ss->modMul(tmp, g[1][i][j], 2);
      ss->modSub(p[1][i][j], p[1][i][j], tmp);
      mpz_set(p_init[1][i][j], p[1][i][j]);
    }
  }

  prefixCarry_mal(p, g, sizes, batch_size, threadID);

  for (int i = 0; i < batch_size; ++i)
  {
    mpz_set(output[0][i][0], input_A[0][i][0]);
    ss->modAdd(output[0][i][0], output[0][i][0], input_B[0][i][0]);
    ss->modMul(tmp, g[0][i][0], 2);
    ss->modSub(output[0][i][0], output[0][i][0], tmp);

    mpz_set(output[1][i][0], input_A[1][i][0]);
    ss->modAdd(output[1][i][0], output[1][i][0], input_B[1][i][0]);
    ss->modMul(tmp, g[1][i][0], 2);
    ss->modSub(output[1][i][0], output[1][i][0], tmp);

    for (int j = 1; j < sizes[i]; ++j)
    {
      mpz_set(output[0][i][j], input_A[0][i][j]);
      ss->modAdd(output[0][i][j], output[0][i][j], input_B[0][i][j]);
      ss->modMul(tmp, g[0][i][j], 2);
      ss->modSub(output[0][i][j], output[0][i][j], tmp);
      ss->modAdd(output[0][i][j], output[0][i][j], g[0][i][j - 1]);

      mpz_set(output[1][i][j], input_A[1][i][j]);
      ss->modAdd(output[1][i][j], output[1][i][j], input_B[1][i][j]);
      ss->modMul(tmp, g[1][i][j], 2);
      ss->modSub(output[1][i][j], output[1][i][j], tmp);
      ss->modAdd(output[1][i][j], output[1][i][j], g[1][i][j - 1]);
    }
  }

  // clear

  mpz_clear(tmp);

  for (int mi = 0; mi < 2; mi++)
  {
    for (int i = 0; i < batch_size; i++)
    {
      for (int j = 0; j < sizes[i]; j++)
      {
        mpz_clear(p[mi][i][j]);
        mpz_clear(p_init[mi][i][j]);
        mpz_clear(g[mi][i][j]);
      }
      free(p[mi][i]);
      free(p_init[mi][i]);
      free(g[mi][i]);
    }
    free(p[mi]);
    free(p_init[mi]);
    free(g[mi]);
  }

  free(p);
  free(p_init);
  free(g);

  for (int i = 0; i < sizes_sum * 2; i++)
  {
    mpz_clear(mult_Buff1[i]);
    mpz_clear(mult_Buff2[i]);
    mpz_clear(mult_Buff3[i]);
  }
  free(mult_Buff1);
  free(mult_Buff2);
  free(mult_Buff3);

  //show(output[0][0], sizes[0], net, id, ss);
}



void BitAdd::prefixCarry_mal(mpz_t ***p, mpz_t ***g, int *sizes, int batch_size, int threadID)
{
  int sizes_sum = 0;
  int max_size = 0;

  for(int i = 0; i < batch_size; i++)
  {
    sizes_sum += sizes[i];
    max_size = std::max(sizes[i], max_size);
  }

  int rounds = (int) ceil(log2(max_size));

  mpz_t *mult_Buff1 = (mpz_t *) malloc(sizeof(mpz_t) * sizes_sum * 2);
  mpz_t *mult_Buff2 = (mpz_t *) malloc(sizeof(mpz_t) * sizes_sum * 2);
  mpz_t *mult_Buff3 = (mpz_t *) malloc(sizeof(mpz_t) * sizes_sum * 2);

  for (int i = 0; i < sizes_sum * 2; i++)
  {
    mpz_init(mult_Buff1[i]);
    mpz_init(mult_Buff2[i]);
    mpz_init(mult_Buff3[i]);
  }

  int buff_p1 = 0;
  int buff_p2 = 0;
  int y = 0;
  mpz_t tmp;
  mpz_init(tmp);

  for (int i = 0; i < rounds; ++i)
  {
    buff_p1 = 0;
    y = (1 << i) - 1;
    while (y + 2 <= max_size)
    {
      for (int z = 1; z <= (1 << i); ++z)
      {
        for (int k = 0; k < batch_size; ++k)
        {
          if (y + z < sizes[k])
          {
            mpz_set(mult_Buff1[buff_p1], p[0][k][y + z]);
            mpz_set(mult_Buff2[buff_p1++], p[0][k][y]);

            mpz_set(mult_Buff1[buff_p1], p[0][k][y + z]);
            mpz_set(mult_Buff2[buff_p1++], g[0][k][y]);
          }
        }
      }
      y += (1 << (i + 1));
    }

    y = (1 << i) - 1;
    while (y + 2 <= max_size)
    {
      for (int z = 1; z <= (1 << i); ++z)
      {
        for (int k = 0; k < batch_size; ++k)
        {
          if (y + z < sizes[k])
          {
            mpz_set(mult_Buff1[buff_p1], p[0][k][y + z]);
            mpz_set(mult_Buff2[buff_p1++], p[1][k][y]);

            mpz_set(mult_Buff1[buff_p1], p[0][k][y + z]);
            mpz_set(mult_Buff2[buff_p1++], g[1][k][y]);
          }
        }
      }
      y += (1 << (i + 1));
    }

    Mul->doOperation(mult_Buff3, mult_Buff1, mult_Buff2, buff_p1, threadID);
    ms->pushBuffer(mult_Buff3, &mult_Buff3[buff_p1 / 2], buff_p1 / 2);

    buff_p1 = 0;
    buff_p2 = 0;
    y = (1 << i) - 1;
    while (y + 2 <= max_size)
    {
      for (int z = 1; z <= (1 << i); ++z)
      {
        for (int k = 0; k < batch_size; ++k)
        {
          if (y + z < sizes[k])
          {
            mpz_set(p[0][k][y + z], mult_Buff3[buff_p1++]);
            ss->modAdd(g[0][k][y + z], g[0][k][y + z], mult_Buff3[buff_p1++]);
          }
        }
      }
      y += (1 << (i + 1));
    }

    y = (1 << i) - 1;
    while (y + 2 <= max_size)
    {
      for (int z = 1; z <= (1 << i); ++z)
      {
        for (int k = 0; k < batch_size; ++k)
        {
          if (y + z < sizes[k])
          {
            mpz_set(p[1][k][y + z], mult_Buff3[buff_p1++]);
            ss->modAdd(g[1][k][y + z], g[1][k][y + z], mult_Buff3[buff_p1++]);
          }
        }
      }
      y += (1 << (i + 1));
    }
  }

  // clear

  mpz_clear(tmp);

  for (int i = 0; i < sizes_sum * 2; i++)
  {
    mpz_clear(mult_Buff1[i]);
    mpz_clear(mult_Buff2[i]);
    mpz_clear(mult_Buff3[i]);
  }
  free(mult_Buff1);
  free(mult_Buff2);
  free(mult_Buff3);
}




void BitAdd::twosComplement_mal(mpz_t ***input_A, mpz_t ***output, int size, int batch_size, int threadID)
{
  int *sizes = new int[batch_size];
  for (int i = 0; i < batch_size; i++)
    sizes[i] = size;

  twosComplement_mal(input_A, output, sizes, batch_size, threadID);

  delete sizes;
}


void BitAdd::twosComplement_mal(mpz_t ***input_A, mpz_t ***output, int *sizes, int batch_size, int threadID)
{
  int sizes_sum = 0;
  for(int i = 0; i < batch_size; i++)
  {
    sizes_sum += sizes[i];
  }

  mpz_t ***neg_A = (mpz_t ***) malloc(sizeof(mpz_t **) * 2);
  mpz_t ***p = (mpz_t ***) malloc(sizeof(mpz_t **) * 2);
  mpz_t ***g = (mpz_t ***) malloc(sizeof(mpz_t **) * 2);

  for (int mi = 0; mi < 2; mi++)
  {
    neg_A[mi] = (mpz_t **) malloc(sizeof(mpz_t *) * batch_size);
    p[mi] = (mpz_t**) malloc(sizeof(mpz_t*) * batch_size);
    g[mi] = (mpz_t**) malloc(sizeof(mpz_t*) * batch_size);

    for (int i = 0; i < batch_size; i++)
    {
      neg_A[mi][i] = (mpz_t *) malloc(sizeof(mpz_t) * sizes[i]);
      p[mi][i] = (mpz_t*) malloc(sizeof(mpz_t) * sizes[i]);
      g[mi][i] = (mpz_t*) malloc(sizeof(mpz_t) * sizes[i]);

      for (int j = 0; j < sizes[i]; j++)
      {
        mpz_init(neg_A[mi][i][j]);
        mpz_init(p[mi][i][j]);
        mpz_init(g[mi][i][j]);
      }
    }
  }

  mpz_t zero;
  mpz_t one;
  mpz_init_set_ui(zero, 0);
  mpz_init_set_ui(one, 1);

  for (int i = 0; i < batch_size; i++)
  {
    for (int j = 0; j < sizes[i]; j++)
    {
      ss->modSub(neg_A[0][i][j], one, input_A[0][i][j]);

      ss->modSub(neg_A[1][i][j], ms->r, input_A[1][i][j]);
    }
  }

  mpz_t *mult_Buff1 = (mpz_t *) malloc(sizeof(mpz_t) * sizes_sum * 2);
  mpz_t *mult_Buff2 = (mpz_t *) malloc(sizeof(mpz_t) * sizes_sum * 2);
  mpz_t *mult_Buff3 = (mpz_t *) malloc(sizeof(mpz_t) * sizes_sum * 2);

  for (int i = 0; i < sizes_sum * 2; i++)
  {
    mpz_init(mult_Buff1[i]);
    mpz_init(mult_Buff2[i]);
    mpz_init(mult_Buff3[i]);
  }

  for (int i = 0; i < batch_size; i++)
  {
    mpz_set(p[0][i][0], input_A[0][i][0]);
    mpz_set(g[0][i][0], neg_A[0][i][0]);

    mpz_set(p[1][i][0], input_A[1][i][0]);
    mpz_set(g[1][i][0], neg_A[1][i][0]);

    for (int j = 1; j < sizes[i]; j++)
    {
      mpz_set(p[0][i][j], neg_A[0][i][j]);
      mpz_set(g[0][i][j], zero);

      mpz_set(p[1][i][j], neg_A[1][i][j]);
      mpz_set(g[1][i][j], zero);
    }
  }

  prefixCarry_mal(p, g, sizes, batch_size, threadID);

  int buff_p1 = 0;
  for (int i = 0; i < batch_size; ++i)
  {
    for (int j = 1; j < sizes[i]; ++j)
    {
      mpz_set(mult_Buff1[buff_p1], neg_A[0][i][j]);
      mpz_set(mult_Buff2[buff_p1++], g[0][i][j - 1]);
    }
  }

  for (int i = 0; i < batch_size; ++i)
  {
    for (int j = 1; j < sizes[i]; ++j)
    {
      mpz_set(mult_Buff1[buff_p1], neg_A[0][i][j]);
      mpz_set(mult_Buff2[buff_p1++], g[1][i][j - 1]);
    }
  }

  Mul->doOperation(mult_Buff3, mult_Buff1, mult_Buff2, buff_p1, threadID);
  ms->pushBuffer(mult_Buff3, &mult_Buff3[buff_p1 / 2], buff_p1 / 2);

  mpz_t tmp;
  mpz_init(tmp);
  buff_p1 = 0;
  for (int i = 0; i < batch_size; ++i)
  {
    mpz_set(output[0][i][0], input_A[0][i][0]);
    for (int j = 1; j < sizes[i]; ++j)
    {
      ss->modAdd(output[0][i][j], neg_A[0][i][j], g[0][i][j - 1]);
      ss->modMul(tmp, mult_Buff3[buff_p1++], 2);
      ss->modSub(output[0][i][j], output[0][i][j], tmp);
    }
  }

  for (int i = 0; i < batch_size; ++i)
  {
    mpz_set(output[1][i][0], input_A[1][i][0]);
    for (int j = 1; j < sizes[i]; ++j)
    {
      ss->modAdd(output[1][i][j], neg_A[1][i][j], g[1][i][j - 1]);
      ss->modMul(tmp, mult_Buff3[buff_p1++], 2);
      ss->modSub(output[1][i][j], output[1][i][j], tmp);
    }
  }

  for (int mi = 0; mi < 2; mi++)
  {
    for (int i = 0; i < batch_size; i++)
    {
      for (int j = 0; j < sizes[i]; j++)
      {
        mpz_clear(neg_A[mi][i][j]);
        mpz_clear(p[mi][i][j]);
        mpz_clear(g[mi][i][j]);
      }
      free(neg_A[mi][i]);
      free(p[mi][i]);
      free(g[mi][i]);
    }
    free(neg_A[mi]);
    free(p[mi]);
    free(g[mi]);
  }

  free(neg_A);
  free(p);
  free(g);

  mpz_clear(zero);
  mpz_clear(one);
  mpz_clear(tmp);

  for (int i = 0; i < sizes_sum * 2; i++)
  {
    mpz_clear(mult_Buff1[i]);
    mpz_clear(mult_Buff2[i]);
    mpz_clear(mult_Buff3[i]);
  }
  free(mult_Buff1);
  free(mult_Buff2);
  free(mult_Buff3);
}






