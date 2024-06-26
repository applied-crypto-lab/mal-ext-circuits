/*
 *   PICCO: A General Purpose Compiler for Private Distributed Computation
 ** Copyright (C) 2013 PICCO Team
 ** Department of Computer Science and Engineering, University of Notre Dame
 *
 *   PICCO is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   PICCO is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with PICCO. If not, see <http://www.gnu.org/licenses/>.
 */

/* NOTE This file has been modified from its original form for use in the applied-crypto-lab/biom-auth codebase */

#include "Mod2M.h"

Mod2M::Mod2M(NodeNetwork nodeNet, std::map<std::string, std::vector<int> > poly, int nodeID, SecretShare *s, mpz_t coeficients[]){
  ss = s;
  B = new BitLTC(nodeNet,poly,nodeID,s,coeficients);
  net = nodeNet;
  polynomials = poly;
  id = nodeID;
  for (int i = 0; i < 9; i++){
    mpz_init(coef[i]);
    mpz_set(coef[i],coeficients[i]);
  }
  Rand = new Random(nodeNet, poly, nodeID, s);

}

Mod2M::Mod2M(NodeNetwork nodeNet, std::map<std::string, std::vector<int> > poly, int nodeID, SecretShare *s, mpz_t coeficients[], MaliciousSMC *malicious){
  ss = s;
  B = new BitLTC(nodeNet,poly,nodeID,s,coeficients);
  net = nodeNet;
  polynomials = poly;
  ms = malicious;
  id = nodeID;
  for (int i = 0; i < 9; i++){
    mpz_init(coef[i]);
    mpz_set(coef[i],coeficients[i]);
  }
  Rand = new Random(nodeNet, poly, nodeID, s);
  Mul = new Mult(nodeNet, nodeID, s);
}

Mod2M::~Mod2M() {}


void Mod2M::doOperation(mpz_t* result, mpz_t* shares1, int K, int M, int size, int threadID){

  //printf("Begin %s\n", __PRETTY_FUNCTION__);

  int peers = ss->getPeers();
  mpz_t** R = (mpz_t**)malloc(sizeof(mpz_t*) * (M+2));
  mpz_t** resultShares = (mpz_t**)malloc(sizeof(mpz_t*) * peers);
  mpz_t* U = (mpz_t*)malloc(sizeof(mpz_t) * size);
  mpz_t* shares = (mpz_t*)malloc(sizeof(mpz_t) * size);
  mpz_t* C = (mpz_t*)malloc(sizeof(mpz_t) * size);

  //initialization
  mpz_t const2, constM, constK1, pow2M, pow2K1;
  mpz_init_set_ui(const2, 2);
  mpz_init_set_ui(constM, M);
  mpz_init_set_ui(constK1, K-1);
  mpz_init(pow2M);
  mpz_init(pow2K1);
  for(int i = 0; i < M+2; i++){
    R[i] = (mpz_t*)malloc(sizeof(mpz_t) * size);
    for(int j = 0; j < size; j++)
      mpz_init(R[i][j]);
  }

  for(int i = 0; i < peers; i++){
    resultShares[i] = (mpz_t*)malloc(sizeof(mpz_t) * size);
    for(int j = 0; j < size; j++)
      mpz_init(resultShares[i][j]);
  }

  for(int i = 0; i < size; i++){
    mpz_init(U[i]);
    mpz_init(C[i]);
    mpz_init_set(shares[i], shares1[i]);
  }

  ss->modPow(pow2M, const2, constM);
  ss->modPow(pow2K1, const2, constK1);

  // start comutation.
  Rand->PRandInt(K, M, size, C, threadID);
  ss->modMul(C, C, pow2M, size);
  Rand->PRandM(K, M, size, R, threadID);

  ss->modAdd(C, C, shares, size);
  ss->modAdd(C, C, R[M], size);
  ss->modAdd(C, C, pow2K1, size);

  net.broadcastToPeers(C, size, resultShares, threadID);
  //net.broadcastToPeers_T(C, size, resultShares, threadID);

  ss->reconstructSecret(C, resultShares, size, true);
  ss->mod(C, C, pow2M, size);

  B->doOperation(C, R, U, M, size, threadID);

  ss->modMul(U, U, pow2M, size);
  ss->modAdd(result, C, U, size);
  ss->modSub(result, result, R[M], size);

  // free the memory
  for(int i = 0; i < M+2; i++){
    for(int j = 0; j < size; j++)
      mpz_clear(R[i][j]);
    free(R[i]);
  }
  free(R);

  for(int i = 0; i < peers; i++){
    for(int j = 0; j < size; j++)
      mpz_clear(resultShares[i][j]);
    free(resultShares[i]);
  }
  free(resultShares);

  for(int i = 0; i < size; i++){
    mpz_clear(U[i]);
    mpz_clear(C[i]);
    mpz_clear(shares[i]);
  }
  free(U);
  free(C);
  free(shares);

  mpz_clear(const2);
  mpz_clear(constK1);
  mpz_clear(constM);
  mpz_clear(pow2M);
  mpz_clear(pow2K1);

  //printf("End %s\n", __PRETTY_FUNCTION__);
}




void Mod2M::doOperation_mal(mpz_t** result, mpz_t** shares1, int K, int M, int size, int threadID){

  //printf("Begin %s\n", __PRETTY_FUNCTION__);

  int peers = ss->getPeers();

  //initialization
  mpz_t const2, constM, constK1, pow2M, pow2K1;
  mpz_init_set_ui(const2, 2);
  mpz_init_set_ui(constM, M);
  mpz_init_set_ui(constK1, K-1);
  mpz_init(pow2M);
  mpz_init(pow2K1);
  ss->modPow(pow2M, const2, constM);
  ss->modPow(pow2K1, const2, constK1);

  mpz_t inv2, const1;
  mpz_init_set_ui(const1, 1);
  mpz_init_set_ui(inv2, 2);
  ss->modInv(inv2, inv2);

  mpz_t** Mod2_S = (mpz_t**)malloc(sizeof(mpz_t*) * 2);
  for(int k = 0; k < 2; k++){
    Mod2_S[k] = (mpz_t*)malloc(sizeof(mpz_t) * size);
    for(int i = 0; i < size; i++)
      mpz_init(Mod2_S[k][i]);
  }
  mpz_t** C = (mpz_t**)malloc(sizeof(mpz_t*) * 2);
  for(int k = 0; k < 2; k++){
    C[k] = (mpz_t*)malloc(sizeof(mpz_t) * size);
    for(int i = 0; i < size; i++){
      mpz_init(C[k][i]);
    }
  }

  Rand->PRandInt(K, M, size, C[0], threadID);
  Rand->PRandInt(M, 1, size, Mod2_S[0], threadID);


  /*PRandM start*/


  /*PRandBit start*/


  int PRandBit_size = size * (M + 1);

  mpz_t** PRandBit_u = (mpz_t**)malloc(sizeof(mpz_t*) * 2);
  for(int i = 0; i < 2; i++){
    PRandBit_u[i] = (mpz_t*)malloc(sizeof(mpz_t) * PRandBit_size);
    for(int j = 0; j < PRandBit_size; j++){
      mpz_init(PRandBit_u[i][j]);
    }
  }
  //for PreMul

  mpz_t field;
  mpz_init(field);
  ss->getFieldSize(field);
  Rand->generateRandValue(id, field, PRandBit_size, PRandBit_u[0]);

  mpz_t** PreMul_R = (mpz_t**)malloc(sizeof(mpz_t*) * 2);
  mpz_t** PreMul_S = (mpz_t**)malloc(sizeof(mpz_t*) * 2);
  for(int i = 0; i < 2; i++){
    PreMul_R[i] = (mpz_t*)malloc(sizeof(mpz_t) * M * size);
    PreMul_S[i] = (mpz_t*)malloc(sizeof(mpz_t) * M * size);
    for(int j = 0; j < M * size; j++){
      mpz_init(PreMul_R[i][j]);
      mpz_init(PreMul_S[i][j]);
    }
  }

  Rand->generateRandValue(id, field, M * size, PreMul_R[0], threadID); //PreMul
  Rand->generateRandValue(id, field, M * size, PreMul_S[0], threadID); //PreMul
  //Round 1 xr for Rand
  //PRandBit_u || PreMul_R || PreMul_S || C[0] || Mod2_S[0]
  //PRandBit_size || M     ||   M      ||   size ||   size
  mpz_t** inputBuffer_mal = (mpz_t**)malloc(sizeof(mpz_t*) * 2);
  for(int i = 0; i < 2; i++){
    inputBuffer_mal[i] = (mpz_t*)malloc(sizeof(mpz_t) * (PRandBit_size + 2*M*size + 2*size));
    for(int j = 0; j < PRandBit_size + 2*M*size + 2*size; j++){
      mpz_init(inputBuffer_mal[i][j]);
    }
  }

  int inputBuffer_p = 0;
  //PRandBit_u[0] || PreMul_R[0] || PreMul_S[0] || C[0] || Mod2_S[0]
  //PRandBit_size || M     ||   M      ||   size ||   size
  for(int i = 0; i < PRandBit_size; i++){
    mpz_set(inputBuffer_mal[0][inputBuffer_p], PRandBit_u[0][i]);
    inputBuffer_p++;
  }

  for(int i = 0; i < M * size; i++){
    mpz_set(inputBuffer_mal[0][inputBuffer_p], PreMul_R[0][i]);
    inputBuffer_p++;
  }

  for(int i = 0; i < M * size; i++){
    mpz_set(inputBuffer_mal[0][inputBuffer_p], PreMul_S[0][i]);
    inputBuffer_p++;
  }

  for(int i = 0; i < size; i++){
    mpz_set(inputBuffer_mal[0][inputBuffer_p], C[0][i]);
    inputBuffer_p++;
  }

  for(int i = 0; i < size; i++){
    mpz_set(inputBuffer_mal[0][inputBuffer_p], Mod2_S[0][i]);
    inputBuffer_p++;
  }
  mpz_t* randR = (mpz_t*)malloc(sizeof(mpz_t) * (PRandBit_size + 2*M*size + 2*size));
  for(int i = 0; i < PRandBit_size + 2*M*size + 2*size; i++){
    mpz_init_set(randR[i], ms->r);
  }


  //Round 1

  Mul->doOperation(inputBuffer_mal[1], randR, inputBuffer_mal[0], PRandBit_size + 2*M*size + 2*size, -1);
  ms->pushBuffer(inputBuffer_mal[0], inputBuffer_mal[1], PRandBit_size + 2*M*size + 2*size);

  //net.getSummary("", false);

  for(int i = 0; i < PRandBit_size + 2*M*size + 2*size; i++){
    mpz_clear(randR[i]);
  }
  free(randR);

  inputBuffer_p = 0;
  for(int i = 0; i < PRandBit_size; i++){
    mpz_set(PRandBit_u[1][i], inputBuffer_mal[1][inputBuffer_p]);
    inputBuffer_p++;
  }

  for(int i = 0; i < M * size; i++){
    mpz_set(PreMul_R[1][i], inputBuffer_mal[1][inputBuffer_p]);
    inputBuffer_p++;
  }

  for(int i = 0; i < M * size; i++){
    mpz_set(PreMul_S[1][i], inputBuffer_mal[1][inputBuffer_p]);
    inputBuffer_p++;
  }

  for(int i = 0; i < size; i++){
    mpz_set(C[1][i], inputBuffer_mal[1][inputBuffer_p]);
    inputBuffer_p++;
  }
  for(int i = 0; i < size; i++){
    mpz_set(Mod2_S[1][i], inputBuffer_mal[1][inputBuffer_p]);
    inputBuffer_p++;
  }

  for(int i=0; i<2; ++i){
    for(int j=0; j<PRandBit_size + 2*M*size + 2*size; ++j)
      mpz_clear(inputBuffer_mal[i][j]);
    free(inputBuffer_mal[i]);
  }
  free(inputBuffer_mal);

  mpz_t* mulBuffer2 = (mpz_t*)malloc(sizeof(mpz_t) * (PRandBit_size + M*size));
  mpz_t* mulBuffer3 = (mpz_t*)malloc(sizeof(mpz_t) * (PRandBit_size + M*size));
  for(int i = 0; i < PRandBit_size + M*size; i++){
    mpz_init(mulBuffer2[i]);
    mpz_init(mulBuffer3[i]);
  }
  for(int i = 0; i < PRandBit_size; ++i) {
    mpz_set(mulBuffer2[i], PRandBit_u[0][i]);
    mpz_set(mulBuffer3[i], PRandBit_u[0][i]);
  }
  for(int i = 0; i < M * size; ++i) {
    mpz_set(mulBuffer2[i+PRandBit_size], PreMul_S[0][i]);
    mpz_set(mulBuffer3[i+PRandBit_size], PreMul_R[0][i]);
  }

  mpz_t** PRandBit_v = (mpz_t**)malloc(sizeof(mpz_t*) * 2);
  for(int i = 0; i < 2; i++){
    PRandBit_v[i] = (mpz_t*)malloc(sizeof(mpz_t) * (PRandBit_size + M*size));
    for(int j = 0; j < PRandBit_size + M*size; j++){
      mpz_init(PRandBit_v[i][j]);
    }
  }

  Mul->doOperation(PRandBit_v[0], mulBuffer2, mulBuffer3, PRandBit_size + M*size, threadID);

  //net.getSummary("", false);

  for(int i = 0; i < PRandBit_size + M*size; i++){
    mpz_clear(mulBuffer2[i]);
    mpz_clear(mulBuffer3[i]);
  }
  free(mulBuffer2);
  free(mulBuffer3);

  //RandBits and PreMul MulPub
  //Round 2 mulpub
  //Round 2' convert multpub -> mult + pub

  mpz_t** PRandBit_resultShares = (mpz_t**)malloc(sizeof(mpz_t*) * peers);
  for(int i = 0; i < peers; i++){
    PRandBit_resultShares[i] = (mpz_t*)malloc(sizeof(mpz_t) * (PRandBit_size + M*size));
    for(int j = 0; j < PRandBit_size + M*size; j++)
      mpz_init(PRandBit_resultShares[i][j]);
  }

  net.broadcastToPeers(PRandBit_v[0], PRandBit_size + M*size, PRandBit_resultShares, -1);
  ms->reconstructSecretCheck(PRandBit_v[0], PRandBit_resultShares, PRandBit_size + M*size, true);

  for(int i = 0; i < peers; i++){
    for(int j = 0; j < PRandBit_size + M*size; j++)
      mpz_clear(PRandBit_resultShares[i][j]);
    free(PRandBit_resultShares[i]);
  }
  free(PRandBit_resultShares);

  //net.getSummary("", false);

  mpz_t** PreMul_U = (mpz_t**)malloc(sizeof(mpz_t*) * 2);
  for(int i = 0; i < 2; i++){
    PreMul_U[i] = (mpz_t*)malloc(sizeof(mpz_t) * M * size);
    for(int j = 0; j < M * size; j++){
      mpz_init(PreMul_U[i][j]);
    }
  }

  for(int i = 0; i < M * size; i++){
    mpz_set(PreMul_U[0][i], PRandBit_v[0][PRandBit_size+i]);
  }

  mpz_t* mulBuffer_mal1 = (mpz_t*)malloc(sizeof(mpz_t) * (PRandBit_size + (3*M - 2) * size));
  mpz_t* mulBuffer_mal2 = (mpz_t*)malloc(sizeof(mpz_t) * (PRandBit_size + (3*M - 2) * size));

  for(int i = 0; i < PRandBit_size + (3*M - 2) * size; i++){
    mpz_init(mulBuffer_mal1[i]);
    mpz_init(mulBuffer_mal2[i]);
  }

  int mulBuffer_pointer = 0;
  for(int i = 0; i < PRandBit_size; ++i) {
    mpz_set(mulBuffer_mal1[mulBuffer_pointer], PRandBit_u[0][i]);
    mpz_set(mulBuffer_mal2[mulBuffer_pointer], PRandBit_u[1][i]);
    mulBuffer_pointer++;
  }
  for(int i = 0; i < M * size; ++i) {
    mpz_set(mulBuffer_mal1[mulBuffer_pointer], PreMul_R[0][i]);
    mpz_set(mulBuffer_mal2[mulBuffer_pointer], PreMul_S[1][i]);
    mulBuffer_pointer++;
  }
  for(int i = 0; i < (M-1) * size; ++i) {
    mpz_set(mulBuffer_mal1[mulBuffer_pointer], PreMul_R[0][i+1]);
    mpz_set(mulBuffer_mal2[mulBuffer_pointer], PreMul_S[0][i]);
    mulBuffer_pointer++;
  }
  for(int i = 0; i < (M-1) * size; ++i) {
    mpz_set(mulBuffer_mal1[mulBuffer_pointer], PreMul_R[0][i+1]);
    mpz_set(mulBuffer_mal2[mulBuffer_pointer], PreMul_S[1][i]);
    mulBuffer_pointer++;
  }

  mpz_t* mulBuffer_mal3 = (mpz_t*)malloc(sizeof(mpz_t) * (PRandBit_size + (3*M - 2) * size));
  for(int i = 0; i < PRandBit_size + (3*M - 2) * size; i++){
    mpz_init(mulBuffer_mal3[i]);
  }

  Mul->doOperation(mulBuffer_mal3, mulBuffer_mal2, mulBuffer_mal1, PRandBit_size + (3*M - 2) * size, threadID);//Round 3

  for(int i = 0; i < PRandBit_size + (3*M - 2) * size; i++){
    mpz_clear(mulBuffer_mal1[i]);
    mpz_clear(mulBuffer_mal2[i]);
  }
  free(mulBuffer_mal1);
  free(mulBuffer_mal2);

  //net.getSummary("", false);

  mulBuffer_pointer = 0;
  for(int i = 0; i < PRandBit_size; i++){
    mpz_set(PRandBit_v[1][i], mulBuffer_mal3[mulBuffer_pointer]);
    mulBuffer_pointer++;
  }

  ms->pushBuffer(PRandBit_v[0], PRandBit_v[1], PRandBit_size);

  for(int i = 0; i < M * size; i++){
    mpz_set(PreMul_U[1][i], mulBuffer_mal3[mulBuffer_pointer]);
    mulBuffer_pointer++;
  }

  ms->pushBuffer(PreMul_U[0], PreMul_U[1], M * size);

  mpz_t** PreMul_V = (mpz_t**)malloc(sizeof(mpz_t*) * 2);
  for(int i = 0; i < 2; i++){
    PreMul_V[i] = (mpz_t*)malloc(sizeof(mpz_t) * M * size);
    for(int j = 0; j < M * size; j++){
      mpz_init(PreMul_V[i][j]);
    }
  }

  for(int i = 0; i < (M-1) * size; i++){
    mpz_set(PreMul_V[0][i], mulBuffer_mal3[mulBuffer_pointer]);
    mulBuffer_pointer++;
  }

  for(int i = 0; i < (M-1) * size; i++){
    mpz_set(PreMul_V[1][i], mulBuffer_mal3[mulBuffer_pointer]);
    mulBuffer_pointer++;
  }

  ms->pushBuffer(PreMul_V[0], PreMul_V[1], (M-1) * size);

  //ms->check_ver(PreMul_V, (M-1) * size);

  //clean buffer
  for(int i = 0; i < PRandBit_size + (3*M - 2) * size; i++){
    mpz_clear(mulBuffer_mal3[i]);
  }
  free(mulBuffer_mal3);

  //Round 3 xr for previous mulpub, along with this mult

  ss->modSqrt(PRandBit_v[0], PRandBit_v[0], PRandBit_size);
  ss->modInv(PRandBit_v[0], PRandBit_v[0], PRandBit_size);

  mpz_t** PRandM_tempResult = (mpz_t**) malloc(sizeof(mpz_t*)  * 2);
  for(int i = 0; i < 2; i++){
    PRandM_tempResult[i] = (mpz_t*) malloc(sizeof(mpz_t)  * (size * (M + 1)));
    for(int j = 0; j < size * (M + 1); j++){
      mpz_init(PRandM_tempResult[i][j]);
    }
  }

  ss->modMul(PRandM_tempResult[0], PRandBit_v[0], PRandBit_u[0], PRandBit_size);
  ss->modMul(PRandM_tempResult[1], PRandBit_v[0], PRandBit_u[1], PRandBit_size);

  ss->modAdd(PRandM_tempResult[0], PRandM_tempResult[0], const1, PRandBit_size);
  ss->modAdd(PRandM_tempResult[1], PRandM_tempResult[1], ms->r, PRandBit_size);

  ss->modMul(PRandM_tempResult[0], PRandM_tempResult[0], inv2, PRandBit_size);
  ss->modMul(PRandM_tempResult[1], PRandM_tempResult[1], inv2, PRandBit_size);

  //free the memory
  mpz_clear(inv2);

  for(int i = 0; i < 2; i++){
    for(int j = 0; j < PRandBit_size + M*size; j++){
      mpz_clear(PRandBit_v[i][j]);
    }
    free(PRandBit_v[i]);
  }
  free(PRandBit_v);
  for(int i = 0; i < 2; i++){
    for(int j = 0; j < PRandBit_size; j++){
      mpz_clear(PRandBit_u[i][j]);
    }
    free(PRandBit_u[i]);
  }
  free(PRandBit_u);


  /*PRandBit end*/


  mpz_t*** R = (mpz_t***)malloc(sizeof(mpz_t**) * 2);
  for(int k = 0; k < 2; k++){
    R[k] = (mpz_t**)malloc(sizeof(mpz_t*) * (M+2));
    for(int i = 0; i < M+2; i++){
      R[k][i] = (mpz_t*)malloc(sizeof(mpz_t) * size);
      for(int j = 0; j < size; j++)
        mpz_init(R[k][i][j]);
    }
  }

  for (int i = 0; i < size; i++) {
    mpz_set(R[0][M][i], PRandM_tempResult[0][i]);
    mpz_set(R[0][0][i], PRandM_tempResult[0][i]);

    mpz_set(R[1][M][i], PRandM_tempResult[1][i]);
    mpz_set(R[1][0][i], PRandM_tempResult[1][i]);
  }

  mpz_t** PRandM_temp = (mpz_t**) malloc(sizeof(mpz_t*)  * 2);
  for(int i = 0; i < 2; i++){
    PRandM_temp[i] = (mpz_t*) malloc(sizeof(mpz_t)  * size);
    for(int j = 0; j < size; j++){
      mpz_init(PRandM_temp[i][j]);
    }
  }

  unsigned long pow = 1;
  for (int i = 1; i < M; i++) {
    pow = pow << 1;
    for (int j = 0; j < size; j++) {
      mpz_set(R[0][i][j], PRandM_tempResult[0][i * size + j]);
      mpz_mul_ui(PRandM_temp[0][j], R[0][i][j], pow);

      mpz_set(R[1][i][j], PRandM_tempResult[1][i * size + j]);
      mpz_mul_ui(PRandM_temp[1][j], R[1][i][j], pow);
    }
    ss->modAdd(R[0][M], R[0][M], PRandM_temp[0], size);
    ss->modAdd(R[1][M], R[1][M], PRandM_temp[1], size);
  }

  for(int i = 0; i < 2; i++){
    for(int j = 0; j < size; j++){
      mpz_clear(PRandM_temp[i][j]);
    }
    free(PRandM_temp[i]);
  }
  free(PRandM_temp);

  mpz_t*** Mod2_R = (mpz_t***)malloc(sizeof(mpz_t**) * 2);
  for(int k = 0; k < 2; k++){
    Mod2_R[k] = (mpz_t**)malloc(sizeof(mpz_t*) * 2);
    for(int i = 0; i < 2; i++){
      Mod2_R[k][i] = (mpz_t*)malloc(sizeof(mpz_t) * size);
      for(int j = 0; j < size; j++)
        mpz_init(Mod2_R[k][i][j]);
    }
  }

  for (int i = 0; i < size; i++) {
    mpz_set(Mod2_R[0][1][i], PRandM_tempResult[0][i + size]);
    mpz_set(Mod2_R[0][0][i], PRandM_tempResult[0][i + size]);

    mpz_set(Mod2_R[1][1][i], PRandM_tempResult[1][i + size]);
    mpz_set(Mod2_R[1][0][i], PRandM_tempResult[1][i + size]);

  }

  //free the memory
  for(int i = 0; i < 2; i++){
    for(int j = 0; j < size * (M + 1); j++){
      mpz_clear(PRandM_tempResult[i][j]);
    }
    free(PRandM_tempResult[i]);
  }
  free(PRandM_tempResult);


  /*PRandM end*/


  ss->modMul(C[0], C[0], pow2M, size);
  ss->modMul(C[1], C[1], pow2M, size);

  mpz_t** shares = (mpz_t**)malloc(sizeof(mpz_t*) * 2);
  for(int k = 0; k < 2; k++){
    shares[k] = (mpz_t*)malloc(sizeof(mpz_t) * size);
    for(int i = 0; i < size; i++){
      mpz_init_set(shares[k][i], shares1[k][i]);
    }
  }

  ss->modAdd(C[0], C[0], shares[0], size);
  ss->modAdd(C[1], C[1], shares[1], size);

  for(int k = 0; k < 2; k++){
    for(int i = 0; i < size; i++){
      mpz_clear(shares[k][i]);
    }
    free(shares[k]);
  }
  free(shares);

  ss->modAdd(C[0], C[0], R[0][M], size);
  ss->modAdd(C[1], C[1], R[1][M], size);

  ss->modAdd(C[0], C[0], pow2K1, size);
  ss->modMul(pow2K1, pow2K1, ms->r);
  ss->modAdd(C[1], C[1], pow2K1, size);
  //ms->pushBuffer(C[0], C[1], size);

  ms->verify();

  //net.getSummary("", false);

  mpz_t** resultShares = (mpz_t**)malloc(sizeof(mpz_t*) * peers);
  for(int i = 0; i < peers; i++){
    resultShares[i] = (mpz_t*)malloc(sizeof(mpz_t) * size);
    for(int j = 0; j < size; j++)
      mpz_init(resultShares[i][j]);
  }

  net.broadcastToPeers(C[0], size, resultShares, threadID);//Round 4 open
  ms->reconstructSecretCheck(C[0], resultShares, size, true);

  for(int i = 0; i < peers; i++){
    for(int j = 0; j < size; j++)
      mpz_clear(resultShares[i][j]);
    free(resultShares[i]);
  }
  free(resultShares);

  //net.getSummary("", false);

  ss->mod(C[0], C[0], pow2M, size);
  ss->modMul(C[1], C[0], ms->r, size);


  /*BitLT start*/


  mpz_t*** BitLT_d = (mpz_t***)malloc(sizeof(mpz_t**) * 2);
  mpz_t*** BitLT_a = (mpz_t***)malloc(sizeof(mpz_t**) * 2);
  mpz_t** BitLT_temp = (mpz_t**)malloc(sizeof(mpz_t*) * 2);
  mpz_t** BitLT_temp1 = (mpz_t**)malloc(sizeof(mpz_t*) * 2);

  for(int k = 0; k < 2; k++){
    BitLT_d[k] = (mpz_t**)malloc(sizeof(mpz_t*) * M);
    for(int i = 0; i < M; i++){
      BitLT_d[k][i] = (mpz_t*)malloc(sizeof(mpz_t) * size);
      for(int j = 0; j < size; j++){
        mpz_init(BitLT_d[k][i][j]);
      }
    }
    BitLT_a[k] = (mpz_t**)malloc(sizeof(mpz_t*) * size);
    for(int i = 0; i < size; i++){
      BitLT_a[k][i] = (mpz_t*)malloc(sizeof(mpz_t) * M);
      for(int j = 0; j < M; j++)
        mpz_init(BitLT_a[k][i][j]);
    }
  }
  for(int k = 0; k < 2; k++){
    BitLT_temp[k] = (mpz_t*)malloc(sizeof(mpz_t) * size);
    BitLT_temp1[k] = (mpz_t*)malloc(sizeof(mpz_t) * size);
    for(int i = 0; i < size; i++){
      mpz_init(BitLT_temp[k][i]);
      mpz_init(BitLT_temp1[k][i]);
    }
  }

  for(int j = 0; j < size; j++)
    binarySplit(C[0][j], BitLT_a[0][j], M);
  for(int i = 0; i < M; i++){
    for(int j = 0; j < size; j++){
      ss->modMul(BitLT_a[1][j][i], BitLT_a[0][j][i], ms->r);
      mpz_set(BitLT_temp1[0][j], BitLT_a[0][j][i]);
      mpz_set(BitLT_temp1[1][j], BitLT_a[1][j][i]);
      //      ss->modMul(BitLT_temp1[1][j], BitLT_a[0][j][i], ss->r);
    }
    ss->modMul(BitLT_temp[0], BitLT_temp1[0], R[0][i], size);
    ss->modMul(BitLT_temp[1], BitLT_temp1[0], R[1][i], size);

    ss->modMul(BitLT_temp[0], BitLT_temp[0], const2, size);
    ss->modMul(BitLT_temp[1], BitLT_temp[1], const2, size);

    ss->modSub(BitLT_temp[0], R[0][i], BitLT_temp[0], size);
    ss->modSub(BitLT_temp[1], R[1][i], BitLT_temp[1], size);

    ss->modAdd(BitLT_temp[0], BitLT_temp1[0], BitLT_temp[0], size);
    ss->modAdd(BitLT_temp[1], BitLT_temp1[1], BitLT_temp[1], size);

    ss->modAdd(BitLT_temp[0], BitLT_temp[0], const1, size);
    ss->modAdd(BitLT_temp[1], BitLT_temp[1], ms->r, size);

    for(int j = 0; j < size; j++){
      mpz_set(BitLT_d[0][M-1-i][j], BitLT_temp[0][j]);
      mpz_set(BitLT_d[1][M-1-i][j], BitLT_temp[1][j]);
    }
  }

  for(int k = 0; k < 2; k++){
    for(int i = 0; i < size; i++){
      mpz_clear(BitLT_temp1[k][i]);
    }
    free(BitLT_temp1[k]);
  }
  free(BitLT_temp1);


  /*PreMul start*/




  mpz_t** PreMul_W = (mpz_t**)malloc(sizeof(mpz_t*) * 2);
  for(int i = 0; i < 2; i++){
    PreMul_W[i] = (mpz_t*)malloc(sizeof(mpz_t) * M * size);
    for(int j = 0; j < M * size; j++){
      mpz_init(PreMul_W[i][j]);
    }
  }

  for (int i = 0; i < size; i++) {
    mpz_set(PreMul_W[0][i], PreMul_R[0][i]);
    mpz_set(PreMul_W[1][i], PreMul_R[1][i]);
  }

  for(int i = 0; i < 2; i++){
    for(int j = 0; j < M * size; j++){
      mpz_clear(PreMul_R[i][j]);
    }
    free(PreMul_R[i]);
  }
  free(PreMul_R);

  mpz_t t_temp;
  mpz_init(t_temp);

  for (int j = 0; j < size; j++){
    for(int i = 1; i < M; i++){
      ss->modInv(t_temp, PreMul_U[0][i-1]);
      ss->modMul(PreMul_W[0][i*size + j], PreMul_V[0][(i-1)*size + j], t_temp);
      ss->modMul(PreMul_W[1][i*size + j], PreMul_V[1][(i-1)*size + j], t_temp);
    }
  }

  for(int i = 0; i < 2; i++){
    for(int j = 0; j < M * size; j++){
      mpz_clear(PreMul_V[i][j]);
    }
    free(PreMul_V[i]);
  }
  free(PreMul_V);

  mpz_clear(t_temp);

  mpz_t** PreMul_temp = (mpz_t**)malloc(sizeof(mpz_t*) * 2);
  for(int i = 0; i < 2; i++){
    PreMul_temp[i] = (mpz_t*)malloc(sizeof(mpz_t) * M * size);
    for(int j = 0; j < M * size; j++){
      mpz_init(PreMul_temp[i][j]);
    }
  }

  ss->modInv(PreMul_temp[0], PreMul_U[0], M * size);
  ss->modMul(PreMul_S[0], PreMul_S[0], PreMul_temp[0], M * size);
  ss->modMul(PreMul_S[1], PreMul_S[1], PreMul_temp[0], M * size);

  for(int i = 0; i < 2; i++){
    for(int j = 0; j < M * size; j++){
      mpz_clear(PreMul_temp[i][j]);
    }
    free(PreMul_temp[i]);
  }
  free(PreMul_temp);

  for(int i = 0; i < 2; i++){
    for(int j = 0; j < M * size; j++){
      mpz_clear(PreMul_U[i][j]);
    }
    free(PreMul_U[i]);
  }
  free(PreMul_U);


  mpz_t* mulBufferExtra1 = (mpz_t*)malloc(sizeof(mpz_t) * (2*M*size));
  mpz_t* mulBufferExtra2 = (mpz_t*)malloc(sizeof(mpz_t) * (2*M*size));
  mpz_t* mulBufferExtra3 = (mpz_t*)malloc(sizeof(mpz_t) * (2*M*size));
  for(int j = 0; j < 2*M*size; j++){
    mpz_init(mulBufferExtra1[j]);
    mpz_init(mulBufferExtra2[j]);
    mpz_init(mulBufferExtra3[j]);
  }
  for(int i = 0; i < M; i++){
    for(int j = 0; j < size; j++){
      mpz_set(mulBufferExtra1[i*size + j], BitLT_d[0][i][j]);
      mpz_set(mulBufferExtra2[i*size + j], PreMul_W[0][i*size + j]);
      mpz_set(mulBufferExtra1[M*size + i*size + j], BitLT_d[0][i][j]);
      mpz_set(mulBufferExtra2[M*size + i*size + j], PreMul_W[1][i*size + j]);
    }
  }

  for(int i = 0; i < 2; i++){
    for(int j = 0; j < M * size; j++){
      mpz_clear(PreMul_W[i][j]);
    }
    free(PreMul_W[i]);
  }
  free(PreMul_W);

  Mul->doOperation(mulBufferExtra3, mulBufferExtra1, mulBufferExtra2, 2*M*size, threadID);//Round 5

  //net.getSummary("", false);

  for(int j = 0; j < 2*M*size; j++){
    mpz_clear(mulBufferExtra1[j]);
    mpz_clear(mulBufferExtra2[j]);
  }
  free(mulBufferExtra1);
  free(mulBufferExtra2);

  mpz_t** PreMul_results = (mpz_t**)malloc(sizeof(mpz_t*) * 2);
  for(int i = 0; i < 2; i ++){
    PreMul_results[i] = (mpz_t*)malloc(sizeof(mpz_t) * M * size);
    for(int j = 0; j < M * size; j++){
      mpz_init(PreMul_results[i][j]);
    }
  }

  for(int i = 0; i < size*M; ++i){
    mpz_set(PreMul_results[0][i], mulBufferExtra3[i]);
    mpz_set(PreMul_results[1][i], mulBufferExtra3[i + size*M]);
  }

  for(int j = 0; j < 2*M*size; j++){
    mpz_clear(mulBufferExtra3[j]);
  }
  free(mulBufferExtra3);

  ms->pushBuffer(PreMul_results[0], PreMul_results[1], size * M);

  //ms->check_ver(PreMul_results, size * M);

  ms->verify();

  //net.getSummary("", false);

  mpz_t** PreMul_buffer3 = (mpz_t**)malloc(sizeof(mpz_t*) * peers);
  for(int i = 0; i < peers; i++){
    PreMul_buffer3[i] = (mpz_t*)malloc(sizeof(mpz_t) * M * size);
    for(int j = 0; j < M * size; j++)
      mpz_init(PreMul_buffer3[i][j]);
  }

  net.broadcastToPeers(PreMul_results[0], size * M, PreMul_buffer3, threadID);  //Round 5'
  ms->reconstructSecretCheck(PreMul_results[0], PreMul_buffer3, size * M, true);

  for(int i = 0; i < peers; i++){
    for(int j = 0; j < M * size; j++)
      mpz_clear(PreMul_buffer3[i][j]);
    free(PreMul_buffer3[i]);
  }
  free(PreMul_buffer3);

  //net.getSummary("", false);

  mpz_t** PreMul_temp1 = (mpz_t**)malloc(sizeof(mpz_t*) * 2);
  for(int i = 0; i < 2; i++){
    PreMul_temp1[i] = (mpz_t*)malloc(sizeof(mpz_t) * size);
    for(int j = 0; j < size; j++){
      mpz_init(PreMul_temp1[i][j]);
    }
  }

  for(int i = 0; i < size; i++){
    mpz_set(PreMul_temp1[0][i], PreMul_results[0][i]);
    mpz_set(PreMul_temp1[1][i], PreMul_results[1][i]);
  }

  for(int i = 1; i < M; i++){
    for(int j = 0; j < size; j++){
      ss->modMul(PreMul_temp1[0][j], PreMul_temp1[0][j], PreMul_results[0][i*size + j]);
      ss->modMul(BitLT_d[0][i][j], PreMul_S[0][i*size + j], PreMul_temp1[0][j]);
      ss->modMul(BitLT_d[1][i][j], PreMul_S[1][i*size + j], PreMul_temp1[0][j]);
    }
  }

  for(int i = 0; i < 2; i++){
    for(int j = 0; j < M * size; j++){
      mpz_clear(PreMul_S[i][j]);
      mpz_clear(PreMul_results[i][j]);
    }
    free(PreMul_S[i]);
    free(PreMul_results[i]);
  }
  free(PreMul_S);
  free(PreMul_results);

  for(int i = 0; i < 2; i++){
    for(int j = 0; j < size; j++){
      mpz_clear(PreMul_temp1[i][j]);
    }
    free(PreMul_temp1[i]);
  }
  free(PreMul_temp1);


  /*PreMul-End*/


  mpz_t BitLT_tmp;
  mpz_init(BitLT_tmp);

  mpz_t** BitLT_temp2 = (mpz_t**)malloc(sizeof(mpz_t*) * 2);
  for(int k = 0; k < 2; k++){
    BitLT_temp2[k] = (mpz_t*)malloc(sizeof(mpz_t) * M);
    for(int i = 0; i < M; i++){
      mpz_init(BitLT_temp2[k][i]);
    }
  }

  for(int j = 0; j < size; j++){
    mpz_set_ui(BitLT_temp[0][j], 0);
    mpz_set_ui(BitLT_temp[1][j], 0);
    for(int i = 0; i < M; i++){
      mpz_set(BitLT_temp2[0][i], BitLT_d[0][M-1-i][j]);
      mpz_set(BitLT_temp2[1][i], BitLT_d[1][M-1-i][j]);
    }

    for(int i = 0; i < M-1; i++){
      ss->modSub(BitLT_temp2[0][i], BitLT_temp2[0][i], BitLT_temp2[0][i+1]);
      ss->modSub(BitLT_temp2[1][i], BitLT_temp2[1][i], BitLT_temp2[1][i+1]);
    }
    ss->modSub(BitLT_temp2[0][M-1], BitLT_temp2[0][M-1], const1);
    ss->modSub(BitLT_temp2[1][M-1], BitLT_temp2[1][M-1], ms->r);

    for(int i = 0; i < M; i++){
      ss->modSub(BitLT_tmp, const1, BitLT_a[0][j][i]);
      ss->modMul(BitLT_tmp, BitLT_temp2[0][i], BitLT_tmp);
      ss->modAdd(BitLT_tmp, BitLT_tmp, BitLT_temp[0][j]);
      mpz_set(BitLT_temp[0][j], BitLT_tmp);
      ss->modSub(BitLT_tmp, ms->r, BitLT_a[1][j][i]);
      ss->modMul(BitLT_tmp, BitLT_temp2[0][i], BitLT_tmp);
      ss->modAdd(BitLT_tmp, BitLT_tmp, BitLT_temp[1][j]);
      mpz_set(BitLT_temp[1][j], BitLT_tmp);
    }
  }

  mpz_clear(const1);

  for(int k = 0; k < 2; k++){
    for(int i = 0; i < M; i++){
      for(int j = 0; j < size; j++){
        mpz_clear(BitLT_d[k][i][j]);
      }
      free(BitLT_d[k][i]);
    }
    free(BitLT_d[k]);
    for(int i = 0; i < size; i++){
      for(int j = 0; j < M; j++){
        mpz_clear(BitLT_a[k][i][j]);
      }
      free(BitLT_a[k][i]);
    }
    free(BitLT_a[k]);
  }
  free(BitLT_d);
  free(BitLT_a);

  for(int k = 0; k < 2; k++){
    for(int i = 0; i < M; i++){
      mpz_clear(BitLT_temp2[k][i]);
    }
    free(BitLT_temp2[k]);
  }
  free(BitLT_temp2);

  mpz_clear(BitLT_tmp);


  /*Mod2 start*/


  mpz_t constM1, const2M1;
  mpz_init_set_ui(constM1, M-1);
  mpz_init(const2M1);
  ss->modPow(const2M1, const2, constM1);

  mpz_t** Mod2_C = (mpz_t**)malloc(sizeof(mpz_t*) * 2);
  for(int k = 0; k < 2; k++){
    Mod2_C[k] = (mpz_t*)malloc(sizeof(mpz_t) * size);
    for(int i = 0; i < size; i++){
      mpz_init(Mod2_C[k][i]);
    }
  }

  ss->modAdd(Mod2_C[0], BitLT_temp[0], Mod2_R[0][0], size);
  ss->modAdd(Mod2_C[1], BitLT_temp[1], Mod2_R[1][0], size);

  for(int k = 0; k < 2; k++){
    for(int i = 0; i < size; i++){
      mpz_clear(BitLT_temp[k][i]);
    }
    free(BitLT_temp[k]);
  }
  free(BitLT_temp);

  ss->modMul(Mod2_S[0], Mod2_S[0], const2, size);
  ss->modMul(Mod2_S[1], Mod2_S[1], const2, size);
  if(M > 1){
    ss->modAdd(Mod2_C[0], Mod2_C[0], const2M1, size);
    ss->modMul(const2M1, const2M1, ms->r);
    ss->modAdd(Mod2_C[1], Mod2_C[1], const2M1, size);
  }

  mpz_clear(constM1);
  mpz_clear(const2M1);

  ss->modAdd(Mod2_C[0], Mod2_C[0], Mod2_S[0], size);
  ss->modAdd(Mod2_C[1], Mod2_C[1], Mod2_S[1], size);

  for(int k = 0; k < 2; k++){
    for(int i = 0; i < size; i++)
      mpz_clear(Mod2_S[k][i]);
    free(Mod2_S[k]);
  }
  free(Mod2_S);

  mpz_t** Mod2_shares = (mpz_t**)malloc(sizeof(mpz_t*) * peers);
  for(int i = 0; i < peers; i++){
    Mod2_shares[i] = (mpz_t*)malloc(sizeof(mpz_t) * size);
    for(int j = 0; j < size; j++)
      mpz_init(Mod2_shares[i][j]);
  }

  net.broadcastToPeers(Mod2_C[0], size, Mod2_shares, threadID);
  ms->reconstructSecretCheck(Mod2_C[0], Mod2_shares, size, true);

  for(int i = 0; i < peers; i++){
    for(int j = 0; j < size; j++)
      mpz_clear(Mod2_shares[i][j]);
    free(Mod2_shares[i]);
  }
  free(Mod2_shares);

  //net.getSummary("", false);

  mpz_t* Mod2_Bit = (mpz_t*)malloc(sizeof(mpz_t));
  mpz_init(Mod2_Bit[0]);

  for(int i = 0; i < size; i++){
    binarySplit(Mod2_C[0][i], Mod2_Bit, 1);
    mpz_set(Mod2_C[0][i], Mod2_Bit[0]);
  }

  mpz_clear(Mod2_Bit[0]);
  free(Mod2_Bit);

  mpz_t** U = (mpz_t**)malloc(sizeof(mpz_t*) * 2);
  for(int k = 0; k < 2; k++){
    U[k] = (mpz_t*)malloc(sizeof(mpz_t) * size);
    for(int i = 0; i < size; i++){
      mpz_init(U[k][i]);
    }
  }

  ss->modMul(U[0], Mod2_C[0], Mod2_R[0][0], size);
  ss->modMul(U[1], Mod2_C[0], Mod2_R[1][0], size);

  ss->modMul(U[0], U[0], const2, size);
  ss->modMul(U[1], U[1], const2, size);

  ss->modSub(U[0], Mod2_R[0][0], U[0], size);
  ss->modSub(U[1], Mod2_R[1][0], U[1], size);

  for(int k = 0; k < 2; k++){
    for(int i = 0; i < 2; i++){
      for(int j = 0; j < size; j++)
        mpz_clear(Mod2_R[k][i][j]);
      free(Mod2_R[k][i]);
    }
    free(Mod2_R[k]);
  }
  free(Mod2_R);

  ss->modAdd(U[0], U[0], Mod2_C[0], size);
  ss->modMul(Mod2_C[1], Mod2_C[0], ms->r, size);
  ss->modAdd(U[1], U[1], Mod2_C[1], size);

  for(int k = 0; k < 2; k++){
    for(int i = 0; i < size; i++){
      mpz_clear(Mod2_C[k][i]);
    }
    free(Mod2_C[k]);
  }
  free(Mod2_C);


  /*Mod2 end*/


  /*BitLT end*/



  ss->modMul(U[0], U[0], pow2M, size);
  ss->modMul(U[1], U[1], pow2M, size);

  ss->modAdd(result[0], C[0], U[0], size);
  ss->modAdd(result[1], C[1], U[1], size);

  ss->modSub(result[0], result[0], R[0][M], size);
  ss->modSub(result[1], result[1], R[1][M], size);

  ms->pushBuffer(result[0], result[1], size);

  // free the memory
  for(int k = 0; k < 2; k++){
    for(int i = 0; i < M+2; i++){
      for(int j = 0; j < size; j++)
        mpz_clear(R[k][i][j]);
      free(R[k][i]);
    }
    free(R[k]);
  }
  free(R);

  for(int k = 0; k < 2; k++){
    for(int i = 0; i < size; i++){
      mpz_clear(U[k][i]);
      mpz_clear(C[k][i]);
    }
    free(U[k]);
    free(C[k]);
  }
  free(U);
  free(C);

  mpz_clear(const2);
  mpz_clear(constK1);
  mpz_clear(constM);
  mpz_clear(pow2M);
  mpz_clear(pow2K1);

  //printf("End %s\n", __PRETTY_FUNCTION__);
}
