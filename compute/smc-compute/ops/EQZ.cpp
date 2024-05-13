/*
 *  PICCO: A General Purpose Compiler for Private Distributed Computation
 ** Copyright (C) 2013 PICCO Team
 ** Department of Computer Science and Engineering, University of Notre Dame
 *
 *  PICCO is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  PICCO is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with PICCO. If not, see <http://www.gnu.org/licenses/>.
 */

/* NOTE This file has been modified from its original form for use in the applied-crypto-lab/biom-auth codebase */

#include "EQZ.h"


EQZ::EQZ(NodeNetwork nodeNet, std::map<std::string, std::vector<int> > poly, int NodeID, SecretShare *s, mpz_t coefficients[]) {

  PreMul = new PrefixMultiplication(nodeNet,poly,NodeID,s,coefficients);
  Rand = new Random(nodeNet, poly, NodeID, s);

  net = nodeNet;
  id = NodeID;
  ss = s;

  for (int i = 0; i < 9; i++){ //Not optimal, pass this thing by pointer somehow
    mpz_init(coef[i]);
    mpz_set(coef[i],coefficients[i]);
  }
}

EQZ::EQZ(NodeNetwork nodeNet, std::map<std::string, std::vector<int> > poly, int NodeID, SecretShare *s, mpz_t coefficients[], MaliciousSMC *malicious) {

  PreMul = new PrefixMultiplication(nodeNet,poly,NodeID,s,coefficients);
  Rand = new Random(nodeNet, poly, NodeID, s);
  Mul = new Mult(nodeNet, NodeID, s);;
  net = nodeNet;
  id = NodeID;
  ss = s;
  ms = malicious;

  for (int i = 0; i < 9; i++){ //Not optimal, pass this thing by pointer somehow
    mpz_init(coef[i]);
    mpz_set(coef[i],coefficients[i]);
  }
}

EQZ::~EQZ() {}



void EQZ::doOperation(mpz_t* shares, mpz_t* result, int K, int size, int threadID){
  int peers = ss->getPeers();
  int m = ceil(log2(K));
  mpz_t* S = (mpz_t*)malloc(sizeof(mpz_t) * size);
  mpz_t* bitK = (mpz_t*)malloc(sizeof(mpz_t) * K);
  mpz_t* bitm = (mpz_t*)malloc(sizeof(mpz_t) * m);
  mpz_t** resultShares = (mpz_t**)malloc(sizeof(mpz_t*)*peers);
  mpz_t* C = (mpz_t*)malloc(sizeof(mpz_t) * size);
  mpz_t* c = (mpz_t*)malloc(sizeof(mpz_t) * size);
  mpz_t* sum = (mpz_t*)malloc(sizeof(mpz_t) * size);
  mpz_t temp1, temp2, const1, const2, constK, constm, const2K, const2m;

  //initialization
  mpz_init(temp1);
  mpz_init(temp2);
  mpz_init_set_ui(const1, 1);
  mpz_init_set_ui(const2, 2);
  mpz_init_set_ui(constK, K);
  mpz_init_set_ui(constm, m);
  mpz_init(const2K);
  mpz_init(const2m);

  for(int i = 0; i < K; i++)
    mpz_init(bitK[i]);
  for(int i = 0; i < m; i++)
    mpz_init(bitm[i]);

  for(int i=0; i<size; ++i){
    mpz_init(C[i]);
    mpz_init(c[i]);
    mpz_init(S[i]);
    mpz_init(sum[i]);
  }

  for(int i=0; i<peers; ++i){
    resultShares[i] = (mpz_t*)malloc(sizeof(mpz_t) * size);
    for(int j=0; j<size; ++j)
      mpz_init(resultShares[i][j]);
  }

  ////////////////////////// EQZ (PART 1): LINE 1-3 ///////////////////////////
  mpz_t** V = (mpz_t**)malloc(sizeof(mpz_t*) * (K+2));
  for(int i=0; i<K+2; ++i){
    V[i] = (mpz_t*)malloc(sizeof(mpz_t) * size);
    for(int j=0; j<size; ++j)
      mpz_init(V[i][j]);
  }

  Rand->PRandM(K, K, size, V, threadID);
  ss->modAdd(C, shares, V[K], size);
  Rand->PRandInt(K, K, size, S, threadID);
  ss->modPow(const2K, const2, constK);
  ss->modMul(S, S, const2K, size);
  ss->modAdd(C, C, S, size);
  net.broadcastToPeers(C, size, resultShares, threadID);
  ss->reconstructSecret(c, resultShares, size, true);
  for(int i = 0; i < size; i++){
    binarySplit(c[i], bitK, K);
    for(int j = 0; j < K; j++){
      ss->modAdd(temp1, bitK[j], V[j][i]);
      ss->modMul(temp2, bitK[j], V[j][i]);
      ss->modMul(temp2, temp2, const2);
      ss->modSub(temp1, temp1, temp2);
      ss->modAdd(sum[i], sum[i], temp1);
    }
  }
  for(int i=0; i<K+2; ++i){
    for(int j=0; j<size; ++j)
      mpz_clear(V[i][j]);
    free(V[i]);
  }
  free(V);
  ////////////////////////// EQZ (PART 2): LINE 1-5 of KOrCL ///////////////////////////
  mpz_t** U = (mpz_t**)malloc(sizeof(mpz_t*) * (m+2));
  for(int i = 0; i < m+2; i++) {
    U[i] = (mpz_t*)malloc(sizeof(mpz_t)*size);
    for (int j = 0; j < size; j++)
      mpz_init(U[i][j]);
  }
  Rand->PRandM(K, m, size, U, threadID);
  Rand->PRandInt(K, m, size, S, threadID);

  ss->modAdd(C, sum, U[m], size);
  ss->modPow(const2m, const2, constm);
  ss->modMul(S, S, const2m, size);
  ss->modAdd(C, C, S, size);
  //	for(int i = 0; i < size; i++)
  //		ss->modAdd(C[i], C[i], S[0]);
  //	for(int i = 0; i < size; i++)
  //		ss->modAdd(C[i], U[m][0], sum[i]);

  net.broadcastToPeers(C, size, resultShares, threadID);
  ss->reconstructSecret(c,resultShares, size,true);
  for(int i = 0; i < size; i++){
    binarySplit(c[i], bitm, m);
    mpz_set_ui(sum[i], 1);        //NOTE changed from 0
    for(int j = 0; j < m; j++){
      ss->modAdd(temp1,bitm[j],U[j][0]);
      ss->modMul(temp2,bitm[j],U[j][0]);
      ss->modMul(temp2,const2,temp2);
      ss->modSub(temp1,temp1,temp2);
      ss->modAdd(sum[i],sum[i],temp1);
    }
  }

  for(int i = 0; i < m+2; i++){
    mpz_clear(U[i][0]);
    free(U[i]);
  }
  free(U);
  ////////////////////////// EQZ (PART 3): evaluate symmetric function  ///////////////////////////
  mpz_t** T = (mpz_t**)malloc(sizeof(mpz_t*) * m);
  for(int i=0; i<m; ++i){
    T[i] = (mpz_t*)malloc(sizeof(mpz_t) * size);
    for(int j=0; j<size; ++j){
      mpz_init(T[i][j]);
    }
  }
  for(int i = 0; i < m; i++)
    ss->copy(sum, T[i], size);
  PreMul->doOperation(T, T, m, size, threadID);
  for(int i = 0; i < size; i++){
    mpz_set(temp2, coef[m]);
    mpz_set_ui(result[i], 0);
    ss->modAdd(result[i],result[i], temp2);
    for(int j = 0; j < m; j++){
      mpz_set(temp2,coef[m-j-1]);
      ss->modMul(temp1,T[j][i],temp2);
      ss->modAdd(result[i], result[i], temp1);
    }
    ss->modSub(result[i],const1,result[i]);
  }

  /*Free the memory*/
  mpz_clear(temp1);
  mpz_clear(temp2);
  mpz_clear(const2);
  mpz_clear(const2K);
  mpz_clear(const2m);
  mpz_clear(constm);
  mpz_clear(constK);
  mpz_clear(const1);

  for(int i=0; i<size; ++i){
    mpz_clear(C[i]);
    mpz_clear(c[i]);
    mpz_clear(sum[i]);
    mpz_clear(S[i]);
  }
  free(C);
  free(c);
  free(sum);
  free(S);

  for(int i = 0; i < K; i++)
    mpz_clear(bitK[i]);
  free(bitK);

  for(int i = 0; i < m; i++)
    mpz_clear(bitm[i]);
  free(bitm);

  for(int i=0; i<peers; ++i){
    for(int j=0; j<size; ++j)
      mpz_clear(resultShares[i][j]);
    free(resultShares[i]);
  }
  free(resultShares);

  for(int i=0; i<m; ++i){
    for(int j=0; j<size; ++j){
      mpz_clear(T[i][j]);
    }
    free(T[i]);
  }
  free(T);
}




void EQZ::doOperation_mal(mpz_t** shares, mpz_t** result, int K, int size, int threadID)
{
  int peers = ss->getPeers();
  int m = ceil(log2(K));

  mpz_t temp1, temp2, const1, const2, constK, constm, const2K, const2m;

  //initialization
  mpz_init(temp1);
  mpz_init(temp2);
  mpz_init_set_ui(const1, 1);
  mpz_init_set_ui(const2, 2);
  mpz_init_set_ui(constK, K);
  mpz_init_set_ui(constm, m);
  mpz_init(const2K);
  mpz_init(const2m);

  mpz_t inv2;
  mpz_init_set_ui(inv2, 2);
  ss->modInv(inv2, inv2);

  // removing S_temp
  //  mpz_t* S_temp = (mpz_t*)malloc(sizeof(mpz_t) * (1));
  //  mpz_init(S_temp[0]);

  ////////////////////// EQZ (PART 1): LINE 1-3 /////////////////////

  //  mpz_set(S[0][size], S_temp[0]);
  //mpz_clear(S_temp[0]);
  //free(S_temp);
  //Rand->PRandM(K, K, size+1, V, threadID);
  //PRand:
  unsigned long PRandM_pow = 1;

  //PRandBit(size*K+m, PRandM_tempResult);
  //PRandBit:
  int PRandBit_size = size*(K+m); // previously size*K+m
  mpz_t** PRandBit_resultShares = (mpz_t**)malloc(sizeof(mpz_t*) * peers);

  // replaced PRandBit_size+m with PRandBit_size+m*size
  for(int i = 0; i < peers; i++){
    PRandBit_resultShares[i] = (mpz_t*)malloc(sizeof(mpz_t) * (PRandBit_size + m*size));
    for(int j = 0; j < PRandBit_size+m*size; j++)
      mpz_init(PRandBit_resultShares[i][j]);
  }

  mpz_t** PRandBit_u = (mpz_t**)malloc(sizeof(mpz_t*) * 2);
  for(int i = 0; i < 2; i++){
    PRandBit_u[i] = (mpz_t*)malloc(sizeof(mpz_t) * PRandBit_size);
    for(int j = 0; j < PRandBit_size; j++){
      mpz_init(PRandBit_u[i][j]);
    }
  }

  mpz_t** PreMul_R = (mpz_t**)malloc(sizeof(mpz_t*) * 2);
  mpz_t** PreMul_S = (mpz_t**)malloc(sizeof(mpz_t*) * 2);
  for(int i = 0; i < 2; i++){
    // previous allocation is m elements
    PreMul_R[i] = (mpz_t*)malloc(sizeof(mpz_t) * m * size);
    PreMul_S[i] = (mpz_t*)malloc(sizeof(mpz_t) * m * size);
    for(int j = 0; j < m * size; j++){
      mpz_init(PreMul_R[i][j]);
      mpz_init(PreMul_S[i][j]);
    }
  }

  mpz_t field;
  mpz_init(field);
  ss->getFieldSize(field);
  Rand->generateRandValue(id, field, PRandBit_size, PRandBit_u[0]); //(K+m)*size, previously K*size+m
  Rand->generateRandValue(id, field, m*size, PreMul_R[0]);              //m*size, previously m
  Rand->generateRandValue(id, field, m*size, PreMul_S[0]);              //m*size, previously m
  //Malicious Check: multiply r
  //S[size+1] || PRandBit_u[K*size+m] || PreMul_R[m] || PreMul_S[m]

  mpz_t** inputBuffer_mal = (mpz_t**)malloc(sizeof(mpz_t*) * 2);
  unsigned int inputBuffer_size = (K + 3*m + 2)*size; // previously size+1+K*size+3*m

  for(int i = 0; i < 2; i++){
    inputBuffer_mal[i] = (mpz_t*)malloc(sizeof(mpz_t) * inputBuffer_size);
    for(int j = 0; j < inputBuffer_size; j++){
      mpz_init(inputBuffer_mal[i][j]);
    }
  }
  mpz_t* randR = (mpz_t*)malloc(sizeof(mpz_t) * inputBuffer_size);
  for(int i = 0; i < inputBuffer_size; i++){
    mpz_init_set(randR[i], ms->r);
  }

  mpz_t** S = (mpz_t**)malloc(sizeof(mpz_t*) * 2);
  // this seems to be for 2*size RandInt, previously size+1
  for(int i = 0; i < 2; i++){
    S[i] = (mpz_t*)malloc(sizeof(mpz_t) * 2*(size));
    for(int j = 0; j < 2*size; j++){
      mpz_init(S[i][j]);
    }
  }

  Rand->PRandInt(K, K, size, S[0], threadID);
  Rand->PRandInt(K, m, size, S[0]+size, threadID);

  int inputBuffer_p = 0;

  // copy RandInt random values
  for(int i = 0; i < 2*size; i++){
    mpz_set(inputBuffer_mal[0][inputBuffer_p], S[0][i]);
    inputBuffer_p++;
  }
  // copy RandBit random values
  for(int i = 0; i < (K+m)*size; i++){
    mpz_set(inputBuffer_mal[0][inputBuffer_p], PRandBit_u[0][i]);
    inputBuffer_p++;
  }
  // copy premul random values
  for(int i = 0; i < m*size; i++){
    mpz_set(inputBuffer_mal[0][inputBuffer_p], PreMul_R[0][i]);
    inputBuffer_p++;
  }
  for(int i = 0; i < m*size; i++){
    mpz_set(inputBuffer_mal[0][inputBuffer_p], PreMul_S[0][i]);
    inputBuffer_p++;
  }

  Mul->doOperation(inputBuffer_mal[1], randR, inputBuffer_mal[0], inputBuffer_size, -1);
  ms->pushBuffer(inputBuffer_mal[0], inputBuffer_mal[1], inputBuffer_size);

  //Should we check this?
  inputBuffer_p = 0;

  for(int i = 0; i < 2*size; i++){
    mpz_set(S[1][i], inputBuffer_mal[1][inputBuffer_p]);
    inputBuffer_p++;
  }
  for(int i = 0; i < (K+m)*size; i++){
    mpz_set(PRandBit_u[1][i], inputBuffer_mal[1][inputBuffer_p]);
    inputBuffer_p++;
  }
  for(int i = 0; i < m*size; i++){
    mpz_set(PreMul_R[1][i], inputBuffer_mal[1][inputBuffer_p]);
    inputBuffer_p++;
  }
  for(int i = 0; i < m*size; i++){
    mpz_set(PreMul_S[1][i], inputBuffer_mal[1][inputBuffer_p]);
    inputBuffer_p++;
  }

  for(int i=0; i<2; ++i){
    for(int j=0; j<inputBuffer_size; ++j)
      mpz_clear(inputBuffer_mal[i][j]);
    free(inputBuffer_mal[i]);
  }
  free(inputBuffer_mal);

  for(int i = 0; i < inputBuffer_size; i++){
    mpz_clear(randR[i]);
  }
  free(randR);

  //Mulpub in RandBit, communication: (K + 2m)*size (previously K*size+2m)
  unsigned mulpub_size = PRandBit_size + m*size;
  mpz_t* mulBuffer2 = (mpz_t*)malloc(sizeof(mpz_t) * (mulpub_size));
  mpz_t* mulBuffer3 = (mpz_t*)malloc(sizeof(mpz_t) * (mulpub_size));
  for(int i = 0; i < mulpub_size; i++){
    mpz_init(mulBuffer2[i]);
    mpz_init(mulBuffer3[i]);
  }
  for(int i = 0; i < PRandBit_size; ++i) {
    mpz_set(mulBuffer2[i], PRandBit_u[0][i]);
    mpz_set(mulBuffer3[i], PRandBit_u[0][i]);
  }
  for(int i = 0; i < m*size; ++i) {
    mpz_set(mulBuffer2[i+PRandBit_size], PreMul_R[0][i]);
    mpz_set(mulBuffer3[i+PRandBit_size], PreMul_S[0][i]);
  }

  mpz_t** PRandBit_v = (mpz_t**)malloc(sizeof(mpz_t*) * 2);
  for(int i = 0; i < 2; i++){
    PRandBit_v[i] = (mpz_t*)malloc(sizeof(mpz_t) * (PRandBit_size + m*size));
    for(int j = 0; j < PRandBit_size + m*size; j++){
      mpz_init(PRandBit_v[i][j]);
    }
  }

  Mul->doOperation(PRandBit_v[0], mulBuffer2, mulBuffer3, mulpub_size, threadID);//Round 2

  for(int i = 0; i < mulpub_size; i++){
    mpz_clear(mulBuffer2[i]);
    mpz_clear(mulBuffer3[i]);
  }
  free(mulBuffer2);
  free(mulBuffer3);

  net.broadcastToPeers(PRandBit_v[0], mulpub_size, PRandBit_resultShares, -1); //Round 2'
  ms->reconstructSecretCheck(PRandBit_v[0], PRandBit_resultShares, mulpub_size, true);

  //Step 5 in PreMul along with Malicious check for the above Mulpub
  //communication: Mulpub check ((K+2m)*size) + Mul ((m - 1)*size) + Mulcheck ((m - 1)*size) = (K+4m-2)*size (previously Mulpub check (K*size + 2m) + Mul (m - 1) + Mulcheck (m - 1) = K*size + 4m - 2)

  //NOTE below is redundant given subsequent Mul->doOperation()

  //ss->modMul(PRandBit_v[1], PRandBit_u[0], PRandBit_u[1], PRandBit_size);
  //ss->modMul(PreMul_temp[1], PreMul_R[0], PreMul_S[1], m*size);

  //for(int i = 0; i < m*size; i++){
  //  mpz_set(PRandBit_v[1][PRandBit_size+i], PreMul_temp[1][i]);
  //}

  //for (int j = 0; j < size; j++){
  //  for(int i = 0; i < m-1; i++){
  //    ss->modMul(PreMul_V[0][i*size + j], PreMul_R[0][i*size + j + 1], PreMul_S[0][i*size + j]);
  //    ss->modMul(PreMul_V[1][i*size + j], PreMul_R[0][i*size + j + 1], PreMul_S[1][i*size + j]);
  //  }
  //}
  //

  //D->mark();

  unsigned mul_size = size*(K+4*m-2);
  mpz_t* mulBuffer_mal1 = (mpz_t*)malloc(sizeof(mpz_t) * mul_size);
  mpz_t* mulBuffer_mal2 = (mpz_t*)malloc(sizeof(mpz_t) * mul_size);
  mpz_t* mulBuffer_mal3 = (mpz_t*)malloc(sizeof(mpz_t) * mul_size);
  for(int i = 0; i < mul_size; i++){
    mpz_init(mulBuffer_mal1[i]);
    mpz_init(mulBuffer_mal2[i]);
    mpz_init(mulBuffer_mal3[i]);
  }

  int mulBuffer_pointer = 0;
  for(int i = 0; i < PRandBit_size; ++i) {
    mpz_set(mulBuffer_mal1[mulBuffer_pointer], PRandBit_u[0][i]);
    mpz_set(mulBuffer_mal2[mulBuffer_pointer], PRandBit_u[1][i]);
    mulBuffer_pointer++;
  }

  for(int i = 0; i < m*size; ++i) {
    mpz_set(mulBuffer_mal1[mulBuffer_pointer], PreMul_R[0][i]);
    mpz_set(mulBuffer_mal2[mulBuffer_pointer], PreMul_S[1][i]);
    mulBuffer_pointer++;
  }

  for (int j = 0; j < size; j++) {
    for(int i = 0; i < m-1; ++i) {
      mpz_set(mulBuffer_mal1[mulBuffer_pointer], PreMul_R[0][i*size + j+1]);
      mpz_set(mulBuffer_mal2[mulBuffer_pointer], PreMul_S[0][i*size + j]);
      mulBuffer_pointer++;
    }
  }

  for (int j = 0; j < size; j++) {
    for(int i = 0; i < m-1; ++i) {
      mpz_set(mulBuffer_mal1[mulBuffer_pointer], PreMul_R[0][i*size + j+1]);
      mpz_set(mulBuffer_mal2[mulBuffer_pointer], PreMul_S[1][i*size + j]);
      mulBuffer_pointer++;
    }
  }

  Mul->doOperation(mulBuffer_mal3, mulBuffer_mal2, mulBuffer_mal1, mul_size, threadID);//Round 3

  mulBuffer_pointer = 0;
  for(int i = 0; i < (K+2*m)*size; i++){
    mpz_set(PRandBit_v[1][i], mulBuffer_mal3[mulBuffer_pointer]);
    mulBuffer_pointer++;
  }

  mpz_t** PreMul_V = (mpz_t**)malloc(sizeof(mpz_t*) * 2);
  for(int i = 0; i < 2; i++){
    // previous allocation is m elements
    PreMul_V[i] = (mpz_t*)malloc(sizeof(mpz_t) * m * size);
    for(int j = 0; j < m * size; j++){
      mpz_init(PreMul_V[i][j]);
    }
  }

  for(int i = 0; i < (m-1)*size; i++){
    mpz_set(PreMul_V[0][i], mulBuffer_mal3[mulBuffer_pointer]);
    mulBuffer_pointer++;
  }
  for(int i = 0; i < (m-1)*size; i++){
    mpz_set(PreMul_V[1][i], mulBuffer_mal3[mulBuffer_pointer]);
    mulBuffer_pointer++;
  }

  ms->pushBuffer(PRandBit_v[0], PRandBit_v[1], (K+2*m)*size);
  ms->pushBuffer(PreMul_V[0], PreMul_V[1], (m-1) * size);

  //ms->check_ver(PRandBit_v, (K+2*m)*size);

  for(int i = 0; i < mul_size; i++){
    mpz_clear(mulBuffer_mal1[i]);
    mpz_clear(mulBuffer_mal2[i]);
    mpz_clear(mulBuffer_mal3[i]);
  }
  free(mulBuffer_mal1);
  free(mulBuffer_mal2);
  free(mulBuffer_mal3);

  mpz_t** PreMul_U = (mpz_t**)malloc(sizeof(mpz_t*) * 2);
  for(int i = 0; i < 1; i++){ //NOTE only using index 0, as in deallocation
    // previous allocation is m elements
    PreMul_U[i] = (mpz_t*)malloc(sizeof(mpz_t) * m * size);
    for(int j = 0; j < m * size; j++){
      mpz_init(PreMul_U[i][j]);
    }
  }

  for(int i = 0; i < m*size; i++){
    mpz_set(PreMul_U[0][i], PRandBit_v[0][PRandBit_size+i]);
  }

  mpz_t** PRandM_tempResult = (mpz_t**) malloc(sizeof(mpz_t*)  * 2);
  for(int i = 0; i < 2; i++){
    PRandM_tempResult[i] = (mpz_t*) malloc(sizeof(mpz_t)  * (size * (K + m))); // previously size*K + m
    for(int j = 0; j < (size * (K + m)); j++){
      mpz_init(PRandM_tempResult[i][j]);
    }
  }

  //Step 5 in PreMul along with Malicious check for the above Mulpub End
  //PRandBit Line 3 - 4 Normal branch
  ss->modSqrt(PRandBit_v[0], PRandBit_v[0], PRandBit_size); //Normal branch
  ss->modInv(PRandBit_v[0], PRandBit_v[0], PRandBit_size);//Normal branch
  ss->modMul(PRandM_tempResult[0], PRandBit_v[0], PRandBit_u[0], PRandBit_size);//Normal branch
  ss->modMul(PRandM_tempResult[1], PRandBit_v[0], PRandBit_u[1], PRandBit_size);  //Malicious branch

  ss->modAdd(PRandM_tempResult[0], PRandM_tempResult[0], const1, PRandBit_size);//Normal branch
  ss->modMul(PRandM_tempResult[0], PRandM_tempResult[0], inv2, PRandBit_size);//Normal branch
  ss->modAdd(PRandM_tempResult[1], PRandM_tempResult[1], ms->r, PRandBit_size);//Malicious branch
  ss->modMul(PRandM_tempResult[1], PRandM_tempResult[1], inv2, PRandBit_size);//Malicious branch

  mpz_clear(inv2);
  //mpz_clear(const1);
  for(int i = 0; i < peers; i++){
    for(int j = 0; j < PRandBit_size + m*size; j++)
      mpz_clear(PRandBit_resultShares[i][j]);
    free(PRandBit_resultShares[i]);
  }
  free(PRandBit_resultShares);

  for(int i = 0; i < 2; i++){
    for(int j = 0; j < PRandBit_size + m*size; j++){
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
  //PRandBit End

  //initialization PRandM
  mpz_t*** V = (mpz_t***)malloc(sizeof(mpz_t**) * 2); //For PRandM
  for(int i = 0; i < 2; i++){
    V[i] = (mpz_t**)malloc(sizeof(mpz_t*) * (K+2));
    for(int j = 0; j < K+2; j++){
      V[i][j] = (mpz_t*)malloc(sizeof(mpz_t) * (size+1));
      for(int kk = 0; kk < size + 1; kk++){
        mpz_init(V[i][j][kk]);
      }
    }
  }

  for (int i = 0; i < size; i++)
  {
    mpz_set(V[0][K][i], PRandM_tempResult[0][i]);
    mpz_set(V[0][0][i], PRandM_tempResult[0][i]);

    mpz_set(V[1][K][i], PRandM_tempResult[1][i]);
    mpz_set(V[1][0][i], PRandM_tempResult[1][i]);
  }

  // this used to be an array of size 2*(m+2)*1, but I changed it to be 2*(m+2)(size+1) for consistency with the above; not sure where +2 or +1 come from and whether they are used
  mpz_t*** U = (mpz_t***)malloc(sizeof(mpz_t**) * 2); //For PRandM
  for(int i = 0; i < 2; i++){
    U[i] = (mpz_t**)malloc(sizeof(mpz_t*) * (m+2));
    for(int j = 0; j < m+2; j++){
      U[i][j] = (mpz_t*)malloc(sizeof(mpz_t)*(size+1));
      for (int kk = 0; kk < size + 1; kk++)
        mpz_init(U[i][j][kk]);
    }
  }

  mpz_set(U[0][m][0], PRandM_tempResult[0][size*K]);
  mpz_set(U[0][0][0], PRandM_tempResult[0][size*K]);

  mpz_set(U[1][m][0], PRandM_tempResult[1][size*K]);
  mpz_set(U[1][0][0], PRandM_tempResult[1][size*K]);

  mpz_t** PRandM_temp = (mpz_t**) malloc(sizeof(mpz_t*)  * 2);
  for(int i = 0; i < 2; i++){
    PRandM_temp[i] = (mpz_t*) malloc(sizeof(mpz_t)  * (size+1)); // leaving at size+1
    for(int j = 0; j < size+1; j++){
      mpz_init(PRandM_temp[i][j]);
    }
  }

  for (int i = 1; i < K; i++) {
    PRandM_pow = PRandM_pow << 1;
    for (int j = 0; j < size; j++) {
      mpz_set(V[0][i][j], PRandM_tempResult[0][i * size + j]);
      mpz_mul_ui(PRandM_temp[0][j], V[0][i][j], PRandM_pow);

      mpz_set(V[1][i][j], PRandM_tempResult[1][i * size + j]);
      mpz_mul_ui(PRandM_temp[1][j], V[1][i][j], PRandM_pow);
    }
    ss->modAdd(V[0][K], V[0][K], PRandM_temp[0], size);
    ss->modAdd(V[1][K], V[1][K], PRandM_temp[1], size);
  }
  PRandM_pow = 1;
  for (int i = 1; i < m; i++) {
    PRandM_pow = PRandM_pow << 1;

    for (int j = 0; j < size; j++) {
      mpz_set(U[0][i][j], PRandM_tempResult[0][size*(K+i) + j]);
      mpz_set(U[1][i][j], PRandM_tempResult[1][size*(K+i) + j]);

      mpz_mul_ui(PRandM_temp[0][j], U[0][i][j], PRandM_pow);
      mpz_mul_ui(PRandM_temp[1][j], U[1][i][j], PRandM_pow);
    }
    ss->modAdd(U[0][m], U[0][m], PRandM_temp[0], size);
    ss->modAdd(U[1][m], U[1][m], PRandM_temp[1], size);
  }

  for(int i = 0; i < 2; i++){
    for(int j = 0; j < (size * (K + m)); j++){
      mpz_clear(PRandM_tempResult[i][j]);
    }
    free(PRandM_tempResult[i]);
  }
  free(PRandM_tempResult);

  for(int i = 0; i < 2; i++){
    for(int j = 0; j < size+1; j++){
      mpz_clear(PRandM_temp[i][j]);
    }
    free(PRandM_temp[i]);
  }
  free(PRandM_temp);

  //PRandM End
  //Line 2 in EQZ

  mpz_t** C = (mpz_t**)malloc(sizeof(mpz_t*) * 2);
  for(int i = 0; i < 2; i++){
    C[i] = (mpz_t*)malloc(sizeof(mpz_t) * size);
    for(int j = 0; j < size; j++){
      mpz_init(C[i][j]);
    }
  }

  ss->modAdd(C[0], shares[0], V[0][K], size); //normal branch
  ss->modAdd(C[1], shares[1], V[1][K], size); //Malicious branch

  ss->modPow(const2K, const2, constK);

  ss->modMul(S[0], S[0], const2K, size); //normal branch
  ss->modMul(S[1], S[1], const2K, size); //Malicious branch

  ss->modAdd(C[0], C[0], S[0], size); //normal branch
  ss->modAdd(C[1], C[1], S[1], size); //Malicious branch

  ms->verify();

  mpz_t** resultShares = (mpz_t**)malloc(sizeof(mpz_t*)*peers);
  for(int i=0; i<peers; ++i){
    resultShares[i] = (mpz_t*)malloc(sizeof(mpz_t) * size);
    for(int j=0; j<size; ++j)
      mpz_init(resultShares[i][j]);
  }

  net.broadcastToPeers(C[0], size, resultShares, threadID); //Round 4

  mpz_t* c = (mpz_t*) malloc(sizeof(mpz_t) * size);
  for(int i = 0; i < size; ++i){
    mpz_init(c[i]);
  }

  ms->reconstructSecretCheck(c, resultShares, size, true);

  mpz_t** bitK = (mpz_t**)malloc(sizeof(mpz_t*) * 2);
  for(int i = 0; i < 2; i++){
    bitK[i] = (mpz_t*)malloc(sizeof(mpz_t) * K);
    for(int j = 0; j < K; j++)
      mpz_init(bitK[i][j]);
  }

  mpz_t** sum = (mpz_t**)malloc(sizeof(mpz_t*) * 2);
  for(int i = 0; i < 2; i++){
    sum[i] = (mpz_t*)malloc(sizeof(mpz_t) * size);
    for(int j = 0; j < size; j++){
      mpz_init(sum[i][j]);
    }
  }

  for(int i = 0; i < size; i++){
    binarySplit(c[i], bitK[0], K);
    ss->modMul(bitK[1], bitK[0], ms->r, K);
    for(int j = 0; j < K; j++){
      ss->modAdd(temp1, bitK[0][j], V[0][j][i]);  //normal branch
      ss->modMul(temp2, bitK[0][j], V[0][j][i]);
      ss->modMul(temp2, temp2, const2);
      ss->modSub(temp1, temp1, temp2);
      ss->modAdd(sum[0][i], sum[0][i], temp1);

      ss->modAdd(temp1, bitK[1][j], V[1][j][i]); //Malicious branch
      ss->modMul(temp2, bitK[0][j], V[1][j][i]);
      ss->modMul(temp2, temp2, const2);
      ss->modSub(temp1, temp1, temp2);
      ss->modAdd(sum[1][i], sum[1][i], temp1);
    }
  }

  for(int i = 0; i < 2; i++){
    for(int j = 0; j < K; j++)
      mpz_clear(bitK[i][j]);
    free(bitK[i]);
  }
  free(bitK);

  for(int i = 0; i < 2; i++){
    for(int j = 0; j < K+2; j++){
      for(int kk = 0; kk < size + 1; kk++){
        mpz_clear(V[i][j][kk]);
      }
      free(V[i][j]);
    }
    free(V[i]);
  }
  free(V);

  ////////////////////// EQZ (PART 2): LINE 1-5 of KOrCL /////////////////////
  //Rand->PRandM(K, m, 1, U, threadID);
  //Rand->PRandInt(K, m, 1, S, threadID);
  ss->modPow(const2m, const2, constm);
  //  ss->modMul(S[0][size], S[0][size], const2m);
  //ss->modMul(S[1][size], S[1][size], const2m);
  ss->modMul(S[0]+size, S[0]+size, const2m, size);
  ss->modMul(S[1]+size, S[1]+size, const2m, size);

  //last fine  here

  for(int i = 0; i < size; i++){
    ss->modAdd(C[0][i], C[0][i], S[0][size+i]);
    ss->modAdd(C[1][i], C[1][i], S[1][size+i]);
  }

  for(int i = 0; i < size; i++){
    ss->modAdd(C[0][i], U[0][m][i], sum[0][i]);
    ss->modAdd(C[1][i], U[1][m][i], sum[1][i]);
  }

  for(int i = 0; i < 2; i++){
    for(int j = 0; j < 2 * size; j++){
      mpz_clear(S[i][j]);
    }
    free(S[i]);
  }
  free(S);

  //ms->verify();

  net.broadcastToPeers(C[0], size, resultShares, threadID); //Round 5
  ms->reconstructSecretCheck(c,resultShares, size,true);

  for(int i=0; i<peers; ++i){
    for(int j=0; j<size; ++j)
      mpz_clear(resultShares[i][j]);
    free(resultShares[i]);
  }
  free(resultShares);

  for(int i = 0; i < 2; i++){
    for(int j = 0; j < size; j++){
      mpz_clear(C[i][j]);
    }
    free(C[i]);
  }
  free(C);

  mpz_t** bitm = (mpz_t**)malloc(sizeof(mpz_t*) * 2);
  for(int i = 0; i < 2; i++){
    bitm[i] = (mpz_t*)malloc(sizeof(mpz_t) * m);
    for(int j = 0; j < m; j++)
      mpz_init(bitm[i][j]);
  }

  for(int i = 0; i < size; i++){
    binarySplit(c[i], bitm[0], m);
    ss->modMul(bitm[1], bitm[0], ms->r, m);

    mpz_set_ui(sum[0][i], 1);  //NOTE changed from 0
    mpz_set(sum[1][i], ms->r);  //NOTE changed from 0

    for(int j = 0; j < m; j++){
      ss->modAdd(temp1,bitm[0][j],U[0][j][i]);//normal
      ss->modMul(temp2,bitm[0][j],U[0][j][i]);
      ss->modMul(temp2,const2,temp2);
      ss->modSub(temp1,temp1,temp2);
      ss->modAdd(sum[0][i],sum[0][i],temp1);

      ss->modAdd(temp1,bitm[1][j],U[1][j][i]);//malicious
      ss->modMul(temp2,bitm[0][j],U[1][j][i]);
      ss->modMul(temp2,const2,temp2);
      ss->modSub(temp1,temp1,temp2);
      ss->modAdd(sum[1][i],sum[1][i],temp1);
    }
  }

  for(int i = 0; i < size; ++i){
    mpz_clear(c[i]);
  }
  free(c);

  for(int i = 0; i < 2; i++){
    for(int j = 0; j < m; j++)
      mpz_clear(bitm[i][j]);
    free(bitm[i]);
  }
  free(bitm);

  for(int i = 0; i < 2; i++){
    for(int j = 0; j < m+2; j++){
      for (int kk = 0; kk < size+1; kk++)
        mpz_clear(U[i][j][kk]);
      free(U[i][j]);
    }
    free(U[i]);
  }
  free(U);

  ////////////////// EQZ (PART 3): evaluate symmetric function  //////////////////

  mpz_t*** T = (mpz_t***)malloc(sizeof(mpz_t**) * 2);
  for(int i=0; i<2; ++i){
    T[i] = (mpz_t**)malloc(sizeof(mpz_t*) * m);
    for(int j=0; j< m; ++j){
      T[i][j] = (mpz_t*)malloc(sizeof(mpz_t) * size);
      for(int kk = 0; kk < size; kk++){
        mpz_init(T[i][j][kk]);
      }
    }
  }


  for(int i = 0; i < m; i++){
    ss->copy(sum[0], T[0][i], size);
    ss->copy(sum[1], T[1][i], size);
  }

  for(int i = 0; i < 2; i++){
    for(int j = 0; j < size; j++){
      mpz_clear(sum[i][j]);
    }
    free(sum[i]);
  }
  free(sum);

  //PreMul->doOperation(T, T, m, size, threadID);
  //PreMul:
  mpz_t** PreMul_results = (mpz_t**)malloc(sizeof(mpz_t*) * 2);
  for(int i = 0; i < 2; i ++){
    PreMul_results[i] = (mpz_t*)malloc(sizeof(mpz_t) * m * size);
    for(int j = 0; j < m * size; j++){
      mpz_init(PreMul_results[i][j]);
    }
  }

  mpz_t** PreMul_W = (mpz_t**)malloc(sizeof(mpz_t*) * 2);
  for(int i = 0; i < 2; i++){
    // previous allocation is m elements
    PreMul_W[i] = (mpz_t*)malloc(sizeof(mpz_t) * m * size);
    for(int j = 0; j < m * size; j++){
      mpz_init(PreMul_W[i][j]);
    }
  }

  for (int i = 0; i < size; i++) {
    mpz_set(PreMul_W[0][i], PreMul_R[0][i]);
    mpz_set(PreMul_W[1][i], PreMul_R[1][i]);
  }

  for(int i = 0; i < 2; i++){
    for(int j = 0; j < m * size; j++){
      mpz_clear(PreMul_R[i][j]);
    }
    free(PreMul_R[i]);
  }
  free(PreMul_R);

  mpz_t t_temp;
  mpz_init(t_temp);

  for (int j = 0; j < size; j++){
    for(int i = 1; i < m; i++){
      ss->modInv(t_temp, PreMul_U[0][i-1]);
      ss->modMul(PreMul_W[0][i*size + j], PreMul_V[0][(i-1)*size + j], t_temp);
      ss->modMul(PreMul_W[1][i*size + j], PreMul_V[1][(i-1)*size + j], t_temp);
    }
  }
  mpz_clear(t_temp);

  ss->modInv(PreMul_U[0], PreMul_U[0], m * size);
  ss->modMul(PreMul_S[0], PreMul_S[0], PreMul_U[0], m * size);
  ss->modMul(PreMul_S[1], PreMul_S[1], PreMul_U[0], m * size);

  for(int i = 0; i < 1; i++){ //NOTE only using index 0, as in allocation
    for(int j = 0; j < m * size; j++){
      mpz_clear(PreMul_U[i][j]);
      mpz_clear(PreMul_V[i][j]);
    }
    free(PreMul_U[i]);
    free(PreMul_V[i]);
  }
  free(PreMul_U);
  free(PreMul_V);

  mpz_t* mulBufferExtra1 = (mpz_t*)malloc(sizeof(mpz_t) * (size*m*2));
  mpz_t* mulBufferExtra2 = (mpz_t*)malloc(sizeof(mpz_t) * (size*m*2));
  mpz_t* mulBufferExtra3 = (mpz_t*)malloc(sizeof(mpz_t) * (size*m*2));
  for(int j = 0; j < size*m*2; j++){
    mpz_init(mulBufferExtra1[j]);
    mpz_init(mulBufferExtra2[j]);
    mpz_init(mulBufferExtra3[j]);
  }
  for(int i = 0; i < m; i++){
    for(int j = 0; j < size; j++){
      mpz_set(mulBufferExtra1[i*size+j], T[0][i][j]);
      mpz_set(mulBufferExtra2[i*size+j], PreMul_W[0][i*size + j]);
      mpz_set(mulBufferExtra1[m*size+i*size+j], T[0][i][j]);
      mpz_set(mulBufferExtra2[m*size+i*size+j], PreMul_W[1][i*size + j]);
    }
  }

  for(int i = 0; i < 2; i++){
    for(int j = 0; j < m * size; j++){
      mpz_clear(PreMul_W[i][j]);
    }
    free(PreMul_W[i]);
  }
  free(PreMul_W);

  Mul->doOperation(mulBufferExtra3, mulBufferExtra1, mulBufferExtra2, size*m*2, threadID);//Round6

  for(int i = 0; i < size*m; ++i){
    mpz_set(PreMul_results[0][i], mulBufferExtra3[i]);
    mpz_set(PreMul_results[1][i], mulBufferExtra3[i+size*m]);
  }

  ms->pushBuffer(PreMul_results[0], PreMul_results[1], size*m);

  //Malicious check for above Mulpub
  mpz_t** mulBuffer_share3 = (mpz_t**)malloc(sizeof(mpz_t*) * peers);
  //mpz_t** mulBuffer_share4 = (mpz_t**)malloc(sizeof(mpz_t*) * peers);
  for(int i = 0; i < peers; i++){
    mulBuffer_share3[i] = (mpz_t*)malloc(sizeof(mpz_t) * (size*m*2));
    //mulBuffer_share4[i] = (mpz_t*)malloc(sizeof(mpz_t) * (size*m*2));
    for(int j = 0; j < size*m*2; j++){
      mpz_init(mulBuffer_share3[i][j]);
      //mpz_init(mulBuffer_share4[i][j]);
    }
  }

  for(int i = 0; i < size*m; i++){
    for(int j = 0; j < peers; ++j){
      mpz_set_ui(mulBuffer_share3[j][i], 0);
      //mpz_set_ui(mulBuffer_share4[j][i], 0);
    }
  }

  net.broadcastToPeers(PreMul_results[0], size*m, mulBuffer_share3, threadID); //Round 6'
  ms->reconstructSecretCheck(PreMul_results[0], mulBuffer_share3, size * m, true);
  //switched the below to the above, which makes more sense, removed mulBuffer_share4
  //ms->reconstructSecretCheck(PreMul_results[0], mulBuffer_share4, size * m, true);

  //  ss->getShares(mulBuffer_share3, PreMul_results[1], size*m);
  //net.multicastToPeers(mulBuffer_share3, mulBuffer_share4, size*m, threadID); //Round 7
  //ss->reconstructSecret(PreMul_results[1], mulBuffer_share4, size*m, true);

  for(int i = 0; i < peers; i++){
    for(int j = 0; j < size * m * 2; j++){
      mpz_clear(mulBuffer_share3[i][j]);
      //mpz_clear(mulBuffer_share4[i][j]);
    }
    free(mulBuffer_share3[i]);
    //free(mulBuffer_share4[i]);
  }
  free(mulBuffer_share3);
  //free(mulBuffer_share4);

  for(int j = 0; j < size*m*2; j++){
    mpz_clear(mulBufferExtra1[j]);
    mpz_clear(mulBufferExtra2[j]);
    mpz_clear(mulBufferExtra3[j]);
  };
  free(mulBufferExtra1);
  free(mulBufferExtra2);
  free(mulBufferExtra3);

  // seems good
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


  //maybe not needed
  //ss->copy(T[0], T[0], size);


  for(int i = 1; i < m; i++){
    for(int j = 0; j < size; j++){
      ss->modMul(PreMul_temp1[0][j], PreMul_temp1[0][j], PreMul_results[0][i*size+j]);
      ss->modMul(T[0][i][j], PreMul_S[0][i], PreMul_temp1[0][j]);
      ss->modMul(T[1][i][j], PreMul_S[1][i], PreMul_temp1[0][j]);
    }
  }

  for(int i = 0; i < 2; i++){
    for(int j = 0; j < size; j++){
      mpz_clear(PreMul_temp1[i][j]);
    }
    free(PreMul_temp1[i]);
  }
  free(PreMul_temp1);

  for(int i = 0; i < 2; i++){
    for(int j = 0; j < m * size; j++){
      mpz_clear(PreMul_S[i][j]);
      mpz_clear(PreMul_results[i][j]);
    }
    free(PreMul_S[i]);
    free(PreMul_results[i]);
  }
  free(PreMul_S);
  free(PreMul_results);

  //PreMul End

  mpz_t tempBuffer;
  mpz_init(tempBuffer);

  int checktemp;

  for(int i = 0; i < size; i++){
    mpz_set(temp2, coef[m]);
    ss->modMul(tempBuffer, temp2, ms->r);
    mpz_set_ui(result[0][i], 0);
    mpz_set_ui(result[1][i], 0);

    ss->modAdd(result[0][i], result[0][i], temp2);
    ss->modAdd(result[1][i], result[1][i], tempBuffer);

    for(int j = 0; j < m; j++){
      mpz_set(temp2, coef[m-j-1]);

      ss->modMul(temp1, T[0][j][i], temp2);
      ss->modAdd(result[0][i], result[0][i], temp1);
      ss->modMul(temp1, T[1][j][i], temp2);
      ss->modAdd(result[1][i], result[1][i], temp1);
    }
    ss->modSub(result[0][i], const1, result[0][i]);
    ss->modSub(result[1][i], ms->r, result[1][i]);
  }

  mpz_clear(tempBuffer);
  ms->pushBuffer(result[0], result[1], size);

  mpz_clear(temp1);
  mpz_clear(temp2);
  mpz_clear(const2);
  mpz_clear(const2K);
  mpz_clear(const2m);
  mpz_clear(constm);
  mpz_clear(constK);
  mpz_clear(const1);


  for(int i=0; i<2; ++i){
    for(int j=0; j< m; ++j){
      for(int kk = 0; kk < size; kk++){
        mpz_clear(T[i][j][kk]);
      }
      free(T[i][j]);
    }
    free(T[i]);
  }
  free(T);
}


