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

#include "SMC_Utils.h"
#include "SecretShare.h"
#include <string>
#include <cmath>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include "openssl/bio.h"
#include <netinet/in.h>
#include "unistd.h"

//Constructors
SMC_Utils::SMC_Utils(int id, std::string runtime_config, std::string privatekey_filename, int numOfInputPeers, int numOfOutputPeers, std::string *IO_files, int numOfPeers, int threshold, int bits, std::string mod, int num_threads, int threat_model){
  base = 10;
  std::cout << "SMC_Utils constructor\n";
  mpz_t modulus;
  mpz_init(modulus);
  mpz_set_str(modulus, mod.c_str(), 10);
  nodeConfig = new NodeConfiguration(id, runtime_config, bits);
  peers = numOfPeers;
  ss = new SecretShare(numOfPeers, threshold, id, modulus);
  std::cout << "Creating the NodeNetwork\n";

  unsigned char key_0[16],key_1[16];
  ss->getCoef(id);
  NodeNetwork* nodeNet = new NodeNetwork(nodeConfig, privatekey_filename, num_threads, key_0, key_1, threshold);
  nNet = *nodeNet;
  std::cout << "Created the NodeNetwork\n";
  clientConnect();
  receivePolynomials(privatekey_filename);

  //initialize input and output streams
  inputStreams = new std::ifstream[numOfInputPeers];
  outputStreams = new std::ofstream[numOfOutputPeers];
  for(int i = 0; i < numOfInputPeers; i++)
  {
    inputStreams[i].open(IO_files[i].c_str(), std::ifstream::in);
    if(!inputStreams[i]){
      std::cout << "Input files could not be opened\n";
      std::exit(1);
    }
  }

  for(int i = 0; i < numOfOutputPeers; i++)
  {
    std::stringstream c;
    c << id;
    std::string s = c.str();
    IO_files[numOfInputPeers+i] = IO_files[numOfInputPeers+i] + s;
    outputStreams[i].open(IO_files[numOfInputPeers+i].c_str(), std::ofstream::out);
    if(!outputStreams[i])
    {
      std::cout<<"Output files could not be opened\n";
      std::exit(1);
    }
  }
  std::cout << "Created the files\n";
  ss->Seed(key_0,key_1);

  threat_mod = threat_model;
  if ((threat_mod < 0) || (threat_mod > 1))
  {
    threat_mod = MALICIOUS;
  }

  //non-malicious
  T = new Trunc(*nodeNet, polynomials, id, ss, coef);
  Ts = new TruncS(*nodeNet, polynomials, id, ss, coef);
  P = new Pow2(*nodeNet, polynomials, id, ss, coef);
  BOps = new BitOps(*nodeNet, polynomials, id, ss, coef);
  Mul = new Mult(*nodeNet, id, ss);
  Idiv = new IntDiv(*nodeNet, polynomials, id, ss, coef);

  //for test purposes
  PRand = new Random(*nodeNet, polynomials, id, ss);

  setCoef();

  if (threat_mod == MALICIOUS)
  {
    MSmc = new MaliciousSMC(nodeConfig, *nodeNet, ss, numOfPeers, threshold, PRand, Mul);

    Lt = new LTZ(*nodeNet, polynomials, id, ss, coef, MSmc);
    Eq = new EQZ(*nodeNet, polynomials, id, ss, coef, MSmc);
    DProd = new DotProduct(*nodeNet, polynomials, id, ss, coef, MSmc);
    BitA = new BitAdd(*nodeNet, polynomials, id, ss, coef, MSmc, Mul);
    BitL = new BitLT(*nodeNet, polynomials, id, ss, coef, MSmc, Mul);
    BitE = new BitEq(*nodeNet, polynomials, id, ss, coef, MSmc, Mul);
    BitM = new BitMul(*nodeNet, polynomials, id, ss, coef, MSmc, Mul);
    BitS = new BitSum(*nodeNet, polynomials, id, ss, coef, MSmc, Mul);
  }
  else	//threat_mod == SEMIHONEST
  {
    Lt = new LTZ(*nodeNet, polynomials, id, ss, coef);
    Eq = new EQZ(*nodeNet, polynomials, id, ss, coef);
    DProd = new DotProduct(*nodeNet, polynomials, id, ss, coef);
    BitA = new BitAdd(*nodeNet, polynomials, id, ss, coef, Mul);
    BitL = new BitLT(*nodeNet, polynomials, id, ss, coef, Mul);
    BitE = new BitEq(*nodeNet, polynomials, id, ss, coef, Mul);
    BitM = new BitMul(*nodeNet, polynomials, id, ss, coef, Mul);
    BitS = new BitSum(*nodeNet, polynomials, id, ss, coef, Mul);
  }


}


SMC_Utils::~SMC_Utils()
{
  delete ss;
  if (threat_mod == MALICIOUS)
  {
    delete MSmc;
  }
  delete nodeConfig;
  delete Lt;
  delete PRand;
  delete Mul;
  delete Eq;
  delete DProd;
  delete BOps;
  delete T;
  delete Ts;
  delete Idiv;
  delete P;
  delete BitA;
  delete BitL;
  delete BitE;
  delete BitM;
  delete BitS;
}



void SMC_Utils::smc_reset_counters()
{
  nNet.reset_comm_counter();
  Mul->reset_mult_counter();
}


void SMC_Utils::smc_get_communication_summary(std::string test_description, bool writing_to_file)
{
  nNet.getSummary(test_description, writing_to_file);
  Mul->getSummary(test_description, writing_to_file);
}


/* added for randbit Functions */
void SMC_Utils::smc_randbit(mpz_t* result, int resultlen){
  PRand->PRandBit(resultlen, result);
}

/* bit-wise functions (boolean circuit)*/
void SMC_Utils::smc_bitadd(mpz_t** a, mpz_t** b, mpz_t** s, int size, int batch_size, int threadID){
  BitA->doOperation(a, b, s, size, batch_size, threadID);
}

void SMC_Utils::smc_bittwoscomp(mpz_t** a, mpz_t** s, int size, int batch_size, int threadID)
{
  BitA->twosComplement(a, s, size, batch_size, threadID);
}

void SMC_Utils::smc_bitmul(mpz_t** a, mpz_t** b, mpz_t** s, int in_size, int batch_size, int out_size, int threadID){
  BitM->doOperation(a, b, s, in_size, batch_size, out_size, threadID);
}

void SMC_Utils::smc_bitsum(mpz_t** a, mpz_t* s, int in_size, int num_elements, int out_size, int threadID){
  BitS->doOperation(a, s, in_size, num_elements, out_size, threadID);
}

void SMC_Utils::smc_bitlt(mpz_t* a, mpz_t* b, mpz_t s, int size, int threadID){
  BitL->doOperation(a, b, s, size, threadID);
}

void SMC_Utils::smc_bitlt(mpz_t** a, mpz_t** b, mpz_t* s, int size, int batch_size, int threadID){
  BitL->doOperation(a, b, s, size, batch_size, threadID);
}

void SMC_Utils::smc_biteq(mpz_t** a, mpz_t** b, mpz_t* s, int size, int batch_size, int threadID){
  BitE->doOperation(a, b, s, size, batch_size, threadID);
}


/* malicious boolean functions */

void SMC_Utils::smc_bitadd_mal(mpz_t*** a, mpz_t*** b, mpz_t*** s, int size, int batch_size, int threadID){
  BitA->doOperation_mal(a, b, s, size, batch_size, threadID);
}

void SMC_Utils::smc_bittwoscomp_mal(mpz_t*** a, mpz_t*** s, int size, int batch_size, int threadID)
{
  BitA->twosComplement_mal(a, s, size, batch_size, threadID);
}

void SMC_Utils::smc_bitmul_mal(mpz_t*** a, mpz_t*** b, mpz_t*** s, int in_size, int batch_size, int out_size, int threadID){
  BitM->doOperation_mal(a, b, s, in_size, batch_size, out_size, threadID);
}

void SMC_Utils::smc_bitsum_mal(mpz_t*** a, mpz_t** s, int in_size, int num_elements, int out_size, int threadID){
  BitS->doOperation_mal(a, s, in_size, num_elements, out_size, threadID);
}

void SMC_Utils::smc_bitlt_mal(mpz_t** a, mpz_t** b, mpz_t* s, int size, int threadID){
  BitL->doOperation_mal(a, b, s, size, threadID);
}

void SMC_Utils::smc_bitlt_mal(mpz_t*** a, mpz_t*** b, mpz_t** s, int size, int batch_size, int threadID){
  BitL->doOperation_mal(a, b, s, size, batch_size, threadID);
}

void SMC_Utils::smc_biteq_mal(mpz_t*** a, mpz_t*** b, mpz_t** s, int size, int batch_size, int threadID){
  BitE->doOperation_mal(a, b, s, size, batch_size, threadID);
}



/* malicious arithmetic functions */
void SMC_Utils::smc_init_mal(){
  mpz_t r_temp [1];
  mpz_init(r_temp[0]);

  mpz_t field;
  mpz_init(field);
  ss->getFieldSize(field);
  int pid = nNet.getID();

  PRand->generateRandValue(pid, field, 1, r_temp);
  mpz_set(MSmc->r, r_temp[0]);
  mpz_clear(r_temp[0]);
  mpz_clear(field);

}

void SMC_Utils::smc_clean_mal(){
  MSmc->clean_mal();
  printf("Cleaned malicious buffer\n");
}

void SMC_Utils::smc_getr_mal(mpz_t a){
  mpz_set(a, MSmc->r);
}

void SMC_Utils::smc_input_mal(int id, mpz_t* var, int size, int varlen, std::string type, int threadID){
  std:: string line;
  std::vector<std::string> tokens;
  std::vector<std::string> temp;
  std::getline(inputStreams[id-1], line);
  temp = splitfunc(line.c_str(), "=");
  tokens = splitfunc(temp[1].c_str(), ",");
  mpz_set_str(var[0], tokens[0].c_str(), base);
  smc_mult(var[0], MSmc->r, var[1], varlen, varlen, varlen, type, threadID);
}

void SMC_Utils::smc_input_mal(mpz_t* a, mpz_t *b, std::string type, int threadID)
{
  mpz_t* rArray;
  mpz_t* mult_in;
  mpz_t* mult_out;
  rArray = (mpz_t*)malloc(sizeof(mpz_t) * 2);
  mult_in = (mpz_t*)malloc(sizeof(mpz_t) * 2);
  mult_out = (mpz_t*)malloc(sizeof(mpz_t) * 2);
  for(int i = 0; i < 2; ++i) {
    mpz_init_set(rArray[i], MSmc->r);
    mpz_init(mult_out[i]);
  }

  mpz_init_set(mult_in[0], a[0]);
  mpz_init_set(mult_in[1], b[0]);

  Mul->doOperation(mult_out, mult_in, rArray, 2, threadID);
  MSmc->pushBuffer(mult_in, mult_out, 2);

  mpz_set(a[1], mult_out[0]);
  mpz_set(b[1], mult_out[1]);

  for (int i = 0; i < 2; ++i){
    mpz_clear(rArray[i]);
    mpz_clear(mult_in[i]);
    mpz_clear(mult_out[i]);
  }

  free(rArray);
  free(mult_in);
  free(mult_out);
}

void SMC_Utils::smc_input_mal(mpz_t** a, int size, std::string type, int threadID){
  mpz_t* rArray;
  mpz_t* mult_in;
  mpz_t* mult_out;
  rArray = (mpz_t*)malloc(sizeof(mpz_t) * size);
  mult_in = (mpz_t*)malloc(sizeof(mpz_t) * size);
  mult_out = (mpz_t*)malloc(sizeof(mpz_t) * size);
  for(int i = 0; i < size; ++i) {
    mpz_init_set(rArray[i], MSmc->r);
    mpz_init(mult_out[i]);
  }

  int buff_ptr = 0;
  for(int j = 0; j < size; ++j){
    mpz_init_set(mult_in[buff_ptr++], a[0][j]);
  }

  Mul->doOperation(mult_out, mult_in, rArray, size, threadID);
  MSmc->pushBuffer(mult_in, mult_out, size);

  buff_ptr = 0;
  for(int j = 0; j < size; ++j){
    mpz_set(a[1][j], mult_out[buff_ptr++]);
  }

  for (int i = 0; i < size; ++i){
    mpz_clear(rArray[i]);
    mpz_clear(mult_in[i]);
    mpz_clear(mult_out[i]);
  }

  free(rArray);
  free(mult_in);
  free(mult_out);
}

void SMC_Utils::smc_input_mal(mpz_t** a, mpz_t **b, int size, std::string type, int threadID){
  mpz_t* rArray;
  mpz_t* mult_in;
  mpz_t* mult_out;
  rArray = (mpz_t*)malloc(sizeof(mpz_t) * 2 * size);
  mult_in = (mpz_t*)malloc(sizeof(mpz_t) * 2 * size);
  mult_out = (mpz_t*)malloc(sizeof(mpz_t) * 2 * size);
  for(int i = 0; i < 2 * size; ++i) {
    mpz_init_set(rArray[i], MSmc->r);
    mpz_init(mult_out[i]);
  }

  int buff_ptr = 0;
  for(int j = 0; j < size; ++j){
    mpz_init_set(mult_in[buff_ptr++], a[0][j]);
    mpz_init_set(mult_in[buff_ptr++], b[0][j]);
  }

  Mul->doOperation(mult_out, mult_in, rArray, 2 * size, threadID);
  MSmc->pushBuffer(mult_in, mult_out, 2 * size);

  buff_ptr = 0;
  for(int j = 0; j < size; ++j){
    mpz_set(a[1][j], mult_out[buff_ptr++]);
    mpz_set(b[1][j], mult_out[buff_ptr++]);
  }

  for (int i = 0; i < 2 * size; ++i){
    mpz_clear(rArray[i]);
    mpz_clear(mult_in[i]);
    mpz_clear(mult_out[i]);
  }

  free(rArray);
  free(mult_in);
  free(mult_out);
}

void SMC_Utils::smc_input_mal(mpz_t*** a, mpz_t ***b, int batch_size, int size, std::string type, int threadID){
  mpz_t* rArray;
  mpz_t* mult_in;
  mpz_t* mult_out;
  rArray = (mpz_t*)malloc(sizeof(mpz_t) * (2 * size * batch_size));
  mult_in = (mpz_t*)malloc(sizeof(mpz_t) * (2 * size * batch_size));
  mult_out = (mpz_t*)malloc(sizeof(mpz_t) * (2 * size * batch_size));
  for(int i = 0; i < 2 * size * batch_size; ++i) {
    mpz_init_set(rArray[i], MSmc->r);
    mpz_init(mult_out[i]);
  }

  int buff_ptr = 0;
  for(int i = 0; i < batch_size; ++i){
    for(int j = 0; j < size; ++j){
      mpz_init_set(mult_in[buff_ptr++], a[0][i][j]);
      mpz_init_set(mult_in[buff_ptr++], b[0][i][j]);
    }
  }

  Mul->doOperation(mult_out, mult_in, rArray, 2 * size * batch_size, threadID);
  MSmc->pushBuffer(mult_in, mult_out, 2 * size * batch_size);

  buff_ptr = 0;
  for(int i = 0; i < batch_size; ++i){
    for(int j = 0; j < size; ++j){
      mpz_set(a[1][i][j], mult_out[buff_ptr++]);
      mpz_set(b[1][i][j], mult_out[buff_ptr++]);
    }
  }

  for (int i = 0; i < 2 * size * batch_size; ++i){
    mpz_clear(rArray[i]);
    mpz_clear(mult_in[i]);
    mpz_clear(mult_out[i]);
  }

  free(rArray);
  free(mult_in);
  free(mult_out);
}


void SMC_Utils::smc_mult_mal(mpz_t** a, mpz_t** b, int alen, int blen, mpz_t** result, int resultlen, int size, std::string type, int threadID)
{
  //a and b are 2D array of size "size".
  //do a batch mult between {a[0],a[1]} with {b[0],b[0]} into {result[0],result[1]}, and copy the results into buffer
  int curSize = 2*size;
  mpz_t* a_temp;
  mpz_t* b_temp;
  a_temp = (mpz_t*)malloc(sizeof(mpz_t) * (curSize));
  for (int i = 0; i < curSize; i++){
    mpz_init(a_temp[i]);
    mpz_set(a_temp[i], a[0][i%size]);
  }
  b_temp = (mpz_t*)malloc(sizeof(mpz_t) * (curSize));
  for (int i = 0; i < curSize; i++){
    mpz_init(b_temp[i]);
    mpz_set(b_temp[i], b[i/size][i%size]);
  }

  Mul->doOperation(a_temp, a_temp, b_temp, curSize, threadID);

  for (int i = 0; i < curSize; i++){
    mpz_set(result[i/size][i%size], a_temp[i]);
  }

  MSmc->pushBuffer(result[0], result[1], size);

  //clean
  for (int i = 0; i < curSize; i++)
    mpz_clear(a_temp[i]);
  free(a_temp);
  for (int i = 0; i < curSize; i++)
    mpz_clear(b_temp[i]);
  free(b_temp);
}

void SMC_Utils::smc_add_mal(mpz_t** a, mpz_t** b, int alen, int blen, mpz_t** result, int resultlen, int size, std::string type, int threadID)
{
  //do a batch add between {a[0],a[1]} with {b[0],b[1]} into {result[0],result[1]}, and copy the results into buffer
  for(int i = 0; i < size; ++i) {
    smc_add(a[0][i], b[0][i], result[0][i], alen, blen, resultlen, type, threadID);
    smc_add(a[1][i], b[1][i], result[1][i], alen, blen, resultlen, type, threadID);
  }
}

void SMC_Utils::smc_add_mal(int a, mpz_t* b, mpz_t* result, int alen, int blen, int resultlen, std::string type, int threadID){
  mpz_t* a_tmp = (mpz_t*)malloc(sizeof(mpz_t) * 2);
  mpz_init_set_ui(a_tmp[0], a);
  mpz_init_set_ui(a_tmp[1], a);
  ss->modMul(a_tmp[1], a_tmp[1], MSmc->r);
  smc_add(a_tmp[0], b[0], result[0], alen, blen, resultlen, type, threadID);
  smc_add(a_tmp[1], b[1], result[1], alen, blen, resultlen, type, threadID);
  mpz_clear(a_tmp[0]);
  mpz_clear(a_tmp[1]);
  free(a_tmp);
}


void SMC_Utils::smc_sub_mal(mpz_t** a, mpz_t** b, int alen, int blen, mpz_t** result, int resultlen, int size, std::string type, int threadID)
{
  //do a batch add between {a[0],a[1]} with {b[0],b[1]} into {result[0],result[1]}, and copy the results into buffer
  for(int i = 0; i < size; ++i) {
    smc_sub(a[0][i], b[0][i], result[0][i], alen, blen, resultlen, type, threadID);
    smc_sub(a[1][i], b[1][i], result[1][i], alen, blen, resultlen, type, threadID);
  }
}



void SMC_Utils::smc_sub_mal(int a, mpz_t* b,  mpz_t* result, int alen, int blen, int resultlen, std::string type, int threadID)
{
  mpz_t* a_tmp = (mpz_t*)malloc(sizeof(mpz_t) * 2);
  mpz_init_set_ui(a_tmp[0], a);
  mpz_init_set_ui(a_tmp[1], a);
  ss->modMul(a_tmp[1], a_tmp[1], MSmc->r);
  ss->modSub(result[0], a_tmp[0], b[0]);
  ss->modSub(result[1], a_tmp[1], b[1]);
  mpz_clear(a_tmp[0]);
  mpz_clear(a_tmp[1]);
  free(a_tmp);
}


void SMC_Utils::smc_verify()
{
  MSmc->verify();
}


unsigned long SMC_Utils::smc_get_verif_time()
{
  return MSmc->VerificationTimer;
}


void SMC_Utils::smc_eqeq_mal(mpz_t** a, mpz_t** b, int alen, int blen, mpz_t** result, int resultlen, int size, std::string type, int threadID)
{
  mpz_t** sub = (mpz_t**)malloc(sizeof(mpz_t*) * 2);
  for(int i=0; i<2; ++i){
    sub[i] = (mpz_t*)malloc(sizeof(mpz_t) * size);
    for(int j = 0; j < size; j++){
      mpz_init(sub[i][j]);
    }
  }
  int len = 0;
  smc_compute_len(alen, blen, &len);
  ss->modSub(sub[0], a[0], b[0], size);
  ss->modSub(sub[1], a[1], b[1], size);
  Eq->doOperation_mal(sub, result, len, size, threadID);
  for(int i=0; i<2; ++i){
    for(int j = 0; j < size; j++){
      mpz_clear(sub[i][j]);
    }
    free(sub[i]);
  }
  free(sub);
}


void SMC_Utils::smc_eqeq_mal(mpz_t* a, mpz_t* b, mpz_t* result, int alen, int blen, int resultlen, std::string type, int threadID){
  mpz_t* sub = (mpz_t*)malloc(sizeof(mpz_t) * 2);
  for(int i=0; i<2; ++i){
    mpz_init(sub[i]);
  }
  ss->modSub(sub[0], a[0], b[0]);
  ss->modSub(sub[1], a[1], b[1]);
  mpz_t** results = (mpz_t**)malloc(sizeof(mpz_t*));
  mpz_t** subs = (mpz_t**)malloc(sizeof(mpz_t*));
  for(int i=0; i<2; ++i){
    subs[i] = (mpz_t*)malloc(sizeof(mpz_t));
    results[i] = (mpz_t*)malloc(sizeof(mpz_t));
    for(int j = 0; j < 1; j++){
      mpz_init_set(subs[i][j], sub[i]);
      mpz_init(results[i][j]);
    }
  }

  int len = 0;
  smc_compute_len(alen, blen, &len);

  //Eq->doOperation(subs, results, len, 1, threadID);
  Eq->doOperation_mal(subs, results, len, 1, threadID);

  mpz_set(result[0], results[0][0]);
  mpz_set(result[1], results[1][0]);
  for(int i=0; i<2; ++i){
    mpz_clear(sub[i]);
  }
  free(sub);

  for(int i=0; i<2; ++i){
    for(int j = 0; j < 1; j++){
      mpz_clear(subs[i][j]);
      mpz_clear(results[i][j]);
    }
    free(subs[i]);
    free(results[i]);
  }
  free(subs);
  free(results);
}



void SMC_Utils::smc_lt_mal(mpz_t** a, mpz_t** b, int alen, int blen, mpz_t** result, int resultlen, int size, std::string type, int threadID)
{
  mpz_t** sub = (mpz_t**)malloc(sizeof(mpz_t*) * 2);
  for(int k = 0; k < 2; k++){
    sub[k] = (mpz_t*)malloc(sizeof(mpz_t) * size);
    for(int i = 0; i < size; i++)
      mpz_init(sub[k][i]);
  }
  ss->modSub(sub[0], b[0], a[0], size);
  ss->modSub(sub[1], b[1], a[1], size);

  int len = 0;
  smc_compute_len(alen, blen, &len);
  Lt->doOperation_mal(result, sub, len, size, threadID);
  ss->modSub(result[0], 1, result[0], size);
  ss->modSub(result[1], MSmc->r, result[1], size);

  for(int k = 0; k < 2; k++){
    for(int i = 0; i < size; i++){
      mpz_clear(sub[k][i]);
    }
    free(sub[k]);
  }
  free(sub);
}


void SMC_Utils::smc_lt_mal(mpz_t* a, mpz_t* b, mpz_t* result, int alen, int blen, int resultlen, std::string type, int threadID){
  mpz_t* sub = (mpz_t*)malloc(sizeof(mpz_t) * 2);
  for(int i=0; i<2; ++i){
    mpz_init(sub[i]);
  }
  ss->modSub(sub[0], b[0], a[0]);
  ss->modSub(sub[1], b[1], a[1]);
  mpz_t** results = (mpz_t**)malloc(sizeof(mpz_t*));
  mpz_t** subs = (mpz_t**)malloc(sizeof(mpz_t*));
  for(int i=0; i<2; ++i){
    subs[i] = (mpz_t*)malloc(sizeof(mpz_t));
    results[i] = (mpz_t*)malloc(sizeof(mpz_t));
    for(int j = 0; j < 1; j++){
      mpz_init_set(subs[i][j], sub[i]);
      mpz_init(results[i][j]);
    }
  }

  int len = 0;
  smc_compute_len(alen, blen, &len);
  Lt->doOperation_mal(results, subs, len, 1, threadID);

  mpz_set(result[0], results[0][0]);
  mpz_set(result[1], results[1][0]);
  ss->modSub(result[0], 1, result[0]);
  ss->modSub(result[1], MSmc->r, result[1]);

  for(int i=0; i<2; ++i){
    mpz_clear(sub[i]);
  }
  free(sub);

  for(int i=0; i<2; ++i){
    for(int j = 0; j < 1; j++){
      mpz_clear(subs[i][j]);
      mpz_clear(results[i][j]);
    }
    free(subs[i]);
    free(results[i]);
  }
  free(subs);
  free(results);
}


void SMC_Utils::smc_priv_eval_mal(mpz_t* a, mpz_t* b, mpz_t* cond, int threadID)
{
  mpz_t** results;
  results = (mpz_t**)malloc(sizeof(mpz_t*)*2);
  results[0] = (mpz_t*)malloc(sizeof(mpz_t));
  results[1] = (mpz_t*)malloc(sizeof(mpz_t));
  mpz_init(results[0][0]);
  mpz_init(results[1][0]);

  mpz_t** op1;
  op1 = (mpz_t**)malloc(sizeof(mpz_t*)*2);
  op1[0] = (mpz_t*)malloc(sizeof(mpz_t));
  op1[1] = (mpz_t*)malloc(sizeof(mpz_t));
  mpz_init(op1[0][0]);
  mpz_init(op1[1][0]);

  mpz_t** op2;
  op2 = (mpz_t**)malloc(sizeof(mpz_t*)*2);
  op2[0] = (mpz_t*)malloc(sizeof(mpz_t));
  op2[1] = (mpz_t*)malloc(sizeof(mpz_t));
  mpz_init_set(op2[0][0], cond[0]);
  mpz_init_set(op2[1][0], cond[1]);

  ss->modSub(op1[0][0], a[0], b[0]);
  ss->modSub(op1[1][0], a[1], b[1]);

  smc_mult_mal(op1, op2, 32, 32, results, 32, 1, "int", -1);
  ss->modAdd(a[0], results[0][0], b[0]);
  ss->modAdd(a[1], results[1][0], b[1]);

  mpz_clear(results[0][0]);
  mpz_clear(results[1][0]);
  free(results[0]);
  free(results[1]);
  free(results);

  mpz_clear(op1[0][0]);
  mpz_clear(op1[1][0]);
  free(op1[0]);
  free(op1[1]);
  free(op1);

  mpz_clear(op2[0][0]);
  mpz_clear(op2[1][0]);
  free(op2[0]);
  free(op2[1]);
  free(op2);
}


/* Specific SMC Utility Functions */
int SMC_Utils::smc_open(mpz_t var, int threadID){
  mpz_t* data = (mpz_t*)malloc(sizeof(mpz_t) * 1);
  mpz_t* results = (mpz_t*)malloc(sizeof(mpz_t) * 1);
  mpz_t** buffer = (mpz_t**)malloc(sizeof(mpz_t*) * peers);
  for(int i=0; i<peers; ++i){
    buffer[i] = (mpz_t*)malloc(sizeof(mpz_t));
    mpz_init(buffer[i][0]);
  }
  mpz_init(data[0]);
  mpz_init(results[0]);
  mpz_set(data[0], var);
  nNet.broadcastToPeers(data, 1, buffer, threadID);
  ss->reconstructSecret(results,buffer, 1, false);
  mpz_t tmp, field;
  mpz_init(tmp);
  mpz_init(field);
  ss->getFieldSize(field);
  mpz_mul_ui(tmp, results[0], 2);
  if(mpz_cmp(tmp, field) > 0)
    mpz_sub(results[0], results[0], field);
  int result = mpz_get_si(results[0]);

  //free the memory
  mpz_clear(data[0]);
  mpz_clear(results[0]);
  free(data);
  free(results);
  for(int i = 0; i < peers; i++)
  {
    mpz_clear(buffer[i][0]);
    free(buffer[i]);
  }
  free(buffer);

  return result;
}


void SMC_Utils::smc_open(mpz_t *inputs, int* outputs, int batch_size, int threadID)
{
  mpz_t* data = (mpz_t*) malloc(sizeof(mpz_t) * batch_size);
  mpz_t* results = (mpz_t*) malloc(sizeof(mpz_t) * batch_size);
  mpz_t** buffer = (mpz_t**) malloc(sizeof(mpz_t*) * peers);
  for(int i=0; i<peers; ++i){
    buffer[i] = (mpz_t*) malloc(sizeof(mpz_t) * batch_size);
    for (int j = 0; j < batch_size; j++)
      mpz_init(buffer[i][j]);
  }
  for (int j = 0; j < batch_size; j++)
  {
    mpz_init(data[j]);
    mpz_init(results[j]);
    mpz_set(data[j], inputs[j]);
  }

  nNet.broadcastToPeers(data, batch_size, buffer, threadID);
  ss->reconstructSecret(results, buffer, batch_size, false);
  mpz_t tmp, field;
  mpz_init(tmp);
  mpz_init(field);
  ss->getFieldSize(field);

  for (int j = 0; j < batch_size; j++)
  {
    mpz_mul_ui(tmp, results[j], 2);
    if(mpz_cmp(tmp, field) > 0)
    {
      mpz_sub(results[j], results[j], field);
    }
    outputs[j] = mpz_get_si(results[j]);
  }

  //free the memory
  for (int j = 0; j < batch_size; j++)
  {
    mpz_clear(data[j]);
    mpz_clear(results[j]);
  }
  free(data);
  free(results);
  for(int i = 0; i < peers; i++)
  {
    for (int j = 0; j < batch_size; j++)
      mpz_clear(buffer[i][j]);
    free(buffer[i]);
  }
  free(buffer);
}

/********************************************************/

float SMC_Utils::smc_open(mpz_t* var, int threadID){
  mpz_t* data = (mpz_t*)malloc(sizeof(mpz_t) * 4);
  mpz_t* results = (mpz_t*)malloc(sizeof(mpz_t) * 4);
  mpz_t** buffer = (mpz_t**)malloc(sizeof(mpz_t*) * peers);
  for(int i=0; i<peers; ++i){
    buffer[i] = (mpz_t*)malloc(sizeof(mpz_t) * 4);
    for(int j = 0; j < 4; j++)
      mpz_init(buffer[i][j]);
  }

  for(int i = 0; i < 4; i++)
  {
    mpz_init(data[i]);
    mpz_init(results[i]);
    mpz_set(data[i], var[i]);
  }
  nNet.broadcastToPeers(data, 4, buffer, threadID);
  ss->reconstructSecret(results,buffer, 4, false);

  for(int i = 0; i < 4; i++){
    if(i == 1){
      mpz_t tmp, field;
      mpz_init(tmp);
      mpz_init(field);
      ss->getFieldSize(field);
      mpz_mul_ui(tmp, results[1], 2);
      if(mpz_cmp(tmp, field) > 0)
        mpz_sub(results[1], results[1], field);
    }
  }
  double v = mpz_get_d(results[0]);
  double p = mpz_get_d(results[1]);
  double z = mpz_get_d(results[2]);
  double s = mpz_get_d(results[3]);
  double result = 0;

  //free the memory
  for(int i = 0; i < 4; i++)
  {
    mpz_clear(data[i]);
    mpz_clear(results[i]);
  }
  free(data);
  free(results);

  for(int i = 0; i < peers; i++)
  {
    for(int j = 0; j < 4; j++)
      mpz_clear(buffer[i][j]);
    free(buffer[i]);
  }
  free(buffer);

  //return the result
  if(z == 1){
    //printf("%d\n", 0);
    return 0;
  }
  else{
    result = v * pow(2, p);
    if(s == 1){
      //printf("%f\n", -result);
      return -result;
    }
    else{
      //printf("%f\n", result);
      return result;
    }
  }

}


//for integer variable I/O
void SMC_Utils::smc_input(int id, int* var, std::string type, int threadID){
  std::string line;
  std::vector<std::string> tokens;
  std::getline(inputStreams[id-1], line);
  tokens = splitfunc(line.c_str(), "=");
  *var = atoi(tokens[1].c_str());
}

void SMC_Utils::smc_input(int id, mpz_t* var, std::string type, int threadID){
  std::string line;
  std::vector<std::string> tokens;
  std::getline(inputStreams[id-1], line);
  tokens = splitfunc(line.c_str(), "=");
  mpz_set_str(*var, tokens[1].c_str(), base);
}

void SMC_Utils::smc_output(int id, int* var, std::string type, int threadID){
  std::string value;
  std::stringstream s;
  s << *var;
  outputStreams[id-1] << s.str() + "\n";
  outputStreams[id-1].flush();
}

void SMC_Utils::smc_output(int id, mpz_t* var, std::string type, int threadID){
  //smc_open(*var, threadID);
  std::string value;
  value = mpz_get_str(NULL, base, *var);
  outputStreams[id-1] << value + "\n";
  outputStreams[id-1].flush();
}



//one-dimensional int array I/O
void SMC_Utils::smc_input(int id, mpz_t* var, int size, std::string type, int threadID){
  std:: string line;
  std::vector<std::string> tokens;
  std::vector<std::string> temp;
  std::getline(inputStreams[id-1], line);
  temp = splitfunc(line.c_str(), "=");
  tokens = splitfunc(temp[1].c_str(), ",");
  for(int i=0; i<size; i++)
    mpz_set_str(var[i], tokens[i].c_str(), base);
}

void SMC_Utils::smc_output(int id, mpz_t* var, int size, std::string type, int threadID){
  std::string value;
  for(int i = 0; i < size; i++)
  {
    value = mpz_get_str(NULL, base, var[i]);
    //smc_open(var[i], threadID);
    if(i != size-1)
      outputStreams[id-1] << value+",";
    else
      outputStreams[id-1] << value+"\n";
    outputStreams[id-1].flush();
  }

}

void SMC_Utils::smc_input(int id, int* var, int size, std::string type, int threadID){
  std:: string line;
  std::vector<std::string> tokens;
  std::vector<std::string> temp;
  std::getline(inputStreams[id-1], line);
  temp = splitfunc(line.c_str(), "=");
  tokens = splitfunc(temp[1].c_str(), ",");
  for(int i=0; i<size; i++)
    var[i] = atoi(tokens[i].c_str());
}

void SMC_Utils::smc_output(int id, int* var, int size, std::string type, int threadID){
  std::string value;
  for(int i = 0; i < size; i++)
  {
    std::stringstream s;
    s << var[i];
    if(i != size-1)
      outputStreams[id-1] << s.str()+",";
    else
      outputStreams[id-1] << s.str()+"\n";
    outputStreams[id-1].flush();
  }
}


/* SMC Addition */
void SMC_Utils::smc_add(mpz_t a, mpz_t b, mpz_t result, int alen, int blen, int resultlen, std::string type, int threadID){
  ss->modAdd(result,a,b);
}

void SMC_Utils::smc_add(mpz_t a, int b, mpz_t result, int alen, int blen, int resultlen, std::string type, int threadID){
  mpz_t btmp;
  mpz_init_set_si(btmp, b);
  smc_add(a, btmp, result, alen, blen, resultlen, type, threadID);
  mpz_clear(btmp);
}

void SMC_Utils::smc_add(int a, mpz_t b, mpz_t result, int alen, int blen, int resultlen, std::string type, int threadID){
  mpz_t atmp;
  mpz_init_set_si(atmp, a);
  smc_add(atmp, b, result, alen, blen, resultlen, type, threadID);
  mpz_clear(atmp);
}

//batch version of smc_add
void SMC_Utils::smc_add(int* a, mpz_t* b, int alen, int blen, mpz_t* result, int resultlen, int size, std::string type, int threadID)
{
  mpz_t* atmp = (mpz_t*)malloc(sizeof(mpz_t) * size);
  for(int i = 0; i < size; i++)
    mpz_init_set_si(atmp[i], a[i]);
  smc_add(atmp, b, alen, blen, result, resultlen, size, type, threadID);
  smc_batch_free_operator(&atmp, size);
}

void SMC_Utils::smc_add(mpz_t* a, int* b, int alen, int blen, mpz_t* result, int resultlen, int size, std::string type, int threadID)
{
  mpz_t* btmp = (mpz_t*)malloc(sizeof(mpz_t) * size);
  for(int i = 0; i < size; i++)
    mpz_init_set_si(btmp[i], b[i]);
  smc_add(a, btmp, alen, blen, result, resultlen, size, type, threadID);
  smc_batch_free_operator(&btmp, size);
}

void SMC_Utils::smc_add(mpz_t* a, mpz_t* b, int alen, int blen, mpz_t* result, int resultlen, int size, std::string type, int threadID)
{
  ss->modAdd(result, a, b, size);
}


void SMC_Utils::smc_set(mpz_t a, mpz_t result, int alen, int resultlen, std::string type, int threadID){
  mpz_init_set(result, a);
}

void SMC_Utils::smc_set(mpz_t* a, mpz_t* result, int alen, int resultlen, int size, std::string type, int threadID){
  for(int i = 0; i < size; i++)
    smc_set(a[i], result[i], alen, resultlen, type, threadID);
}

// this routine should implement in a way that result = a + share[0]
void SMC_Utils::smc_set(int a, mpz_t result, int alen, int resultlen, std::string type, int threadID){
  mpz_t value;
  mpz_init_set_si(value, a);
  mpz_set_ui(result, 0);
  ss->modAdd(result, result, value);
  mpz_clear(value);
}

void SMC_Utils::smc_priv_eval(mpz_t a, mpz_t b, mpz_t cond, int threadID){
  mpz_t* results = (mpz_t*)malloc(sizeof(mpz_t));
  mpz_t* op1 = (mpz_t*)malloc(sizeof(mpz_t));
  mpz_t* op2 = (mpz_t*)malloc(sizeof(mpz_t));
  mpz_init(op1[0]);
  mpz_init_set(op2[0], cond);
  mpz_init(results[0]);

  ss->modSub(op1[0], a, b);
  Mul->doOperation(results, op1, op2, 1, threadID);
  ss->modAdd(a, results[0], b);

  smc_batch_free_operator(&op1, 1);
  smc_batch_free_operator(&op2, 1);
  smc_batch_free_operator(&results, 1);
}

void SMC_Utils::smc_priv_eval(mpz_t* a, mpz_t* b, mpz_t cond, int threadID){
  mpz_t* results = (mpz_t*)malloc(sizeof(mpz_t) * 4);
  mpz_t* op1 = (mpz_t*)malloc(sizeof(mpz_t) * 4);
  mpz_t* op2 = (mpz_t*)malloc(sizeof(mpz_t) * 4);
  for(int i = 0; i < 4; i++){
    mpz_init(op1[i]);
    ss->modSub(op1[i], a[i], b[i]);
    mpz_init_set(op2[i], cond);
    mpz_init(results[i]);
  }

  Mul->doOperation(results, op1, op2, 4, threadID);
  ss->modAdd(a, results, b, 4);

  smc_batch_free_operator(&op1, 4);
  smc_batch_free_operator(&op2, 4);
  smc_batch_free_operator(&results, 4);
}

/* SMC Subtraction */
void SMC_Utils::smc_sub(mpz_t a, mpz_t b, mpz_t result, int alen, int blen, int resultlen, std::string type, int threadID){
  ss->modSub(result,a,b);
}

void SMC_Utils::smc_sub(mpz_t a, int b, mpz_t result, int alen, int blen, int resultlen, std::string type, int threadID){
  mpz_t btmp;
  mpz_init_set_si(btmp, b);
  smc_sub(a, btmp, result, alen, blen, resultlen, type, threadID);
  mpz_clear(btmp);
}

void SMC_Utils::smc_sub(int a, mpz_t b, mpz_t result, int alen, int blen, int resultlen, std::string type, int threadID){
  mpz_t atmp;
  mpz_init_set_si(atmp, a);
  smc_sub(atmp, b, result, alen, blen, resultlen, type, threadID);
  mpz_clear(atmp);
}



//batch operations of subtraction
void SMC_Utils::smc_sub(mpz_t* a, mpz_t* b, int alen, int blen, mpz_t* result, int resultlen, int size, std::string type, int threadID)
{
  ss->modSub(result, a, b, size);
}

void SMC_Utils::smc_sub(int* a, mpz_t* b, int alen, int blen, mpz_t* result, int resultlen, int size, std::string type, int threadID)
{
  mpz_t* atmp = (mpz_t*)malloc(sizeof(mpz_t) * size);
  for(int i = 0; i < size; i++)
    mpz_init_set_si(atmp[i], a[i]);
  smc_sub(atmp, b, alen, blen, result, resultlen, size, type, threadID);
  smc_batch_free_operator(&atmp, size);
}

void SMC_Utils::smc_sub(mpz_t* a, int* b, int alen, int blen, mpz_t* result, int resultlen, int size, std::string type, int threadID)
{
  mpz_t* btmp = (mpz_t*)malloc(sizeof(mpz_t) * size);
  for(int i = 0; i < size; i++)
    mpz_init_set_si(btmp[i], b[i]);
  smc_sub(a, btmp, alen, blen, result, resultlen, size, type, threadID);
  smc_batch_free_operator(&btmp, size);
}


/* SMC Multiplication */
void SMC_Utils::smc_mult(mpz_t a, mpz_t b, mpz_t result, int alen, int blen, int resultlen, std::string type, int threadID){
  mpz_t* results = (mpz_t*)malloc(sizeof(mpz_t));
  mpz_t* op1 = (mpz_t*)malloc(sizeof(mpz_t));
  mpz_t* op2 = (mpz_t*)malloc(sizeof(mpz_t));

  mpz_init_set(op1[0], a);
  mpz_init_set(op2[0], b);
  mpz_init(results[0]);

  Mul->doOperation(results, op1, op2, 1, threadID);
  mpz_set(result, results[0]);

  //free the memory
  smc_batch_free_operator(&op1, 1);
  smc_batch_free_operator(&op2, 1);
  smc_batch_free_operator(&results, 1);
}

/******************************************************/
void SMC_Utils::smc_mult(mpz_t a, int b, mpz_t result, int alen, int blen, int resultlen, std::string type, int threadID){
  mpz_t btmp;
  mpz_init(btmp);
  ss->modAdd(btmp, btmp, b);
  ss->modMul(result, a, btmp);
  //smc_mult(a, btmp, result, alen, blen, resultlen, type, threadID);
  mpz_clear(btmp);
}

void SMC_Utils::smc_mult(int a, mpz_t b, mpz_t result, int alen, int blen, int resultlen, std::string type, int threadID){
  mpz_t atmp;
  mpz_init(atmp);
  ss->modAdd(atmp, atmp, a);
  ss->modMul(result, atmp, b);
  //smc_mult(atmp, b, result, alen, blen, resultlen, type, threadID);
  mpz_clear(atmp);
}


void SMC_Utils::smc_mult(int* a, mpz_t* b, int alen, int blen, mpz_t* result, int resultlen, int size, std::string type, int threadID)
{
  mpz_t* atmp = (mpz_t*)malloc(sizeof(mpz_t) * size);
  for(int i = 0; i < size; i++){
    mpz_init_set_si(atmp[i], a[i]);
    ss->modMul(result[i], atmp[i], b[i]);
  }
  smc_batch_free_operator(&atmp, size);
}

void SMC_Utils::smc_mult(mpz_t* a, int* b, int alen, int blen, mpz_t* result, int resultlen, int size, std::string type, int threadID)
{
  mpz_t* btmp = (mpz_t*)malloc(sizeof(mpz_t) * size);
  for(int i = 0; i < size; i++){
    mpz_init_set_si(btmp[i], b[i]);
    ss->modMul(result[i], a[i], btmp[i]);
  }
  //smc_mult(a, btmp, alen, blen, result, resultlen, size, type, threadID);
  smc_batch_free_operator(&btmp, size);
}

void SMC_Utils::smc_mult(mpz_t* a, mpz_t* b, int alen, int blen, mpz_t* result, int resultlen, int size, std::string type, int threadID)
{
  Mul->doOperation(result, a, b, size, threadID);
}

/* SMC Division*/
void SMC_Utils::smc_div(mpz_t a, mpz_t b, mpz_t result, int alen, int blen, int resultlen, std::string type, int threadID){
  mpz_t* results = (mpz_t*)malloc(sizeof(mpz_t));
  mpz_t* op1 = (mpz_t*)malloc(sizeof(mpz_t));
  mpz_t* op2 = (mpz_t*)malloc(sizeof(mpz_t));

  mpz_init_set(op1[0], a);
  mpz_init_set(op2[0], b);
  mpz_init(results[0]);

  //alen and blen could be negative when a and b are coverted from public values
  Idiv->doOperation(results, op1, op2, resultlen, 1, threadID);
  mpz_set(result, results[0]);

  //free the memory
  smc_batch_free_operator(&op1, 1);
  smc_batch_free_operator(&op2, 1);
  smc_batch_free_operator(&results, 1);
}

void SMC_Utils::smc_div(mpz_t a, int b, mpz_t result, int alen, int blen, int resultlen, std::string type, int threadID){
  mpz_t* results = (mpz_t*)malloc(sizeof(mpz_t));
  mpz_t* op1 = (mpz_t*)malloc(sizeof(mpz_t));
  mpz_t* op2 = (mpz_t*)malloc(sizeof(mpz_t));

  mpz_init_set(op1[0], a);
  mpz_init_set_si(op2[0], b);
  mpz_init(results[0]);

  Idiv->doOperationPub(results, op1, op2, resultlen, 1, threadID);
  mpz_set(result, results[0]);

  //free the memory
  smc_batch_free_operator(&op1, 1);
  smc_batch_free_operator(&op2, 1);
  smc_batch_free_operator(&results, 1);
}

void SMC_Utils::smc_div(int a, mpz_t b, mpz_t result, int alen, int blen, int resultlen, std::string type, int threadID){
  mpz_t zero, atmp;
  mpz_init_set_ui(zero, 0);
  mpz_init_set_si(atmp, a);
  ss->modAdd(atmp, atmp, zero);
  smc_div(atmp, b, result, alen, blen, resultlen, type, threadID);

  //free the memory
  mpz_clear(zero);
  mpz_clear(atmp);
}


//batch operations of division
void SMC_Utils::smc_div(mpz_t* a, mpz_t* b, int alen, int blen, mpz_t* result, int resultlen, int size, std::string type, int threadID)
{
  Idiv->doOperation(result, a, b, resultlen, size, threadID);
}

/*
 * void SMC_Utils::smc_div(mpz_t** a, mpz_t** b, int alen_sig, int alen_exp, int blen_sig, int blen_exp, mpz_t** result, int resultlen_sig, int resultlen_exp,  int size, std::string type, int threadID)
 * {
 *	smc_batch_fop_arithmetic(result, a, b, resultlen_sig, resultlen_exp, alen_sig, alen_exp, blen_sig, blen_exp, size, "/", threadID);
 * }
 */

void SMC_Utils::smc_div(int* a, mpz_t* b, int alen, int blen, mpz_t* result, int resultlen, int size, std::string type, int threadID){
  mpz_t* atmp = (mpz_t*)malloc(sizeof(mpz_t) * size);
  for(int i = 0; i < size; i++)
    mpz_init_set_si(atmp[i], a[i]);
  smc_div(atmp, b, alen, blen, result, resultlen, size, type, threadID);
  smc_batch_free_operator(&atmp, size);
}

void SMC_Utils::smc_div(mpz_t* a, int* b, int alen, int blen, mpz_t* result, int resultlen, int size, std::string type, int threadID){
  mpz_t* b_tmp = (mpz_t*)malloc(sizeof(mpz_t) * size);
  for(int i = 0; i < size; i++)
    mpz_init_set_si(b_tmp[i], b[i]);
  Idiv->doOperationPub(result, a, b_tmp, resultlen, size, threadID);
  smc_batch_free_operator(&b_tmp, size);
}


void SMC_Utils::smc_compute_len(int alen, int blen, int* len)
{
  *len = alen >= blen ? alen : blen;
}


/* All Comparisons */
void SMC_Utils::smc_lt(mpz_t a, mpz_t b, mpz_t result, int alen, int blen, int resultlen, std::string type, int threadID){
  mpz_t sub;
  mpz_init(sub);
  ss->modSub(sub,a,b);
  mpz_t* results = (mpz_t*)malloc(sizeof(mpz_t));
  mpz_t* subs = (mpz_t*)malloc(sizeof(mpz_t));

  mpz_init_set(subs[0], sub);
  mpz_init(results[0]);

  int len = 0;
  smc_compute_len(alen, blen, &len);

  Lt->doOperation(results, subs, len, 1, threadID);

  mpz_set(result, results[0]);

  //free the memory
  mpz_clear(sub);
  smc_batch_free_operator(&subs, 1);
  smc_batch_free_operator(&results, 1);
}

void SMC_Utils::smc_lt(mpz_t a, int b, mpz_t result, int alen, int blen, int resultlen, std::string type, int threadID){
  mpz_t bs;
  mpz_init_set_si(bs, b);
  smc_lt(a, bs, result, alen, blen, resultlen, "int", threadID);
  mpz_clear(bs);
}

void SMC_Utils::smc_lt(int a, mpz_t b, mpz_t result, int alen, int blen, int resultlen, std::string type, int threadID){
  mpz_t as;
  mpz_init_set_si(as, a);
  smc_lt(as, b, result, alen, blen, resultlen, "int", threadID);
  mpz_clear(as);
}

//batch operations of comparisons
void SMC_Utils::smc_lt(mpz_t* a, mpz_t* b, int alen, int blen, mpz_t* result, int resultlen, int size, std::string type, int threadID)
{
  mpz_t* sub = (mpz_t*)malloc(sizeof(mpz_t) * size);
  for(int i=0; i<size; ++i)
    mpz_init(sub[i]);
  int len = 0;
  smc_compute_len(alen, blen, &len);
  ss->modSub(sub, a, b, size);
  Lt->doOperation(result, sub, len, size, threadID);
  smc_batch_free_operator(&sub, size);
}

/*
 * void SMC_Utils::smc_lt(mpz_t** a, mpz_t** b, int alen_sig, int alen_exp, int blen_sig, int blen_exp, mpz_t* result, int resultlen, int size, std::string type, int threadID)
 * {
 *	smc_batch_fop_comparison(result, a, b, resultlen, -1, alen_sig, alen_exp, blen_sig, blen_exp, size, "<0", threadID);
 * }
 */

void SMC_Utils::smc_gt(mpz_t a, mpz_t b, mpz_t result, int alen, int blen, int resultlen, std::string type, int threadID){
  mpz_t sub;
  mpz_init(sub);
  ss->modSub(sub,b,a);

  mpz_t* results = (mpz_t*)malloc(sizeof(mpz_t));
  mpz_t* subs = (mpz_t*)malloc(sizeof(mpz_t));
  mpz_init_set(subs[0], sub);
  mpz_init(results[0]);

  /********************************************/
  int len = 0;
  smc_compute_len(alen, blen, &len);
  /********************************************/
  Lt->doOperation(results, subs, len, 1, threadID);
  mpz_set(result, results[0]);

  //free the memory
  mpz_clear(sub);
  smc_batch_free_operator(&subs, 1);
  smc_batch_free_operator(&results, 1);
}

void SMC_Utils::smc_gt(mpz_t a, int b, mpz_t result, int alen, int blen, int resultlen, std::string type, int threadID){
  mpz_t bs;
  mpz_init_set_si(bs, b);
  smc_gt(a, bs, result, alen, blen, resultlen, type, threadID);
  mpz_clear(bs);
}

void SMC_Utils::smc_gt(int a, mpz_t b, mpz_t result, int alen, int blen, int resultlen, std::string type, int threadID){
  mpz_t as;
  mpz_init_set_si(as, a);
  smc_gt(as, b, result, alen, blen, resultlen, type, threadID);
  mpz_clear(as);
}


//batch operations of gt
void SMC_Utils::smc_gt(mpz_t* a, mpz_t* b, int alen, int blen, mpz_t* result, int resultlen, int size, std::string type, int threadID)
{
  mpz_t* sub = (mpz_t*)malloc(sizeof(mpz_t) * size);
  for(int i = 0; i < size; ++i)
    mpz_init(sub[i]);
  int len =  0;
  smc_compute_len(alen, blen, &len);
  ss->modSub(sub, b, a, size);
  Lt->doOperation(result, sub, len, size, threadID);
  smc_batch_free_operator(&sub, size);
}

/*
 * void SMC_Utils::smc_gt(mpz_t** a, mpz_t** b, int alen_sig, int alen_exp, int blen_sig, int blen_exp, mpz_t* result, int resultlen, int size, std::string type, int threadID)
 * {
 *	smc_batch_fop_comparison(result, b, a, resultlen, -1, blen_sig, blen_exp, alen_sig, alen_exp, size, "<0", threadID);
 * }
 */

void SMC_Utils::smc_leq(mpz_t a, mpz_t b, mpz_t result, int alen, int blen, int resultlen, std::string type, int threadID){
  mpz_t sub;
  mpz_init(sub);
  ss->modSub(sub,b,a);

  mpz_t* results = (mpz_t*)malloc(sizeof(mpz_t));
  mpz_t* subs = (mpz_t*)malloc(sizeof(mpz_t));
  mpz_init_set(subs[0], sub);
  mpz_init(results[0]);

  int len = 0;
  smc_compute_len(alen, blen, &len);
  Lt->doOperation(results, subs, len, 1, threadID);
  mpz_set(result, results[0]);
  ss->modSub(result, 1, result);

  //free the memory
  mpz_clear(sub);
  smc_batch_free_operator(&results, 1);
  smc_batch_free_operator(&subs, 1);
}

void SMC_Utils::smc_leq(mpz_t a, int b, mpz_t result, int alen, int blen, int resultlen, std::string type, int threadID){
  mpz_t bs;
  mpz_init_set_si(bs, b);
  smc_leq(a, bs, result, alen, blen, resultlen, type, threadID);
  mpz_clear(bs);
}

void SMC_Utils::smc_leq(int a, mpz_t b, mpz_t result, int alen, int blen, int resultlen, std::string type, int threadID){
  mpz_t as;
  mpz_init_set_si(as, a);
  smc_leq(as, b, result, alen, blen, resultlen, type, threadID);
  mpz_clear(as);
}


//batch operations of leq
void SMC_Utils::smc_leq(mpz_t* a, mpz_t* b, int alen, int blen, mpz_t* result, int resultlen, int size, std::string type, int threadID)
{
  mpz_t* sub = (mpz_t*)malloc(sizeof(mpz_t) * size);
  for(int i = 0; i < size; i++)
    mpz_init(sub[i]);
  ss->modSub(sub, b, a, size);
  int len = 0;
  smc_compute_len(alen, blen, &len);
  Lt->doOperation(result, sub, len, size, threadID);
  ss->modSub(result, 1, result, size);
  smc_batch_free_operator(&sub, size);
}

void SMC_Utils::smc_leq(mpz_t* a, int int_b, int alen, int blen, mpz_t* result, int resultlen, int size, std::string type, int threadID)
{
  mpz_t* b = (mpz_t*)malloc(sizeof(mpz_t) * size);
  mpz_t* sub = (mpz_t*)malloc(sizeof(mpz_t) * size);
  for(int i = 0; i < size; i++)
  {
    mpz_init(sub[i]);
    mpz_init_set_ui(b[i], int_b);
  }

  ss->modSub(sub, b, a, size);
  int len = 0;
  smc_compute_len(alen, blen, &len);
  Lt->doOperation(result, sub, len, size, threadID);
  ss->modSub(result, 1, result, size);
  smc_batch_free_operator(&sub, size);
  smc_batch_free_operator(&b, size);
}


void SMC_Utils::smc_geq(mpz_t a, mpz_t b, mpz_t result, int alen, int blen, int resultlen, std::string type, int threadID){
  mpz_t sub;
  mpz_init(sub);
  ss->modSub(sub, a, b);

  mpz_t* results = (mpz_t*)malloc(sizeof(mpz_t));
  mpz_t* subs = (mpz_t*)malloc(sizeof(mpz_t));
  mpz_init_set(subs[0], sub);
  mpz_init(results[0]);

  int len = 0;
  smc_compute_len(alen, blen, &len);
  Lt->doOperation(results, subs, len, 1, threadID);
  mpz_set(result, results[0]);
  ss->modSub(result, 1, result);

  mpz_clear(sub);
  smc_batch_free_operator(&results, 1);
  smc_batch_free_operator(&subs, 1);

}

void SMC_Utils::smc_geq(mpz_t a, int b, mpz_t result, int alen, int blen, int resultlen, std::string type, int threadID){
  mpz_t bs;
  mpz_init_set_si(bs, b);
  smc_geq(a, bs, result, alen, blen, resultlen, type, threadID);
  mpz_clear(bs);
}

void SMC_Utils::smc_geq(int a, mpz_t b, mpz_t result, int alen, int blen, int resultlen, std::string type, int threadID){
  mpz_t as;
  mpz_init_set_si(as, a);
  smc_geq(as, b, result, alen, blen, resultlen, type, threadID);
  mpz_clear(as);
}


//batch operations of geq
void SMC_Utils::smc_geq(mpz_t* a, mpz_t* b, int alen, int blen, mpz_t* result, int resultlen, int size, std::string type, int threadID)
{
  mpz_t* sub = (mpz_t*)malloc(sizeof(mpz_t) * size);
  for(int i = 0; i < size; i++)
    mpz_init(sub[i]);
  ss->modSub(sub, a, b, size);

  int len = 0;
  smc_compute_len(alen, blen, &len);
  Lt->doOperation(result, sub, len, size, threadID);
  ss->modSub(result, 1, result, size);
  smc_batch_free_operator(&sub, size);
}


// Equality and Inequality
void SMC_Utils::smc_eqeq(mpz_t a, mpz_t b, mpz_t result, int alen, int blen, int resultlen, std::string type, int threadID){
  mpz_t sub;
  mpz_init(sub);
  ss->modSub(sub, a, b);
  mpz_t* results = (mpz_t*)malloc(sizeof(mpz_t));
  mpz_t* subs = (mpz_t*)malloc(sizeof(mpz_t));
  mpz_init_set(subs[0], sub);
  mpz_init(results[0]);

  int len = 0;
  smc_compute_len(alen, blen, &len);
  Eq->doOperation(subs, results, len, 1, threadID);
  mpz_set(result, results[0]);

  mpz_clear(sub);
  smc_batch_free_operator(&results, 1);
  smc_batch_free_operator(&subs, 1);
}

void SMC_Utils::smc_eqeq(mpz_t a, int b, mpz_t result, int alen, int blen, int resultlen, std::string type, int threadID){
  mpz_t bs;
  mpz_init_set_si(bs, b);
  smc_eqeq(a, bs, result, alen, blen, resultlen, type, threadID);
  mpz_clear(bs);
}

void SMC_Utils::smc_eqeq(int a, mpz_t b, mpz_t result, int alen, int blen, int resultlen, std::string type, int threadID){
  mpz_t as;
  mpz_init_set_si(as, a);
  smc_eqeq(as, b, result, alen, blen, resultlen, type, threadID);
  mpz_clear(as);
}


//batch operations of eqeq
void SMC_Utils::smc_eqeq(mpz_t* a, mpz_t* b, int alen, int blen, mpz_t* result, int resultlen, int size, std::string type, int threadID)
{
  mpz_t* sub = (mpz_t*)malloc(sizeof(mpz_t) * size);
  for(int i=0; i<size; ++i)
    mpz_init(sub[i]);
  int len = 0;
  smc_compute_len(alen, blen, &len);
  ss->modSub(sub, a, b, size);
  Eq->doOperation(sub, result, len, size, threadID);
  smc_batch_free_operator(&sub, size);
}


void SMC_Utils::smc_neq(mpz_t a, mpz_t b, mpz_t result, int alen, int blen, int resultlen, std::string type, int threadID){
  mpz_t sub;
  mpz_init(sub);

  ss->modSub(sub,a,b);
  mpz_t* results = (mpz_t*)malloc(sizeof(mpz_t));
  mpz_t* subs = (mpz_t*)malloc(sizeof(mpz_t));

  mpz_init_set(subs[0], sub);
  mpz_init(results[0]);

  int len = 0;
  smc_compute_len(alen, blen, &len);
  Eq->doOperation(subs, results, len, 1, threadID);
  mpz_set(result, results[0]);
  ss->modSub(result, 1, result);

  mpz_clear(sub);
  smc_batch_free_operator(&results, 1);
  smc_batch_free_operator(&subs, 1);
}

void SMC_Utils::smc_neq(mpz_t a, int b, mpz_t result, int alen, int blen, int resultlen, std::string type, int threadID){
  mpz_t bs;
  mpz_init_set_si(bs, b);
  smc_neq(a, bs, result, alen, blen, resultlen, type, threadID);
  mpz_clear(bs);
}

void SMC_Utils::smc_neq(int a, mpz_t b, mpz_t result, int alen, int blen, int resultlen, std::string type, int threadID){
  mpz_t as;
  mpz_init_set_si(as, a);
  smc_neq(as, b, result, alen, blen, resultlen, type, threadID);
  mpz_clear(as);
}


//batch operations of neq
void SMC_Utils::smc_neq(mpz_t* a, mpz_t* b, int alen, int blen, mpz_t* result, int resultlen, int size, std::string type, int threadID)
{
  mpz_t* sub = (mpz_t*)malloc(sizeof(mpz_t) * size);
  for(int i=0; i<size; ++i)
    mpz_init(sub[i]);
  int len = 0;
  smc_compute_len(alen, blen, &len);
  ss->modSub(sub, a, b, size);
  Eq->doOperation(sub, result, len, size, threadID);
  ss->modSub(result, 1, result, size);
  smc_batch_free_operator(&sub, size);
}


// Bitwise Operations
void SMC_Utils::smc_land(mpz_t a, mpz_t b, mpz_t result, int alen, int blen, int resultlen, std::string type, int threadID){
  mpz_t* as = (mpz_t*)malloc(sizeof(mpz_t));
  mpz_t* bs = (mpz_t*)malloc(sizeof(mpz_t));
  mpz_t* results = (mpz_t*)malloc(sizeof(mpz_t));

  mpz_init_set(as[0], a);
  mpz_init_set(bs[0], b);
  mpz_init(results[0]);
  BOps->BitAnd(as, bs, results, 1, threadID);
  mpz_set(result, results[0]);

  mpz_clear(as[0]);
  mpz_clear(bs[0]);
  mpz_clear(results[0]);
  free(as);
  free(bs);
  free(results);
}

void SMC_Utils::smc_land(mpz_t* a, mpz_t* b, int size, mpz_t* result, std::string type, int threadID){
  BOps->BitAnd(a, b, result, size, threadID);
}

void SMC_Utils::smc_xor(mpz_t a, mpz_t b, mpz_t result, int alen, int blen, int resultlen, std::string type, int threadID){
  mpz_t* as = (mpz_t*)malloc(sizeof(mpz_t));
  mpz_t* bs = (mpz_t*)malloc(sizeof(mpz_t));
  mpz_t* results = (mpz_t*)malloc(sizeof(mpz_t));

  mpz_init_set(as[0], a);
  mpz_init_set(bs[0], b);
  mpz_init(results[0]);
  BOps->BitXor(as, bs, results, 1, threadID);
  mpz_set(result, results[0]);

  //free the memory
  mpz_clear(as[0]);
  mpz_clear(bs[0]);
  mpz_clear(results[0]);
  free(as);
  free(bs);
  free(results);
}

void SMC_Utils::smc_xor(mpz_t* a, mpz_t* b, int size, mpz_t* result, std::string type, int threadID){
  BOps->BitXor(a, b, result, size, threadID);
}

void SMC_Utils::smc_lor(mpz_t a, mpz_t b, mpz_t result, int alen, int blen, int resultlen, std::string type, int threadID){
  mpz_t* as = (mpz_t*)malloc(sizeof(mpz_t));
  mpz_t* bs = (mpz_t*)malloc(sizeof(mpz_t));
  mpz_t* results = (mpz_t*)malloc(sizeof(mpz_t));

  mpz_init_set(as[0], a);
  mpz_init_set(bs[0], b);
  mpz_init(results[0]);
  BOps->BitOr(as, bs, results, 1, threadID);
  mpz_set(result, results[0]);

  //free the memory
  mpz_clear(as[0]);
  mpz_clear(bs[0]);
  mpz_clear(results[0]);

  free(as);
  free(bs);
  free(results);
}

void SMC_Utils::smc_lor(mpz_t* a, mpz_t* b, int size, mpz_t* result, std::string type, int threadID){
  BOps->BitOr(a, b, result, size, threadID);
}


void SMC_Utils::smc_shr(mpz_t a, mpz_t b, mpz_t result, int alen, int blen, int resultlen, std::string type, int threadID){
  mpz_t* a_tmp = (mpz_t*)malloc(sizeof(mpz_t));
  mpz_t* b_tmp = (mpz_t*)malloc(sizeof(mpz_t));
  mpz_t* result_tmp = (mpz_t*)malloc(sizeof(mpz_t));

  mpz_init_set(a_tmp[0], a);
  mpz_init_set(b_tmp[0], b);
  mpz_init(result_tmp[0]);

  smc_shr(a_tmp, b_tmp, alen, blen, result_tmp, resultlen, 1, type, threadID);
  mpz_set(result, result_tmp[0]);

  smc_batch_free_operator(&a_tmp, 1);
  smc_batch_free_operator(&b_tmp, 1);
  smc_batch_free_operator(&result_tmp, 1);

}

void SMC_Utils::smc_shr(mpz_t a, int b, mpz_t result, int alen, int blen, int resultlen, std::string type, int threadID){
  mpz_t* a_tmp = (mpz_t*)malloc(sizeof(mpz_t));
  mpz_t* result_tmp = (mpz_t*)malloc(sizeof(mpz_t));
  int* b_tmp = (int*)malloc(sizeof(int));
  mpz_init_set(a_tmp[0], a);
  mpz_init(result_tmp[0]);
  b_tmp[0] = b;

  smc_shr(a_tmp, b_tmp, alen, blen, result_tmp, resultlen, 1, type, threadID);
  mpz_set(result, result_tmp[0]);

  free(b_tmp);
  smc_batch_free_operator(&a_tmp, 1);
  smc_batch_free_operator(&result_tmp, 1);
}

void SMC_Utils::smc_shr(mpz_t* a, mpz_t* b, int alen, int blen, mpz_t* result, int resultlen, int size, std::string type, int threadID){
  if(blen == -1){
    int* b_tmp = (int*)malloc(sizeof(int) * size);
    for(int i = 0; i < size; i++)
      b_tmp[i] = mpz_get_si(b[i]);
    smc_shr(a, b_tmp, alen, blen, result, resultlen, size, type, threadID);
    free(b_tmp);
  }else
    Ts->doOperation(result, a, alen, b, size, threadID);
}

void SMC_Utils::smc_shr(mpz_t* a, int* b, int alen, int blen, mpz_t* result, int resultlen, int size, std::string type, int threadID){
  int same = 1;
  for(int i = 1; i < size; i++)
    if(b[i] != b[0])
      same = 0;
  if(same)
    T->doOperation(result, a, alen, b[0], size, threadID);
  else{
    //for now, we perform sequential executions
    for(int i = 0; i < size; i++)
      smc_shr(a[i], b[i], result[i], alen, blen, resultlen, type, threadID);
  }
}

void SMC_Utils::smc_shl(mpz_t a, mpz_t b, mpz_t result, int alen, int blen, int resultlen, std::string type, int threadID){
  mpz_t* a_tmp = (mpz_t*)malloc(sizeof(mpz_t));
  mpz_t* b_tmp = (mpz_t*)malloc(sizeof(mpz_t));
  mpz_t* result_tmp = (mpz_t*)malloc(sizeof(mpz_t));

  mpz_init_set(a_tmp[0], a);
  mpz_init_set(b_tmp[0], b);
  mpz_init(result_tmp[0]);

  smc_shl(a_tmp, b_tmp, alen, blen, result_tmp, resultlen, 1, type, threadID);
  mpz_set(result, result_tmp[0]);

  smc_batch_free_operator(&a_tmp, 1);
  smc_batch_free_operator(&b_tmp, 1);
  smc_batch_free_operator(&result_tmp, 1);
}

void SMC_Utils::smc_shl(mpz_t a, int b, mpz_t result, int alen, int blen, int resultlen, std::string type, int threadID){
  mpz_t const2;
  mpz_init_set_ui(const2, 2);
  ss->modPow(result, const2, b);
  ss->modMul(result, a, result);
  mpz_clear(const2);
}

void SMC_Utils::smc_shl(mpz_t* a, mpz_t* b, int alen, int blen, mpz_t* result, int resultlen, int size, std::string type, int threadID){
  if(blen == -1){
    int* b_tmp = (int*)malloc(sizeof(int)*size);
    for(int i = 0; i < size; i++)
      b_tmp[i] = mpz_get_si(b[i]);
    smc_shl(a, b_tmp, alen, blen, result, resultlen, size, type, threadID);
    free(b_tmp);

  }else{
    P->doOperation(result, b, blen, size, threadID);
    Mul->doOperation(result, result, a, size, threadID);
  }
}

void SMC_Utils::smc_shl(mpz_t* a, int* b, int alen, int blen, mpz_t* result, int resultlen, int size, std::string type, int threadID){
  mpz_t const2;
  mpz_init_set_ui(const2, 2);
  for(int i = 0; i < size; i++){
    ss->modPow(result[i], const2, b[i]);
    ss->modMul(result[i], a[i], result[i]);
  }
  mpz_clear(const2);
}


// Dot Product
void SMC_Utils::smc_dot(mpz_t* a, mpz_t* b, int size, mpz_t result, int threadID){
  DProd->doOperation(a, b, result, size, threadID);
}

void SMC_Utils::smc_dot(mpz_t** a, mpz_t** b, int size, int array_size, mpz_t* result, std::string type, int threadID){
  DProd->doOperation(a, b, result, size, array_size, threadID);
}

void SMC_Utils::smc_dot_mal(mpz_t** a, mpz_t** b, int size, mpz_t* result, int threadID){
  DProd->doOperation_mal(a, b, result, size,  threadID);
}


void SMC_Utils::smc_batch_handle_priv_cond(mpz_t* result, mpz_t* result_org, mpz_t out_cond, mpz_t *priv_cond, int counter, int size, int threadID)
{
  mpz_t* tmp = (mpz_t*)malloc(sizeof(mpz_t) * size);
  for(int i=0; i<size; ++i)
    mpz_init(tmp[i]);
  if(out_cond == NULL && counter == -1 && priv_cond == NULL)
  {
  }
  else if(out_cond != NULL && counter == -1 && priv_cond == NULL)
  {
    for(int i = 0; i < size; i++)
      mpz_set(tmp[i], out_cond);
    ss->modSub(result, result, result_org, size);
    Mul->doOperation(result, result, tmp, size, threadID);
    ss->modAdd(result, result, result_org, size);
    /*
     *		ss->modSub(tmp3, 1, tmp, size);
     *                Mul->doOperation(tmp1, result, tmp, size);
     *                Mul->doOperation(tmp2, result_org, tmp3, size);
     *                ss->modAdd(result, tmp1, tmp2, size);
     */
  }
  else if(out_cond == NULL && counter != -1 && priv_cond != NULL)
  {
    for(int i = 0; i < size; i++)
      if(counter != size)
        mpz_set(tmp[i], priv_cond[i/(size/counter)]);
    else
      mpz_set(tmp[i], priv_cond[i]);
    ss->modSub(result, result, result_org, size);
    Mul->doOperation(result, result, tmp, size, threadID);
    ss->modAdd(result, result, result_org, size);
    /*
     *		ss->modSub(tmp3, 1, tmp, size);
     *                Mul->doOperation(tmp1, result, tmp, size);
     *                Mul->doOperation(tmp2, result_org, tmp3, size);
     *                ss->modAdd(result, tmp1, tmp2, size);
     */
  }
  for(int i=0; i<size; ++i)
    mpz_clear(tmp[i]);
  free(tmp);
}

void SMC_Utils::smc_batch_BOP_int(mpz_t* result, mpz_t* a, mpz_t* b, int resultlen, int alen, int blen, mpz_t out_cond, mpz_t* priv_cond, int counter, int size, std::string op, std::string type, int threadID)
{
  mpz_t* result_org = (mpz_t*)malloc(sizeof(mpz_t) * size);
  for(int i = 0; i < size; i++)
    mpz_init_set(result_org[i], result[i]);
  if (op == "*"){
    smc_mult(a, b, alen, blen, result, resultlen, size, type, threadID);
  } else if (op == "-"){
    smc_sub(a, b, alen, blen, result, resultlen, size, type, threadID);
  } else if (op == "+"){
    smc_add(a, b, alen, blen, result, resultlen, size, type, threadID);
  } else if (op == "=="){
    smc_eqeq(a, b, alen, blen, result, resultlen, size, type, threadID);
  } else if (op == "!="){
    smc_neq(a, b, alen, blen, result, resultlen, size, type, threadID);
  } else if (op == ">"){
    smc_gt(a, b, alen, blen, result, resultlen, size, type, threadID);
  } else if (op == ">="){
    smc_geq(a, b, alen, blen, result, resultlen, size, type, threadID);
  } else if (op == "<"){
    smc_lt(a, b, alen, blen, result, resultlen, size, type, threadID);
  } else if (op == "<="){
    smc_leq(a, b, alen, blen, result, resultlen, size, type, threadID);
  } else if (op == "/"){
    smc_div(a, b, alen, blen, result, resultlen, size, type, threadID);
  } else if (op == "/P"){
    Idiv->doOperationPub(result, a, b, resultlen, size, threadID);
  } else if (op == "="){
    smc_set(a, result, alen, resultlen, size, type, threadID);
  } else if (op == ">>"){
    smc_shr(a, b, alen, blen, result, resultlen, size, type, threadID);
  } else if(op == "<<"){
    smc_shl(a, b, alen, blen, result, resultlen, size, type, threadID);
  }
  else{
    std::cout << "Unrecognized op: " << op << "\n";
  }

  smc_batch_handle_priv_cond(result, result_org, out_cond, priv_cond, counter, size, threadID);
  smc_batch_free_operator(&result_org, size);
}



void SMC_Utils::smc_convert_operator(mpz_t** result, mpz_t** op, int* index_array, int dim, int size, int flag){
  *result = (mpz_t*)malloc(sizeof(mpz_t) * size);
  for(int i = 0; i < size; i++)
    mpz_init((*result)[i]);
  int dim1, dim2;
  for(int i = 0; i < size; i++){
    if(flag == 1){
      if(dim != 0){
        dim1 = index_array[3*i]/dim;
        dim2 = index_array[3*i]%dim;
        mpz_set((*result)[i], op[dim1][dim2]);
      }
      else
        mpz_set((*result)[i], op[0][index_array[3*i]]);
    }
    else if(flag == 2){
      if(dim != 0 && dim != -1){
        dim1 = index_array[3*i+1]/dim;
        dim2 = index_array[3*i+1]%dim;
        mpz_set((*result)[i], op[dim1][dim2]);
      }
      else if(dim == 0)
        mpz_set((*result)[i], op[0][index_array[3*i+1]]);
    }
    else{
      if(dim != 0){
        dim1 = index_array[3*i+2]/dim;
        dim2 = index_array[3*i+2]%dim;
        mpz_set((*result)[i], op[dim1][dim2]);
      }
    }
  }
}



//convert op to corresponding one-dimensional array result
void SMC_Utils::smc_convert_operator(mpz_t** result, mpz_t* op, int* index_array, int dim, int size, int flag)
{
  mpz_t** ops = (mpz_t**)malloc(sizeof(mpz_t*));
  *ops = op;
  smc_convert_operator(result, ops, index_array, dim, size, flag);
  free(ops);
}

void SMC_Utils::smc_convert_operator(mpz_t*** result, mpz_t** op, int* index_array, int dim, int size, int flag){
  mpz_t*** ops = NULL;
  if(op != NULL){
    ops = (mpz_t***)malloc(sizeof(mpz_t**));
    *ops = op;
  }
  smc_convert_operator(result, ops, index_array, dim, size, flag);
  if(op != NULL)
    free(ops);
}

void SMC_Utils::smc_convert_operator(mpz_t*** result, mpz_t*** op, int* index_array, int dim, int size, int flag)
{
  *result =(mpz_t**)malloc(sizeof(mpz_t*) * size);
  int dim1, dim2;
  for(int i = 0; i < size; i++){
    (*result)[i] = (mpz_t*)malloc(sizeof(mpz_t) * 4);
    for(int j = 0; j < 4; j++)
      mpz_init((*result)[i][j]);
    for(int j = 0; j < 4; j++){
      if(flag == 1){
        if(dim != 0){
          dim1 = index_array[3*i]/dim;
          dim2 = index_array[3*i]%dim;
          mpz_set((*result)[i][j], op[dim1][dim2][j]);
        }
        else
          mpz_set((*result)[i][j], op[0][i][j]);
      }
      else if(flag == 2){
        if(op != NULL && dim != -1){
          if(dim != 0){
            dim1 = index_array[3*i+1]/dim;
            dim2 = index_array[3*i+1]%dim;
            mpz_set((*result)[i][j], op[dim1][dim2][j]);
          }
          else
            mpz_set((*result)[i][j], op[0][i][j]);
        }
      }
      else{
        if(dim != 0){
          dim1 = index_array[3*i+2]/dim;
          dim2 = index_array[3*i+2]%dim;
          mpz_set((*result)[i][j], op[dim1][dim2][j]);
        }
      }
    }
  }
}

void SMC_Utils::smc_batch_free_operator(mpz_t** op, int size)
{
  for(int i = 0; i < size; i++)
    mpz_clear((*op)[i]);
  free(*op);
}

void SMC_Utils::smc_batch_free_operator(mpz_t*** op, int size)
{
  for(int i = 0; i < size; i++)
  {
    for(int j = 0; j < 4; j++)
      mpz_clear((*op)[i][j]);
    free((*op)[i]);
  }
  free(*op);
}

/************************************ INTEGER BATCH ****************************************/
void SMC_Utils::smc_batch(mpz_t* a, mpz_t* b, mpz_t* result, int alen, int blen, int resultlen, int adim, int bdim, int resultdim, mpz_t out_cond, mpz_t* priv_cond, int counter, int* index_array, int size, std::string op, std::string type, int threadID){
  mpz_t *a_tmp, *b_tmp, *result_tmp;
  smc_convert_operator(&a_tmp, a, index_array, adim, size, 1);
  smc_convert_operator(&b_tmp, b, index_array, bdim, size, 2);
  smc_convert_operator(&result_tmp, result, index_array, resultdim, size, 3);

  smc_batch_BOP_int(result_tmp, a_tmp, b_tmp, resultlen, alen, blen, out_cond, priv_cond, counter, size, op, type, threadID);

  for(int i = 0; i < size; ++i)
    mpz_set(result[index_array[3*i+2]], result_tmp[i]);

  smc_batch_free_operator(&a_tmp, size);
  smc_batch_free_operator(&b_tmp, size);
  smc_batch_free_operator(&result_tmp, size);
}

// used to compute 1-priv_cond in a batch stmt
void SMC_Utils::smc_batch(int a, mpz_t* b, mpz_t* result, mpz_t out_cond, mpz_t* priv_cond, int counter, int* index_array, int size, std::string op, int threadID){
  mpz_t* a_tmp = (mpz_t*)malloc(sizeof(mpz_t) * size);
  mpz_t* out_tmp = (mpz_t*)malloc(sizeof(mpz_t) * size);

  for(int i = 0; i < size; i++){
    mpz_init_set_ui(a_tmp[i], a);
    mpz_init(out_tmp[i]);
  }

  ss->modSub(result, a_tmp, b, size);

  if(out_cond != NULL){
    for(int i = 0; i < size; i++)
      mpz_set(out_tmp[i], out_cond);
    Mul->doOperation(result, result, out_tmp, size, threadID);
  }

  smc_batch_free_operator(&a_tmp, size);
  smc_batch_free_operator(&out_tmp, size);
}

void SMC_Utils::smc_batch(mpz_t* a, mpz_t* b, mpz_t* result, mpz_t out_cond, mpz_t* priv_cond, int counter, int *index_array, int size, std::string op, int threadID)
{
  if(counter == size)
    ss->modSub(result, a, b, size);
  else{
    mpz_t* tmp = (mpz_t*)malloc(sizeof(mpz_t) * size);
    for(int i = 0; i < size; i++)
      mpz_init_set(tmp[i], a[i/(size/counter)]);
    ss->modSub(result, tmp, b, size);
    smc_batch_free_operator(&tmp, size);
  }
}

//first param: int array
//second param: int array
//third param: one-dim private int array
void SMC_Utils::smc_batch(int* a, int* b, mpz_t* result, int alen, int blen, int resultlen, int adim, int bdim, int resultdim, mpz_t out_cond, mpz_t* priv_cond, int counter, int* index_array, int size, std::string op, std::string type, int threadID){

  mpz_t* a_tmp = (mpz_t*)malloc(sizeof(mpz_t) * size);
  mpz_t* b_tmp = (mpz_t*)malloc(sizeof(mpz_t) * size);
  for(int i = 0; i < size; i++){
    mpz_init_set_si(a_tmp[i], a[i]);
    mpz_init_set_si(b_tmp[i], b[i]);
  }

  smc_batch(a_tmp, b_tmp, result, alen, blen, resultlen, adim, bdim, resultdim, out_cond, priv_cond, counter, index_array, size, op, type, threadID);

  smc_batch_free_operator(&a_tmp, size);
  smc_batch_free_operator(&b_tmp, size);
}

//first param: int array
//second param: int array
//third param: two-dim private int array
void SMC_Utils::smc_batch(int* a, int* b, mpz_t** result, int alen, int blen, int resultlen, int adim, int bdim, int resultdim, mpz_t out_cond, mpz_t* priv_cond, int counter, int* index_array, int size, std::string op, std::string type, int threadID){

  mpz_t* a_tmp = (mpz_t*)malloc(sizeof(mpz_t) * size);
  mpz_t* b_tmp = (mpz_t*)malloc(sizeof(mpz_t) * size);

  for(int i = 0; i < size; i++){
    mpz_init_set_si(a_tmp[i], a[i]);
    mpz_init_set_si(b_tmp[i], b[i]);
  }

  smc_batch(a_tmp, b_tmp, result, alen, blen, resultlen, adim, bdim, resultdim, out_cond, priv_cond, counter, index_array, size, op, type, threadID);
  smc_batch_free_operator(&a_tmp, size);
  smc_batch_free_operator(&b_tmp, size);
}

//first param: int array
//second param: one-dim private int array
//third param: one-dim private int array
void SMC_Utils::smc_batch(int* a, mpz_t* b, mpz_t* result, int alen, int blen, int resultlen, int adim, int bdim, int resultdim, mpz_t out_cond, mpz_t* priv_cond, int counter, int* index_array, int size, std::string op, std::string type, int threadID){

  mpz_t* a_tmp = (mpz_t*)malloc(sizeof(mpz_t) * size);
  for(int i = 0; i < size; i++)
    mpz_init_set_si(a_tmp[i], a[i]);
  smc_batch(a_tmp, b, result, alen, blen, resultlen, adim, bdim, resultdim, out_cond, priv_cond, counter, index_array, size, op, type, threadID);
  smc_batch_free_operator(&a_tmp, size);
}

//first param: int array
//second param: one-dim private int array
//third param: two-dim private int array
void SMC_Utils::smc_batch(int* a, mpz_t* b, mpz_t** result, int alen, int blen, int resultlen, int adim, int bdim, int resultdim, mpz_t out_cond, mpz_t* priv_cond, int counter, int* index_array, int size, std::string op, std::string type, int threadID){

  mpz_t* a_tmp = (mpz_t*)malloc(sizeof(mpz_t) * size);
  for(int i = 0; i < size; i++)
    mpz_init_set_si(a_tmp[i], a[i]);
  smc_batch(a_tmp, b, result, alen, blen, resultlen, adim, bdim, resultdim, out_cond, priv_cond, counter, index_array, size, op, type, threadID);
  smc_batch_free_operator(&a_tmp, size);
}

//first param: one-dim private int array
//second param: int array
//third param: one-dim private int array
void SMC_Utils::smc_batch(mpz_t* a, int *b, mpz_t* result, int alen, int blen, int resultlen, int adim, int bdim, int resultdim, mpz_t out_cond, mpz_t* priv_cond, int counter, int* index_array, int size, std::string op, std::string type, int threadID){

  mpz_t* b_tmp = (mpz_t*)malloc(sizeof(mpz_t) * size);
  for(int i = 0; i < size; i++)
    mpz_init_set_si(b_tmp[i], b[i]);
  op = (op == "/") ? "/P" : op;
  smc_batch(a, b_tmp, result, alen, blen, resultlen, adim, bdim, resultdim, out_cond, priv_cond, counter, index_array, size, op, type, threadID);
  smc_batch_free_operator(&b_tmp, size);
}

//first param: one-dim private int array
//second param: int array
//third param: two-dim private int array
void SMC_Utils::smc_batch(mpz_t* a, int *b, mpz_t** result, int alen, int blen, int resultlen, int adim, int bdim, int resultdim, mpz_t out_cond, mpz_t* priv_cond, int counter, int* index_array, int size, std::string op, std::string type, int threadID){
  mpz_t* b_tmp = (mpz_t*)malloc(sizeof(mpz_t) * size);
  for(int i = 0; i < size; i++)
    mpz_init_set_si(b_tmp[i], b[i]);
  op = (op == "/") ? "/P" : op;
  smc_batch(a, b_tmp, result, alen, blen, resultlen, adim, bdim, resultdim, out_cond, priv_cond, counter, index_array, size, op, type, threadID);
  smc_batch_free_operator(&b_tmp, size);
}

//first param: integer array
//second param: two-dim private int
//assignment param: one-dim private int
void SMC_Utils::smc_batch(int *a, mpz_t** b, mpz_t* result, int alen, int blen, int resultlen, int adim, int bdim, int resultdim, mpz_t out_cond, mpz_t* priv_cond, int counter, int* index_array, int size, std::string op, std::string type, int threadID){
  mpz_t* a_tmp = (mpz_t*)malloc(sizeof(mpz_t) * size);
  for(int i = 0; i < size; i++)
    mpz_init_set_si(a_tmp[i], a[i]);
  smc_batch(a_tmp, b, result, alen, blen, resultlen, adim, bdim, resultdim, out_cond, priv_cond, counter, index_array, size, op, type, threadID);
  smc_batch_free_operator(&a_tmp, size);
}

//first param: integer array
//second param: two-dim private int
//assignment param: two-dim private int
void SMC_Utils::smc_batch(int *a, mpz_t** b, mpz_t** result, int alen, int blen, int resultlen, int adim, int bdim, int resultdim, mpz_t out_cond, mpz_t* priv_cond, int counter, int* index_array, int size, std::string op, std::string type, int threadID){
  mpz_t* a_tmp = (mpz_t*)malloc(sizeof(mpz_t) * size);
  for(int i = 0; i < size; i++)
    mpz_init_set_si(a_tmp[i], a[i]);
  smc_batch(a_tmp, b, result, alen, blen, resultlen, adim, bdim, resultdim, out_cond, priv_cond, counter, index_array, size, op, type, threadID);
  smc_batch_free_operator(&a_tmp, size);
}

//first param: two-dim private int
//second param: integer array
//assignment param: one-dim private int
void SMC_Utils::smc_batch(mpz_t** a, int* b, mpz_t* result, int alen, int blen, int resultlen, int adim, int bdim, int resultdim, mpz_t out_cond, mpz_t* priv_cond, int counter, int* index_array, int size, std::string op, std::string type, int threadID){
  mpz_t* b_tmp = (mpz_t*)malloc(sizeof(mpz_t) * size);
  for(int i = 0; i < size; i++)
    mpz_init_set_si(b_tmp[i], b[i]);
  op = (op == "/") ? "/P" : op;
  smc_batch(a, b_tmp, result, alen, blen, resultlen, adim, bdim, resultdim, out_cond, priv_cond, counter, index_array, size, op, type, threadID);
  smc_batch_free_operator(&b_tmp, size);
}

//first param: two-dim private int
//second param: integer array
//assignment param: two-dim private int
void SMC_Utils::smc_batch(mpz_t** a, int* b, mpz_t** result, int alen, int blen, int resultlen, int adim, int bdim, int resultdim, mpz_t out_cond, mpz_t* priv_cond, int counter, int* index_array, int size, std::string op, std::string type, int threadID){

  mpz_t* b_tmp = (mpz_t*)malloc(sizeof(mpz_t) * size);
  for(int i = 0; i < size; i++)
    mpz_init_set_si(b_tmp[i], b[i]);
  op = (op == "/") ? "/P" : op;
  smc_batch(a, b_tmp, result, alen, blen, resultlen, adim, bdim, resultdim, out_cond, priv_cond, counter, index_array, size, op, type, threadID);
  //free the memory
  smc_batch_free_operator(&b_tmp, size);
}

//first param: one-dim private int
//second param: two-dim private int
//assignment param: two-dim private int
void SMC_Utils::smc_batch(mpz_t* a, mpz_t** b, mpz_t** result, int alen, int blen, int resultlen, int adim, int bdim, int resultdim, mpz_t out_cond, mpz_t* priv_cond, int counter, int* index_array, int size, std::string op, std::string type, int threadID){
  int dim1, dim2;
  mpz_t *a_tmp, *b_tmp, *result_tmp;
  smc_convert_operator(&a_tmp, a, index_array, adim, size, 1);
  smc_convert_operator(&b_tmp, b, index_array, bdim, size, 2);
  smc_convert_operator(&result_tmp, result, index_array, resultdim, size, 3);

  smc_batch_BOP_int(result_tmp, a_tmp, b_tmp, resultlen, alen, blen, out_cond, priv_cond, counter, size, op, type, threadID);

  if(resultdim != 0){
    for(int i = 0; i < size; ++i){
      dim1 = index_array[3*i+2]/resultdim;
      dim2 = index_array[3*i+2]%resultdim;
      mpz_set(result[dim1][dim2], result_tmp[i]);
    }
  }

  smc_batch_free_operator(&a_tmp, size);
  smc_batch_free_operator(&b_tmp, size);
  smc_batch_free_operator(&result_tmp, size);
}

//first param: two-dim private int
//second param: one-dim private int
//assignment param: two-dim private int
void SMC_Utils::smc_batch(mpz_t** a, mpz_t* b, mpz_t** result, int alen, int blen, int resultlen, int adim, int bdim, int resultdim, mpz_t out_cond, mpz_t* priv_cond, int counter, int* index_array, int size, std::string op, std::string type, int threadID){
  int dim1, dim2;
  mpz_t *a_tmp, *b_tmp, *result_tmp;
  smc_convert_operator(&a_tmp, a, index_array, adim, size, 1);
  smc_convert_operator(&b_tmp, b, index_array, bdim, size, 2);
  smc_convert_operator(&result_tmp, result, index_array, resultdim, size, 3);

  smc_batch_BOP_int(result_tmp, a_tmp, b_tmp, resultlen, alen, blen, out_cond, priv_cond, counter, size, op, type, threadID);

  if(resultdim != 0){
    for(int i = 0; i < size; ++i){
      dim1 = index_array[3*i+2]/resultdim;
      dim2 = index_array[3*i+2]%resultdim;
      mpz_set(result[dim1][dim2], result_tmp[i]);
    }
  }

  smc_batch_free_operator(&a_tmp, size);
  smc_batch_free_operator(&b_tmp, size);
  smc_batch_free_operator(&result_tmp, size);
}

//first param: two-dim private int
//second param: two-dim private int
//assignment param: one-dim private int
void SMC_Utils::smc_batch(mpz_t** a, mpz_t** b, mpz_t* result, int alen, int blen, int resultlen, int adim, int bdim, int resultdim, mpz_t out_cond, mpz_t* priv_cond, int counter, int* index_array, int size, std::string op, std::string type, int threadID){
  if(op == "@"){
    mpz_t** result_tmp = (mpz_t**)malloc(sizeof(mpz_t*));
    result_tmp[0] = (mpz_t*)malloc(sizeof(mpz_t) * resultdim);
    for(int i = 0; i < resultdim; i++)
      mpz_init_set(result_tmp[0][i], result[i]);
    smc_batch(a, b, result_tmp, alen, blen, resultlen, adim, bdim, resultdim, out_cond, priv_cond, counter, index_array, size, op, type, threadID);
    for(int i = 0; i < resultdim; i++)
      mpz_set(result[i], result_tmp[0][i]);
    smc_batch_free_operator(&(result_tmp[0]), resultdim);
    free(result_tmp);
    return;
  }
  mpz_t *a_tmp, *b_tmp, *result_tmp;
  smc_convert_operator(&a_tmp, a, index_array, adim, size, 1);
  smc_convert_operator(&b_tmp, b, index_array, bdim, size, 2);
  smc_convert_operator(&result_tmp, result, index_array, resultdim, size, 3);

  smc_batch_BOP_int(result_tmp, a_tmp, b_tmp, resultlen, alen, blen, out_cond, priv_cond, counter, size, op, type, threadID);

  for(int i = 0; i < size; i++)
    mpz_set(result[index_array[3*i+2]], result_tmp[i]);

  smc_batch_free_operator(&a_tmp, size);
  smc_batch_free_operator(&b_tmp, size);
  smc_batch_free_operator(&result_tmp, size);
}

//first param: one-dim private int
//second param: one-dim private int
//assignment param: two-dim private int
void SMC_Utils::smc_batch(mpz_t* a, mpz_t* b, mpz_t** result, int alen, int blen, int resultlen, int adim, int bdim, int resultdim, mpz_t out_cond, mpz_t* priv_cond, int counter, int* index_array, int size, std::string op, std::string type, int threadID){
  int dim1, dim2;
  mpz_t *a_tmp, *b_tmp, *result_tmp;
  smc_convert_operator(&a_tmp, a, index_array, adim, size, 1);
  smc_convert_operator(&b_tmp, b, index_array, bdim, size, 2);
  smc_convert_operator(&result_tmp, result, index_array, resultdim, size, 3);

  smc_batch_BOP_int(result_tmp, a_tmp, b_tmp, resultlen, alen, blen, out_cond, priv_cond, counter, size, op, type, threadID);

  if(resultdim != 0){
    for(int i = 0; i < size; ++i){
      dim1 = index_array[3*i+2]/resultdim;
      dim2 = index_array[3*i+2]%resultdim;
      mpz_set(result[dim1][dim2], result_tmp[i]);
    }
  }

  smc_batch_free_operator(&a_tmp, size);
  smc_batch_free_operator(&b_tmp, size);
  smc_batch_free_operator(&result_tmp, size);

}
//first param: one-dim private int
//second param: two-dim private int
//assignment param: one-dim private int
void SMC_Utils::smc_batch(mpz_t* a, mpz_t** b, mpz_t* result, int alen, int blen, int resultlen, int adim, int bdim, int resultdim, mpz_t out_cond, mpz_t* priv_cond, int counter, int* index_array, int size, std::string op, std::string type, int threadID){

  mpz_t *a_tmp, *b_tmp, *result_tmp;
  smc_convert_operator(&a_tmp, a, index_array, adim, size, 1);
  smc_convert_operator(&b_tmp, b, index_array, bdim, size, 2);
  smc_convert_operator(&result_tmp, result, index_array, resultdim, size, 3);

  smc_batch_BOP_int(result_tmp, a_tmp, b_tmp, resultlen, alen, blen, out_cond, priv_cond, counter, size, op, type, threadID);

  for(int i = 0; i < size; i++)
    mpz_set(result[index_array[3*i+2]], result_tmp[i]);

  smc_batch_free_operator(&a_tmp, size);
  smc_batch_free_operator(&b_tmp, size);
  smc_batch_free_operator(&result_tmp, size);
}

//first param: two-dim private int
//second param: one-dim private int
//assignment param: one-dim private int
void SMC_Utils::smc_batch(mpz_t** a, mpz_t* b, mpz_t* result, int alen, int blen, int resultlen, int adim, int bdim, int resultdim, mpz_t out_cond, mpz_t* priv_cond, int counter, int* index_array, int size, std::string op, std::string type, int threadID){

  mpz_t *a_tmp, *b_tmp, *result_tmp;
  smc_convert_operator(&a_tmp, a, index_array, adim, size, 1);
  smc_convert_operator(&b_tmp, b, index_array, bdim, size, 2);
  smc_convert_operator(&result_tmp, result, index_array, resultdim, size, 3);

  smc_batch_BOP_int(result_tmp, a_tmp, b_tmp, resultlen, alen, blen, out_cond, priv_cond, counter, size, op, type, threadID);

  for(int i = 0; i < size; i++)
    mpz_set(result[index_array[3*i+2]], result_tmp[i]);

  smc_batch_free_operator(&a_tmp, size);
  smc_batch_free_operator(&b_tmp, size);
  smc_batch_free_operator(&result_tmp, size);
}

void SMC_Utils::smc_batch_dot(mpz_t** a, mpz_t** b, int size, int array_size, int* index_array, mpz_t* result, int threadID)
{
  int a_dim = 0, b_dim = 0;
  mpz_t **a_tmp = (mpz_t**)malloc(sizeof(mpz_t*) * size);
  mpz_t **b_tmp = (mpz_t**)malloc(sizeof(mpz_t*) * size);
  for(int i = 0 ; i < size; i++){
    a_tmp[i] = (mpz_t*)malloc(sizeof(mpz_t) * array_size);
    b_tmp[i] = (mpz_t*)malloc(sizeof(mpz_t) * array_size);
    a_dim = index_array[3*i];
    b_dim = index_array[3*i+1];
    for(int j = 0; j < array_size; j++)
    {
      mpz_init_set(a_tmp[i][j],a[a_dim][j]);
      mpz_init_set(b_tmp[i][j],b[b_dim][j]);
    }
  }

  smc_dot(a_tmp, b_tmp, size, array_size, result, "int", threadID);

  //free the memory
  for(int i = 0; i < size; i++)
  {
    for(int j = 0; j < array_size; j++)
    {
      mpz_clear(a_tmp[i][j]);
      mpz_clear(b_tmp[i][j]);
    }
    free(a_tmp[i]);
    free(b_tmp[i]);
  }
  free(a_tmp);
  free(b_tmp);

}

//first param: two-dim private int
//second param: two-dim private int
//assignment param: two-dim private int

void SMC_Utils::smc_batch(mpz_t** a, mpz_t** b, mpz_t** result, int alen, int blen, int resultlen, int adim, int bdim, int resultdim, mpz_t out_cond, mpz_t* priv_cond, int counter, int* index_array, int size, std::string op, std::string type, int threadID){
  int dim1, dim2;
  mpz_t *a_tmp, *b_tmp, *result_tmp, *result_org;
  if(op == "@"){
    result_tmp = (mpz_t*)malloc(sizeof(mpz_t) * size);
    result_org = (mpz_t*)malloc(sizeof(mpz_t) * size);
    for(int i = 0; i < size; i++){
      mpz_init(result_tmp[i]);
      mpz_init(result_org[i]);
      if(resultdim != 0){
        dim1 = index_array[3*i+2]/resultdim;
        dim2 = index_array[3*i+2]%resultdim;
        mpz_set(result_org[i], result[dim1][dim2]);
      }
    }
    smc_batch_dot(a, b, size, adim, index_array, result_tmp, threadID);
    smc_batch_handle_priv_cond(result_tmp, result_org, out_cond, priv_cond, counter, size, threadID);
  }
  else{
    smc_convert_operator(&a_tmp, a, index_array, adim, size, 1);
    smc_convert_operator(&b_tmp, b, index_array, bdim, size, 2);
    smc_convert_operator(&result_tmp, result, index_array, resultdim, size, 3);
    smc_batch_BOP_int(result_tmp, a_tmp, b_tmp, resultlen, alen, blen, out_cond, priv_cond, counter, size, op, type, threadID);
  }

  if(resultdim != 0){
    for(int i = 0; i < size; ++i){
      dim1 = index_array[3*i+2]/resultdim;
      dim2 = index_array[3*i+2]%resultdim;
      mpz_set(result[dim1][dim2], result_tmp[i]);
    }
  }

  if(op != "@"){
    smc_batch_free_operator(&a_tmp, size);
    smc_batch_free_operator(&b_tmp, size);
    smc_batch_free_operator(&result_tmp, size);
  }else{
    smc_batch_free_operator(&result_org, size);
    smc_batch_free_operator(&result_tmp, size);
  }
}




//INT2INT
void SMC_Utils::smc_batch_int2int(int* a, mpz_t* result, int adim, int resultdim, int alen, int blen, mpz_t out_cond, mpz_t* priv_cond, int counter, int* index_array, int size, int threadID){
  mpz_t* a_tmp = (mpz_t*)malloc(sizeof(mpz_t) * size);
  for(int i = 0; i < size; i++)
    mpz_init_set_si(a_tmp[i], a[i]);
  smc_batch_int2int(a_tmp, result, size, resultdim, 32, blen, out_cond, priv_cond, counter, index_array, size, threadID);
  smc_batch_free_operator(&a_tmp, size);
}

void SMC_Utils::smc_batch_int2int(int* a, mpz_t** result, int adim, int resultdim, int alen, int blen, mpz_t out_cond, mpz_t* priv_cond, int counter, int* index_array, int size, int threadID){
  mpz_t* a_tmp = (mpz_t*)malloc(sizeof(mpz_t) * size);
  for(int i = 0; i < size; i++)
    mpz_init_set_si(a_tmp[i], a[i]);
  smc_batch_int2int(a_tmp, result, size, resultdim, 32, blen, out_cond, priv_cond, counter, index_array, size, threadID);
  smc_batch_free_operator(&a_tmp, size);
}

void SMC_Utils::smc_batch_int2int(mpz_t* a, mpz_t* result, int adim, int resultdim, int alen, int blen, mpz_t out_cond, mpz_t* priv_cond, int counter, int* index_array, int size, int threadID){
  mpz_t* result_tmp = (mpz_t*)malloc(sizeof(mpz_t) * size);
  mpz_t* result_org = (mpz_t*)malloc(sizeof(mpz_t) * size);
  for(int i = 0; i < size; i++){
    mpz_init_set(result_tmp[i], a[index_array[3*i]]);
    mpz_init_set(result_org[i], result[index_array[3*i+2]]);
  }
  smc_batch_handle_priv_cond(result_tmp, result_org, out_cond, priv_cond, counter, size, threadID);
  for(int i = 0; i < size; i++)
    mpz_set(result[index_array[3*i+2]], result_tmp[i]);
  smc_batch_free_operator(&result_tmp, size);
  smc_batch_free_operator(&result_org, size);
}

void SMC_Utils::smc_batch_int2int(mpz_t** a, mpz_t* result, int adim, int resultdim, int alen, int blen, mpz_t out_cond, mpz_t* priv_cond, int counter, int* index_array, int size, int threadID){
  mpz_t* a_tmp;
  smc_convert_operator(&a_tmp, a, index_array, adim, size, 1);
  for(int i = 0; i < size; i++)
    index_array[3*i] = i;
  smc_batch_int2int(a_tmp, result, size, resultdim, alen, blen, out_cond, priv_cond, counter, index_array, size, threadID);
  smc_batch_free_operator(&a_tmp, size);
}

void SMC_Utils::smc_batch_int2int(mpz_t* a, mpz_t** result, int adim, int resultdim, int alen, int blen, mpz_t out_cond, mpz_t* priv_cond, int counter, int* index_array, int size, int threadID){
  mpz_t* result_tmp;
  smc_convert_operator(&result_tmp, result, index_array, resultdim, size, 3);
  int* result_index_array = (int*)malloc(sizeof(int) * size);
  for(int i = 0; i < size; i++){
    result_index_array[i] = index_array[3*i+2];
    index_array[3*i+2] = i;
  }
  smc_batch_int2int(a, result_tmp, adim, size, alen, blen, out_cond, priv_cond, counter, index_array, size, threadID);
  for(int i = 0; i < size; i++){
    int dim1 = result_index_array[i]/resultdim;
    int dim2 = result_index_array[i]%resultdim;
    mpz_set(result[dim1][dim2], result_tmp[i]);
  }
  free(result_index_array);
  smc_batch_free_operator(&result_tmp, size);
}

void SMC_Utils::smc_batch_int2int(mpz_t** a, mpz_t** result, int adim, int resultdim, int alen, int blen, mpz_t out_cond, mpz_t* priv_cond, int counter, int* index_array, int size, int threadID){
  mpz_t *result_tmp, *a_tmp;
  int* result_index_array = (int*)malloc(sizeof(int) * size);
  smc_convert_operator(&a_tmp, a, index_array, adim, size, 1);
  smc_convert_operator(&result_tmp, result, index_array, resultdim, size, 3);

  for(int i = 0; i < size; i++)
  {
    result_index_array[i] = index_array[3*i+2];
    index_array[3*i] = i;
    index_array[3*i+2] = i;
  }

  smc_batch_int2int(a_tmp, result_tmp, size, size, alen, blen, out_cond, priv_cond, counter, index_array, size, threadID);

  for(int i = 0; i < size; i++){
    int dim1 = result_index_array[i]/resultdim;
    int dim2 = result_index_array[i]%resultdim;
    mpz_set(result[dim1][dim2], result_tmp[i]);
  }

  free(result_index_array);
  smc_batch_free_operator(&a_tmp, size);
  smc_batch_free_operator(&result_tmp, size);
}


/* Clienct Connection and Data Passing */
void SMC_Utils::clientConnect(){
  int sockfd, portno;
  socklen_t clilen;
  struct sockaddr_in server_addr, cli_addr;
  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if(sockfd < 0)
    fprintf(stderr, "ERROR, opening socket\n");
  bzero((char*) &server_addr, sizeof(server_addr));
  portno = nodeConfig->getPort()+ 100;
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = INADDR_ANY;
  server_addr.sin_port = htons(portno);
  if(bind(sockfd, (struct sockaddr*) &server_addr, sizeof(server_addr)) < 0)
    fprintf(stderr, "ERROR, on binding\n");
  listen(sockfd, 5);
  clilen = sizeof(cli_addr);
  newsockfd = accept(sockfd, (struct sockaddr*) &cli_addr, &clilen);
  if(newsockfd < 0)
    fprintf(stderr, "ERROR, on accept\n");
  printf("Client connected\n");
}

void SMC_Utils::receivePolynomials(std::string privatekey_filename){
  FILE *prikeyfp = fopen(privatekey_filename.c_str(), "r");
  if( prikeyfp == NULL ) printf("File Open %s error\n", privatekey_filename.c_str());
  RSA *priRkey = PEM_read_RSAPrivateKey(prikeyfp, NULL, NULL, NULL);
  if( priRkey == NULL) printf("Read Private Key for RSA Error\n");
  char *buffer = (char*)malloc(RSA_size(priRkey));
  int n = read(newsockfd, buffer, RSA_size(priRkey));
  if (n < 0) printf("ERROR reading from socket \n");
  char *decrypt = (char*)malloc(n);
  memset(decrypt, 0x00, n);
  int dec_len = RSA_private_decrypt(n, (unsigned char*)buffer, (unsigned char*)decrypt, priRkey, RSA_PKCS1_OAEP_PADDING);
  if(dec_len < 1) printf("RSA private decrypt error\n");
  if(dec_len < 1)
  {
    printf("RSA private decrypt error\n");
  }

  int keysize = 0;
  int coefsize = 0;
  int mpz_t_size = 0;
  memcpy(&keysize, decrypt, sizeof(int));
  memcpy(&coefsize, decrypt+sizeof(int), sizeof(int));
  memcpy(&mpz_t_size, decrypt+sizeof(int)*2, sizeof(int));
  mpz_t* Keys = (mpz_t*)malloc(sizeof(mpz_t) * keysize);
  for(int k = 0; k < keysize; k++)
    mpz_init(Keys[k]);
  int* Coefficients = (int*)malloc(sizeof(int) * coefsize);
  int position = 0;
  for(int i = 0; i < keysize; i++){
    char strkey[mpz_t_size+1] = {0,};
    memcpy(strkey, decrypt+sizeof(int)*3+position, mpz_t_size);
    mpz_set_str(Keys[i], strkey, 10);
    position += mpz_t_size;
  }
  memcpy(Coefficients, decrypt+sizeof(int)*3+mpz_t_size*keysize, sizeof(int)*coefsize);
  free(buffer);
  free(decrypt);

  for(int i = 0; i < keysize; i++){
    char strkey[mpz_t_size+1] = {0,};
    mpz_get_str(strkey, 10, Keys[i]);
    std::string Strkey = strkey;
    std::vector<int> temp;
    for(int k = 0; k < coefsize/keysize; k++){
      temp.push_back(Coefficients[i * coefsize/keysize + k]);
    }
    polynomials.insert(std::pair<std::string, std::vector<int> >(Strkey, temp));
  }
  //printf("Polynomials received... \n");
}

void SMC_Utils::setCoef(){
  mpz_t temp1, temp2, zero;
  mpz_init(temp1);
  mpz_init(temp2);
  mpz_init_set_ui(zero,0);

  for(int i=0; i<9; i++)
    mpz_init(coef[i]);

  mpz_set(coef[8], zero);

  mpz_set_ui(temp1, 40320);
  mpz_set_ui(temp2, 109584);
  ss->modInv(temp1, temp1);
  mpz_set(coef[7], temp1);
  ss->modMul(coef[7], coef[7], temp2);

  mpz_set_ui(temp2, 118124);
  mpz_set(coef[6], temp1);
  ss->modMul(coef[6], coef[6], temp2);
  ss->modSub(coef[6], zero, coef[6]);

  mpz_set_ui(temp2, 67284);
  mpz_set(coef[5], temp1);
  ss->modMul(coef[5], coef[5], temp2);

  mpz_set_ui(temp2, 22449);
  mpz_set(coef[4], temp1);
  ss->modMul(coef[4], coef[4], temp2);
  ss->modSub(coef[4], zero, coef[4]);

  mpz_set_ui(temp2, 4536);
  mpz_set(coef[3], temp1);
  ss->modMul(coef[3], coef[3], temp2);

  mpz_set_ui(temp2, 546);
  mpz_set(coef[2], temp1);
  ss->modMul(coef[2], coef[2], temp2);
  ss->modSub(coef[2], zero, coef[2]);

  mpz_set_ui(temp2, 36);
  mpz_set(coef[1], temp1);
  ss->modMul(coef[1], coef[1], temp2);

  mpz_set(coef[0], temp1);
  ss->modSub(coef[0], zero, coef[0]);

  mpz_clear(zero);
  mpz_clear(temp1);
  mpz_clear(temp2);
}


double SMC_Utils::time_diff(struct timeval *t1, struct timeval *t2){
  double elapsed;

  if(t1->tv_usec > t2->tv_usec){
    t2->tv_usec += 1000000;
    t2->tv_sec--;
  }

  elapsed = (t2->tv_sec-t1->tv_sec) + (t2->tv_usec - t1->tv_usec)/1000000.0;

  return elapsed;
}


double SMC_Utils::time_diff(struct timespec *t1, struct timespec *t2){
  double elapsed;

  if(t1->tv_nsec > t2->tv_nsec){
    t2->tv_nsec += 1000000000;
    t2->tv_sec--;
  }

  elapsed = (t2->tv_sec-t1->tv_sec) + (t2->tv_nsec - t1->tv_nsec)/1000000000.0;

  return elapsed;
}



std::vector<std::string> SMC_Utils::splitfunc(const char* str, const char* delim)
{
  char* saveptr;
  char* token = strtok_r((char*)str, delim, &saveptr);
  std::vector<std::string> result;
  while(token != NULL)
  {
    result.push_back(token);
    token = strtok_r(NULL,delim,&saveptr);
  }
  return result;
}
