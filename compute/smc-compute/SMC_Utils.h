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

#ifndef SMC_UTILS_H_
#define SMC_UTILS_H_

#include "Headers.h"
#include "NodeConfiguration.h"
#include "NodeNetwork.h"
#include "MaliciousSMC.h"
#include "ops/Operation.h"
#include <string>
#include <iostream>
#include <fstream>
#include <sstream>
#include <math.h>
#include "Debug.h"

#define SEMIHONEST 0
#define MALICIOUS 1


class SMC_Utils {
public:
  //Constructors
  SMC_Utils(int id, std::string runtime_config, std::string privatekey_filename, int numOfInputPeers, int numOfOutputPeers, std::string* IO_files, int numOfPeers, int threshold, int bits, std::string mod, int num_threads, int threat_model);
  //Share a secret between
  virtual ~SMC_Utils();

  int smc_open(mpz_t var, int threadID);
  void smc_open(mpz_t *inputs, int* outputs, int batch_size, int threadID);
  float smc_open(mpz_t* var, int threadID);


  // Boolean Circuit
  void smc_bitadd(mpz_t** a, mpz_t** b, mpz_t** s, int size, int batch_size, int threadID);
  void smc_bittwoscomp(mpz_t** a, mpz_t** s, int size, int batch_size, int threadID);
  void smc_bitmul(mpz_t** a, mpz_t** b, mpz_t** s, int in_size, int batch_size, int out_size, int threadID);
  void smc_bitsum(mpz_t** a, mpz_t* s, int in_size, int num_elements, int out_size, int threadID);
  void smc_bitlt(mpz_t* a, mpz_t* b, mpz_t s, int size, int threadID);
  void smc_bitlt(mpz_t** a, mpz_t** b, mpz_t* s, int size, int batch_size, int threadID);
  void smc_biteq(mpz_t** a, mpz_t** b, mpz_t* s, int size, int batch_size, int threadID);


  //Malicious functions
  void smc_init_mal();
  void smc_clean_mal();
  void smc_input_mal(int id, mpz_t* var, int size, int varlen, std::string type, int threadID);
  void smc_input_mal(mpz_t* a, mpz_t *b, std::string type, int threadID);
  void smc_input_mal(mpz_t** a, int size, std::string type, int threadID);
  void smc_input_mal(mpz_t** a, mpz_t **b, int size, std::string type, int threadID);
  void smc_input_mal(mpz_t*** a, mpz_t ***b, int batch_size, int size, std::string type, int threadID);


  void smc_mult_mal(mpz_t** a, mpz_t** b, int alen, int blen, mpz_t** result, int resultlen, int size, std::string type, int threadID);
  void smc_add_mal(mpz_t** a, mpz_t** b, int alen, int blen, mpz_t** result, int resultlen, int size, std::string type, int threadID);
  void smc_add_mal(int a, mpz_t* b, mpz_t* result, int alen, int blen, int resultlen, std::string type, int threadID);
  void smc_sub_mal(mpz_t** a, mpz_t** b, int alen, int blen, mpz_t** result, int resultlen, int size, std::string type, int threadID);
  void smc_sub_mal(int a, mpz_t* b,  mpz_t* result, int alen, int blen, int resultlen, std::string type, int threadID);
  void smc_eqeq_mal(mpz_t** a, mpz_t** b, int alen, int blen, mpz_t** result, int resultlen, int size, std::string type, int threadID);
  void smc_eqeq_mal(mpz_t* a, mpz_t* b, mpz_t* result, int alen, int blen, int resultlen, std::string type, int threadID);
  void smc_lt_mal(mpz_t** a, mpz_t** b, int alen, int blen, mpz_t** result, int resultlen, int size, std::string type, int threadID);
  void smc_lt_mal(mpz_t* a, mpz_t* b, mpz_t* result, int alen, int blen, int resultlen, std::string type, int threadID);
  void smc_priv_eval_mal(mpz_t* a, mpz_t* b, mpz_t* cond, int threadID);
  void smc_dot_mal(mpz_t** a, mpz_t** b, int in_size, mpz_t* result, int threadID);

  void smc_bitadd_mal(mpz_t*** a, mpz_t*** b, mpz_t*** s, int size, int batch_size, int threadID);
  void smc_bittwoscomp_mal(mpz_t*** a, mpz_t*** s, int size, int batch_size, int threadID);
  void smc_bitmul_mal(mpz_t*** a, mpz_t*** b, mpz_t*** s, int in_size, int batch_size, int out_size, int threadID);
  void smc_bitsum_mal(mpz_t*** a, mpz_t** s, int in_size, int num_elements, int out_size, int threadID);
  void smc_bitlt_mal(mpz_t** a, mpz_t** b, mpz_t* s, int size, int threadID);
  void smc_bitlt_mal(mpz_t*** a, mpz_t*** b, mpz_t** s, int size, int batch_size, int threadID);
  void smc_biteq_mal(mpz_t*** a, mpz_t*** b, mpz_t** s, int size, int batch_size, int threadID);

  void smc_getr_mal(mpz_t a);
  void smc_verify();


  //Methods for input and output
  //for integer variable;
  void smc_input(int id, int* var, std::string type, int threadID);
  void smc_input(int id, mpz_t* var, std::string type, int  threadID);
  void smc_output(int id, int* var, std::string type, int threadID);
  void smc_output(int id, mpz_t* var, std::string type, int thread);



  //for one dimensional integer;
  void smc_input(int id, int* var, int size, std::string type, int threadID);
  void smc_input(int id, mpz_t* var, int size, std::string type, int threadID);
  void smc_output(int id, int* var, int size, std::string type, int threadID);
  void smc_output(int id, mpz_t* var, int size, std::string type, int threadID);


  /************************************ Addition *****************************************/
  /********* singular operations *******/
  //1) private int + private int
  void smc_add(mpz_t a, mpz_t b, mpz_t result, int alen, int blen, int clen, std::string type, int threadID);
  //3) private int + public int
  void smc_add(mpz_t a, int b, mpz_t result, int alen, int blen, int resultlen, std::string type, int threadID);
  //4) public int + private int
  void smc_add(int a, mpz_t b, mpz_t result, int alen, int blen, int resultlen, std::string type, int threadID);
  /************ batch operations *********/
  void smc_add(int* a, mpz_t* b, int alen, int blen, mpz_t* result, int resultlen, int size, std::string type, int threadID);
  void smc_add(mpz_t* a, int* b, int alen, int blen, mpz_t* result, int resultlen, int size, std::string type, int threadID);
  void smc_add(mpz_t* a, mpz_t* b, int alen, int blen, mpz_t* result, int resultlen, int size, std::string type, int threadID);
  void smc_add(mpz_t** a, mpz_t** b, int alen_sig, int alen_exp, int blen_sig, int blen_exp, mpz_t** result, int  resultlen_sig, int resultlen_exp, int size, std::string type, int threadID);

  void smc_sum(mpz_t* a, mpz_t result, int size);

  /************************************* Subtraction *************************************/
  /********** singular operations ***********/
  //1) private int - private int
  void smc_sub(mpz_t a, mpz_t b, mpz_t result, int alen, int blen, int resultlen, std::string type, int threadID);
  //3) private int - public int
  void smc_sub(mpz_t a, int b, mpz_t result, int alen, int blen, int resultlen, std::string type, int threadID);
  //4) public int - private int
  void smc_sub(int a, mpz_t b, mpz_t result, int alen, int blen, int resultlen, std::string type, int threadID);
  /************ batch operations *********/
  void smc_sub(int* a, mpz_t* b, int alen, int blen, mpz_t* result, int resultlen, int size, std::string type, int threadID);
  void smc_sub(mpz_t* a, int* b, int alen, int blen, mpz_t* result, int resultlen, int size, std::string type, int threadID);
  void smc_sub(mpz_t* a, mpz_t* b, int alen, int blen, mpz_t* result, int resultlen, int size, std::string type, int threadID);
  /************************************** Multiplication ***************************************/
  /************* singular operations *****************/
  //1) private int * private int
  void smc_mult(mpz_t a, mpz_t b, mpz_t result, int alen, int blen, int resultlen, std::string type, int threadID);
  //2) private int * public int
  void smc_mult(mpz_t a, int b, mpz_t result, int alen, int blen, int resultlen, std::string type, int threadID);
  //3) public int * private int
  void smc_mult(int a, mpz_t b, mpz_t result, int alen, int blen, int resultlen, std::string type, int threadID);
  /************ batch operations *********/
  void smc_mult(mpz_t* a, int* b, int alen, int blen, mpz_t* result, int resultlen, int size, std::string type, int threadID);
  void smc_mult(int* a, mpz_t* b, int alen, int blen, mpz_t* result, int resultlen, int size, std::string type, int threadID);
  void smc_mult(mpz_t* a, mpz_t* b, int alen, int blen, mpz_t* result, int resultlen, int size, std::string type, int threadID);
  /*****************************************  Division ******************************************/
  /******************* singular operations *****************/
  //1) private int / private int
  void smc_div(mpz_t a, mpz_t b, mpz_t result, int alen, int blen, int resultlen, std::string type, int threadID);
  //2) private int / public int
  void smc_div(mpz_t a, int b, mpz_t result, int alen, int blen, int resultlen, std::string type, int threadID);
  //3) public int / private int
  void smc_div(int a, mpz_t b, mpz_t result, int alen, int blen, int resultlen, std::string type, int threadID);

  /************ batch operations *********/
  void smc_div(mpz_t* a, mpz_t* b, int alen, int blen, mpz_t* result, int resultlen, int size, std::string type, int threadID);
  void smc_div(mpz_t* a, int* b, int alen, int blen, mpz_t* result, int resultlen, int size, std::string type, int threadID);
  void smc_div(int* a, mpz_t* b, int alen, int blen, mpz_t* result, int resultlen, int size, std::string type, int threadID);


  //1) private int < private int
  void smc_lt(mpz_t a, mpz_t b, mpz_t result, int alen, int blen, int resultlen, std::string type, int threadID);
  //2) private int < public int
  void smc_lt(mpz_t a, int b, mpz_t result, int alen, int blen, int resultlen, std::string type, int threadID);
  //3) public int < private int
  void smc_lt(int a, mpz_t b, mpz_t result, int alen, int blen, int resultlen, std::string type, int threadID);

  /************ batch operations *********/
  void smc_lt(mpz_t* a, mpz_t* b, int alen, int blen, mpz_t* result, int resultlen, int size, std::string type, int threadID);
  //void smc_lt(mpz_t** a, mpz_t** b, int alen_sig, int alen_exp, int blen_sig, int blen_exp, mpz_t* result, int resultlen, int size, std::string type, int threadID);

  /************************* singular operations ************************/
  //1) private int > private int
  void smc_gt(mpz_t a, mpz_t b, mpz_t result, int alen, int blen, int resultlen, std::string type, int threadID);
  //2) private int > public int
  void smc_gt(mpz_t a, int b, mpz_t result, int alen, int blen, int resultlen, std::string type, int threadID);
  //3) public int > private int
  void smc_gt(int a, mpz_t b, mpz_t result, int alen, int blen, int resultlen, std::string type, int threadID);

  /************ batch operations *********/
  void smc_gt(mpz_t* a, mpz_t* b, int alen, int blen, mpz_t* result, int resultlen, int size, std::string type, int threadID);
  //void smc_gt(mpz_t** a, mpz_t** b, int alen_sig, int alen_exp, int blen_sig, int blen_exp, mpz_t* result, int resultlen, int size, std::string type, int threadID);
  /************************* singular operations ***********************/
  //1) private int <= private int
  void smc_leq(mpz_t a, mpz_t b, mpz_t result, int alen, int blen, int resultlen, std::string type, int threadID);
  //2) private int <= public int
  void smc_leq(mpz_t a, int b, mpz_t result, int alen, int blen, int resultlen, std::string type, int threadID);
  //3) public int <= private int
  void smc_leq(int a, mpz_t b, mpz_t result, int alen, int blen, int resultlen, std::string type, int threadID);

  /************ batch operations *********/
  void smc_leq(mpz_t* a, mpz_t* b, int alen, int blen, mpz_t* result, int resultlen, int size, std::string type, int threadID);
  void smc_leq(mpz_t* a, int int_b, int alen, int blen, mpz_t* result, int resultlen, int size, std::string type, int threadID);

  /************************* singular operations **********************/
  //1) private int >= private int
  void smc_geq(mpz_t a, mpz_t b, mpz_t result, int alen, int blen, int resultlen, std::string type, int threadID);
  //2) private int >= public int
  void smc_geq(mpz_t a, int b, mpz_t result, int alen, int blen, int resultlen, std::string type, int threadID);
  //3) public int >= private int
  void smc_geq(int a, mpz_t b, mpz_t result, int alen, int blen, int resultlen, std::string type, int threadID);

  /************ batch operations *********/
  void smc_geq(mpz_t* a, mpz_t* b, int alen, int blen, mpz_t* result, int resultlen, int size, std::string type, int threadID);
  //void smc_geq(mpz_t** a, mpz_t** b, int alen_sig, int alen_exp, int blen_sig, int blen_exp, mpz_t* result, int resultlen, int size, std::string type, int threadID);

  /*********************** singular operations *************************/
  //1) private int == private int
  void smc_eqeq(mpz_t a, mpz_t b, mpz_t result, int alen, int blen, int resultlen, std::string type, int threadID);
  //2) private int == public int
  void smc_eqeq(mpz_t a, int b, mpz_t result, int alen, int blen, int resultlen, std::string type, int threadID);
  //3) public int == private int
  void smc_eqeq(int a, mpz_t b, mpz_t result, int alen, int blen, int resultlen, std::string type, int threadID);

  /************ batch operations *********/
  void smc_eqeq(mpz_t* a, mpz_t* b, int alen, int blen, mpz_t* result, int resultlen, int size, std::string type, int threadID);
  //void smc_eqeq(mpz_t** a, mpz_t** b, int alen_sig, int alen_exp, int blen_sig, int blen_exp, mpz_t* result, int resultlen, int size, std::string type, int threadID);

  /************************* singular operations **************************/
  //1) private int != private int
  void smc_neq(mpz_t a, mpz_t b, mpz_t result, int alen, int blen, int resultlen, std::string type, int threadID);
  //2) private int != public int
  void smc_neq(mpz_t a, int b, mpz_t result, int alen, int blen, int resultlen, std::string type, int threadID);
  //3) public int != private int
  void smc_neq(int a, mpz_t b, mpz_t result, int alen, int blen, int resultlen, std::string type, int threadID);

  /************ batch operations *********/
  void smc_neq(mpz_t* a, mpz_t* b, int alen, int blen, mpz_t* result, int resultlen, int size, std::string type, int threadID);
  //void smc_neq(mpz_t** a, mpz_t** b, int alen_sig, int alen_exp, int blen_sig, int blen_exp, mpz_t* result, int resultlen, int size, std::string type, int threadID);

  //Logical operators
  void smc_land(mpz_t a, mpz_t b, mpz_t result, int alen, int blen, int resultlen, std::string type, int threadID);
  void smc_land(mpz_t* a, mpz_t* b, int size, mpz_t* result, std::string type, int threadID);
  void smc_xor(mpz_t a, mpz_t b, mpz_t result, int alen, int blen, int resultlen, std::string type, int threadID);
  void smc_xor(mpz_t* a, mpz_t* b, int size, mpz_t* result, std::string type, int threadID);
  void smc_lor(mpz_t a, mpz_t b, mpz_t result, int alen, int blen, int resultlen, std::string type, int threadID);
  void smc_lor(mpz_t* a, mpz_t* b, int size, mpz_t* result, std::string type, int threadID);

  //Shift operators
  void smc_shl(mpz_t a, mpz_t b, mpz_t result, int alen, int blen, int resultlen, std::string type, int threadID);
  void smc_shl(mpz_t a, int b, mpz_t result, int alen, int blen, int resultlen, std::string type, int threadID);
  void smc_shr(mpz_t a, mpz_t b, mpz_t result, int alen, int blen, int resultlen, std::string type, int threadID);
  void smc_shr(mpz_t a, int b, mpz_t result, int alen, int blen, int resultlen, std::string type, int threadID);


  void smc_shl(mpz_t* a, mpz_t* b, int alen, int blen, mpz_t* result, int resultlen, int size, std::string type, int threadID);
  void smc_shl(mpz_t* a, int* b, int alen, int blen, mpz_t* result, int resultlen, int size, std::string type, int threadID);
  void smc_shr(mpz_t* a, mpz_t* b, int alen, int blen, mpz_t* result, int resultlen, int size, std::string type, int threadID);
  void smc_shr(mpz_t* a, int* b, int alen, int blen, mpz_t* result, int resultlen, int size, std::string type, int threadID);

  //for integer set
  void smc_set(mpz_t a, mpz_t result, int alen, int resultlen, std::string type, int threadID);
  void smc_set(mpz_t* a, mpz_t* result, int alen, int resultlen, int size, std::string type, int threadID);
  void smc_set(int a, mpz_t result, int alen, int resultlen, std::string type, int threadID);
  //Dot Product
  void smc_dot(mpz_t* a, mpz_t* b, int size, mpz_t result, int threadID);
  void smc_dot(mpz_t** a, mpz_t**b, int batch_size, int array_size, mpz_t* result, std::string type, int threadID);
  void smc_batch_dot(mpz_t** a, mpz_t** b, int batch_size, int array_size, int *index_array, mpz_t* result, int threadID);

  void smc_priv_eval(mpz_t a, mpz_t b, mpz_t cond, int threadID);
  void smc_priv_eval(mpz_t* a, mpz_t* b, mpz_t cond, int threadID);


  //Batch Operation Support
  void smc_convert_operator(mpz_t** result, mpz_t** op, int* index_array, int dim, int size, int flag);
  void smc_convert_operator(mpz_t** result, mpz_t* op, int* index_array, int dim, int size, int flag);
  void smc_convert_operator(mpz_t*** result, mpz_t** op, int* index_array, int dim, int size, int flag);
  void smc_convert_operator(mpz_t*** result, mpz_t*** op, int* index_array, int dim, int size, int flag);


  void smc_batch_free_operator(mpz_t** op, int size);
  void smc_batch_free_operator(mpz_t*** op, int size);

  //int
  void smc_batch(mpz_t* a, mpz_t* b, mpz_t* result, int alen, int blen, int resultlen, int adim, int bdim, int resultdim, mpz_t out_cond, mpz_t* priv_cond, int counter, int* index_array, int size, std::string op, std::string type, int threadID);
  void smc_batch(mpz_t** a, mpz_t** b, mpz_t** result, int alen, int blen, int resultlen, int adim, int bdim, int resultdim, mpz_t out_cond, mpz_t* priv_cond, int counter, int* index_array, int size, std::string op, std::string type, int threadID);
  void smc_batch(mpz_t* a, mpz_t** b, mpz_t** result, int alen, int blen, int resultlen, int adim, int bdim, int resultdim, mpz_t out_cond, mpz_t* priv_cond, int counter, int* index_array, int size, std::string op, std::string type, int threadID);
  void smc_batch(mpz_t** a, mpz_t* b, mpz_t** result, int alen, int blen, int resultlen, int adim, int bdim, int resultdim, mpz_t out_cond, mpz_t* priv_cond, int counter, int* index_array, int size, std::string op, std::string type, int threadID);
  void smc_batch(mpz_t** a, mpz_t** b, mpz_t* result, int alen, int blen, int resultlen, int adim, int bdim, int resultdim, mpz_t out_cond, mpz_t* priv_cond, int counter, int* index_array, int size, std::string op, std::string type, int threadID);
  void smc_batch(mpz_t* a, mpz_t* b, mpz_t** result, int alen, int blen, int resultlen, int adim, int bdim, int resultdim, mpz_t out_cond, mpz_t* priv_cond, int counter, int* index_array, int size, std::string op, std::string type, int threadID);
  void smc_batch(mpz_t** a, mpz_t* b, mpz_t* result, int alen, int blen, int resultlen, int adim, int bdim, int resultdim, mpz_t out_cond, mpz_t* priv_cond, int counter, int* index_array, int size, std::string op, std::string type, int threadID);
  void smc_batch(mpz_t* a, mpz_t** b, mpz_t* result, int alen, int blen, int resultlen, int adim, int bdim, int resultdim, mpz_t out_cond, mpz_t* priv_cond, int counter, int* index_array, int size, std::string op, std::string type, int threadID);



  //operations between public and private values;
  //public + private one-dimension int
  void smc_batch(int* a, int* b, mpz_t* result, int alen, int blen, int resultlen, int adim, int bdim, int resultdim, mpz_t out_cond, mpz_t* priv_cond, int counter, int* index_array, int size, std::string op, std::string type, int threadID);
  void smc_batch(int* a, int* b, mpz_t** result, int alen, int blen, int resultlen, int adim, int bdim, int resultdim, mpz_t out_cond, mpz_t* priv_cond, int counter, int* index_array, int size, std::string op, std::string type, int threadID);

  void smc_batch(int* a, mpz_t* b, mpz_t* result, int alen, int blen, int resultlen, int adim, int bdim, int resultdim, mpz_t out_cond, mpz_t* priv_cond, int counter, int* index_array, int size, std::string op, std::string type, int threadID);
  void smc_batch(mpz_t* a, int* b, mpz_t* result, int alen, int blen, int resultlen, int adim, int bdim, int resultdim, mpz_t out_cond, mpz_t* priv_cond, int counter, int* index_array, int size, std::string op, std::string type, int threadID);

  void smc_batch(mpz_t* a, int* b, mpz_t** result, int alen, int blen, int resultlen, int adim, int bdim, int resultdim, mpz_t out_cond, mpz_t* priv_cond, int counter, int* index_array, int size, std::string op, std::string type, int threadID);
  void smc_batch(int* a, mpz_t* b, mpz_t** result, int alen, int blen, int resultlen, int adim, int bdim, int resultdim, mpz_t out_cond, mpz_t* priv_cond, int counter, int* index_array, int size, std::string op, std::string type, int threadID);

  void smc_batch(int* a, mpz_t** b, mpz_t* result, int alen, int blen, int resultlen, int adim, int bdim, int resultdim, mpz_t out_cond, mpz_t* priv_cond, int counter, int* index_array, int size, std::string op, std::string type, int threadID);
  void smc_batch(mpz_t** a, int* b, mpz_t* result, int alen, int blen, int resultlen, int adim, int bdim, int resultdim, mpz_t out_cond, mpz_t* priv_cond, int counter, int* index_array, int size, std::string op, std::string type, int threadID);

  void smc_batch(int* a, mpz_t** b, mpz_t** result, int alen, int blen, int resultlen, int adim, int bdim, int resultdim, mpz_t out_cond, mpz_t* priv_cond, int counter, int* index_array, int size, std::string op, std::string type, int threadID);
  void smc_batch(mpz_t** a, int* b, mpz_t** result, int alen, int blen, int resultlen, int adim, int bdim, int resultdim, mpz_t out_cond, mpz_t* priv_cond, int counter, int* index_array, int size, std::string op, std::string type, int threadID);

  void smc_batch(int a, mpz_t* b, mpz_t* result, mpz_t out_cond, mpz_t* priv_cond, int counter, int* index_array, int size, std::string op, int threadID);
  void smc_batch(mpz_t* a, mpz_t* b, mpz_t* result, mpz_t out_cond, mpz_t* priv_cond, int counter, int* index_array, int size, std::string op, int threadID);



  void smc_batch_handle_priv_cond(mpz_t* result, mpz_t* result_org, mpz_t out_cond, mpz_t *priv_cond, int counter, int size, int threadID);
  void smc_batch_BOP_int(mpz_t* result, mpz_t* a, mpz_t* b, int resultlen, int alen, int blen, mpz_t out_cond, mpz_t* priv_cond, int counter, int size, std::string op, std::string type, int threadID);


  void smc_batch_int2int(int* a, mpz_t* result, int adim, int resultdim, int alen, int blen, mpz_t out_cond, mpz_t* priv_cond, int counter, int* index_array, int size, int threadID);
  void smc_batch_int2int(int* a, mpz_t** result, int adim, int resultdim, int alen, int blen, mpz_t out_cond, mpz_t* priv_cond, int counter, int* index_array, int size, int threadID);
  void smc_batch_int2int(mpz_t* a, mpz_t* result, int adim, int resultdim, int alen, int blen, mpz_t out_cond, mpz_t* priv_cond, int counter, int* index_array, int size, int threadID);
  void smc_batch_int2int(mpz_t** a, mpz_t* result, int adim, int resultdim, int alen, int blen, mpz_t out_cond, mpz_t* priv_cond, int counter, int* index_array, int size, int threadID);
  void smc_batch_int2int(mpz_t* a, mpz_t** result, int adim, int resultdim, int alen, int blen, mpz_t out_cond, mpz_t* priv_cond, int counter, int* index_array, int size, int threadID);
  void smc_batch_int2int(mpz_t** a, mpz_t** result, int adim, int resultdim, int alen, int blen, mpz_t out_cond, mpz_t* priv_cond, int counter, int* index_array, int size, int threadID);


  void smc_compute_len(int alen, int blen, int* len);

  std::map<std::string, std::vector<int> > polynomials; //temporarily public
  mpz_t coef[9]; //temporarily public
  int id; //temporarily public;

  void smc_reset_counters();
  void smc_get_communication_summary(std::string test_description, bool writing_to_file);
  double time_diff(struct timeval *, struct timeval *);
  double time_diff(struct timespec *, struct timespec *);

  std::vector<std::string> splitfunc(const char* str, const char* delim);

  void smc_randbit(mpz_t*, int);
private:
  SecretShare *ss;
  MaliciousSMC *MSmc;
  FILE* inputFile;
  NodeConfiguration* nodeConfig;
  NodeNetwork nNet;
  std::ifstream* inputStreams;
  std::ofstream* outputStreams;
  int base;

  LTZ *Lt;
  Random *PRand;
  Mult *Mul;
  EQZ *Eq;
  DotProduct *DProd;
  BitOps *BOps;
  Trunc *T;
  TruncS *Ts;

  IntDiv *Idiv;
  Pow2* P;
  BitAdd* BitA;
  BitLT* BitL;
  BitEq* BitE;
  BitMul* BitM;
  BitSum* BitS;

  //Handle client connections and polynomail stuff
  void clientConnect();
  void receivePolynomials(std::string privatekey_filename);
  void setCoef();
  int peers;
  int newsockfd;
  int threat_mod;
};

#endif /* SMC_UTILS_H_ */
