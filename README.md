This repository corresponds to the implementation in the article "**Efficiently Compiling Secure Computation Protocols From Passive to Active Security: Beyond Arithmetic Circuits**" published in the Proceedings on Privacy Enhancing Technologies (PoPETs), Vol. 2024.

The code is a fork of PICCO, The complete motivation, design, and analysis of PICCO can be found in the [2013 CCS paper](https://doi.org/10.1145/2508859.2516752), and the main PICCO repository can be found at https://github.com/applied-crypto-lab/picco.

## Description
The above referenced work studies compilation of honest-majority semi-honest secure multi-party protocols secure up to additive attacks to maliciously secure computation with abort. Prior work concentrated on arithmetic circuits composed of addition and multiplication gates, while many practical protocols rely on additional types of elementary operations or gates to achieve good performance. In this work we revisit the notion of security up to additive attacks in the presence of additional gates such as random element generation and opening. This requires re-evaluation of functions that can be securely evaluated, extending the notion of protocols secure up to additive attacks, and re-visiting the notion of delayed verification that points to weaknesses in its prior use and designing a mitigation strategy. We transform the computation using dual execution to achieve security in the malicious model with abort and experimentally evaluate the difference in performance of semi-honest and malicious protocols to demonstrate the low cost.

Our experiments simulate three mutually distrusting parties engaging in distributed computation over a network. Our framework compiles computation with certain properties in protocols secure against semihonest adversaries (those seeking to learn protected information but not deviate from the protocol), into ones which are secure against malicious adversaries (those who may deviate from the protocol as well as learn unauthorized information). The latter case is well known to come at increased performance costs. These protocols are intended to be run over arithmetic circuits in a finite field of sufficient modulus size, and the increased security comes at only modest cost over the original semihonest protocols. Additionally, we introduce capapbilities beyond usual arithmetic circuit computation by allowing for values to be revealed mid-computation so long as they meet certain requirements and are verified against tampering on cetain prescribed occasions. The experiments highlight these claims and should replicate numbers provided in Section 6 of our paper. Instructions on running these experiments are provided below for anyone looking to reproduce these experiments.

The codebase in this repository realizes this functionality by providing efficient implementations of this functionality within the PICCO context. This Malicious-secure functionality is realized with Shamir secret sharing over a finite field. Code is also provided for computation over bit-decomposed values, for use in comparing results against our purely arithmetic circuit versions.

## Usage
The functionality provided for this purpose can also be used to familiarize oneself with the system and\\or run further tests. The framework is general enough for use in any arithmetic circuit setting where malicious-secure protocols are desired, and users may write their own custom programs using this library, and can test this either on their own machines directly, or the Docker container we provide.

### Set up the environment (Local Build)
The following assumes a UNIX-like environment with a BASH shell, and if applicable (for results collecting in reproducibility experiments) an up to date Python interpreter installed (version 3.6+). Most modern Linux distributions should provide\\support this, and this has been verified to work on current Ubuntu and openSUSE Leap installations. Moreover, the underlying functionality is general enough so that this should be easily ported to other operating systems.

Our source code is hosted in a GitHub repository, with instructions described below. The following software is required (all available free of charge):

  - GNU gcc g++ compiler
  - GMP (The GNU Multiple Precision Arithmetic Library)
  - openSSL library v1.1
  - GNU Bison parser
  - flex - fast lexical analyzer generator
  - make

You can download the repository using HTTPS, SSH, or GitHub CLI. The respective commands (any one of which will suffice) are:

```bash
git clone https://github.com/applied-crypto-lab/mal-ext-circuits.git
git clone git@github.com:applied-crypto-lab/mal-ext-circuits.git
gh repo clone applied-crypto-lab/mal-ext-circuits
```

Once the libraries are installed and the repository is downloaded, navigate to the ```mal-ext-circuits``` directory of the local repository and run

```./build.sh```.


## Running the Experiments

In order for anyone wishing to reproduce the experimental values listed in our paper, or simply test the software in a containerized setting, we provide a Docker implementation and describe how to obtain use it here.

### Set up the environment (Docker container)
Clone the `mal-ext-circuits` repository as described above. Once this is done, open a terminal in the ```mal-ext-circuits/compute``` directory and run

```bash
docker build -t mal-ext-circuits-image .
```

### Experiments

- We compare performance of batches of addition, multiplication, less-than comparison, equality comparsion, and over-the-threshold Euclidean distance.
- We run tests for arithmetic and bitwise circuits. The latter serves to compare against arithmetic circuit computation as it is a primary alternative which for most computation, especially basic arithmetic operations such as addition and multiplication, comes at a significant performance cost.
  - We run input sizes in powers of ten for i=0..3 in bitwise computation, and i=0..5 in arithmetic.
  - The input size represents a vector of inputs for which a given operation is computed that many times in parallel
    - The one exception is Euclidean distance, for which the input size represents the size of each of two input vectors which produce a single boolean output decision.
  - The only situation where bitwise circuits outperform our arithmetic ones are generally in comparisons, but such performance loss is quite modest (roughly three times the cost in the malicious case)
  - Thus for circuits for which malicious security is desired and which are not completely dominated by comparisons, our framework is a very attractive
    - In particular, the Euclidean distance protocol is many times faster in our framework.
- For both of the above cases, we compare semihonest computation performance with malicious and observe that our malicious secure protocols are a reasonable 2-6 times slower while providing much stronger security guarantees.
- For reference, we also provide communication totals for each protocol as well as AND gate depth for the bitwise protocols.
- We also provide the cost of verification against malicious tampering as a pecentage of the total protocol time, and observe favorable performance from an asymptotic standpoint.


#### To run the relevant tests, do the following:

  - Open four terminals on your host machine, one for each `<party number>` in {0..3} (also referred to as 'peer id' within the codebase). Then in each terminal navigate to the `mal-ext-circuits/compute` directory in the cloned repository and run  `./launch-artifact-docker.sh <config file suffix> <party number> <net device name>`
    - It is best to be in the habit of starting all scripts taking `<party number>` as argument in the order 3, 2, 1, 0, (as decribed below for `run-comp.sh`), but the only actual restriction on `launch-artifact-docker.sh` is that party 0 must be initiated after party 1 (in general, as currently configured, both of these must be on the same machine, virtual or otherwise).
    - It is expected that a file named `runtime-conif-<config file suffix>` exists in the host working directory (`runtime-config-local` is provided; details are given below).
    - `<net device name>` is an optional parameter. The `LAN.sh` script assumes as default that the primary network device is `eth0`. If this is not the case on your test machine, then provide the correct device name as `<net device name>`.
  - This will start the Docker instance and enter you into a bash shell within it, also in the `mal-ext-circuits/compute` directory of the cloned (and pre-built) repository, with the specified config file copied into the container if a custom file is specified.
  - Once in the running container in directory `mal-ext-circuits/compute`, the program ```run-comp.sh``` runs all three computational parties, as well as the required seed generation program (as party 0).
  - The command structure is
    - ```./run-comp.sh <circuit type> <threat model> <alg> <config file suffix> <party number> <debug flag>```
      - circuit type is in {arith, bit}
      - threat model is in {sh, mal}
      - alg is in {add, mul, lt, equ, ed, all}
      - config file suffix is explained below, (same as in `./launch-artifact-docker.sh`, and should match)
      - party number is in {0..3}, (same as in `./launch-artifact-docker.sh`, and should match)
      - debug flag is in {debug, single}


#### Some important notes about these commands:

- The programs must be run in descending order of party number, with the seed program last (i.e. 3, 2, 1, 0).
- The ```run-comp.sh``` shell script performs basic error checking. However one should take care to run the exact same parameterization for each party or the programs may hang, crash, or produce garbage output.
- The name of the config file must be of the form "runtime-config-X" where X can be any name you would like to give any custom file you create.
  - We have provided a file named runtime-config-local (and so you would type 'local' on the command line for this argument).
  - This file is set up to allow testing of all computational parties on the same machine.
  - In order to use this program in a true distributed network environment, one would need to enter the IP addresses, ports, and key files where your machines can accept TCP communication, into a copy of this file and rename it with a different suffix.
- If the debug flag is set as "debug", then the program runs input size 1, 10, and 100 at one iteration each.
  - In this case, communication information and AND gate counts (only relevant for bitwise circuits) are provided.
- If the debug flag is set to "single", then the program runs all input sizes at one iteration, reporting timing information.
- If no debug flag is set, then all tests are run at default iteration counts in duplicate with timing information provided (as was the case when running the main timing experiments for the paper).
- When you are done testing, you will need to issue the `exit` command to leave the container shell.



#### Some example commands:

- ```./run-comp.sh arith sh add local 3```
  - Starts the program for party 3 (which should be run first for all test runs), for semihonest arithmetic addition at default settings on the local machine
- ```./run-comp.sh arith mal all custom 2```
  - Starts the program for party 2 (which should be run second for all test runs), for all malicious arithmetic experiments (i.e. add, mul, lt, equ, and ed) at default settings for the custom network configuration you have provided in a file called "runtime-config-custom"
- ```./run-comp.sh bit mal equ local 1 debug```
  - Starts the program for party 1 (which should be run third for all test runs), for malicious bitwise equality testing in debug mode on the local machine
- ```./run-comp.sh bit sh ed local 0 single```
  - Starts the program for party 0 (the seed generation program, which should be run last for all test runs), for semihonest bitwise Euclidean distance evaluation in single mode on the local machine


#### Collecting experimental data:
- Within each running container instance, for each individual test parameterization, all test output information is averaged over all iterations (locally for each individual party), and is provided both to console as well as output to csv files named `time_test_results_<party number>.csv`, in append mode, within the container in `/mal-ext-circuits/compute`.
- Once all containers have been exited, `launch-artifact-docker.sh` will create a directory in the host, named `mal-ext-circuits/compute/results`, and copy the csv files there.
- Next, `launch-artifact-docker.sh` will invoke the Python program `mal-ext-circuits/compute/extract_time_results.py` in the host (hence why a working Python 3 installation is indicated). This program will compute the averages of all test runs in the csv files in the results directory (those pulled from the container, results averaged this time across the three computational parties).
  - These averages will be stored in `results/compiled_time_test_results.csv`, and it is these values which should be compared with our paper's results.
  - For semi-honest test runs, the single rightmost column of values gives the average time per run
  - For malicious test runs, the three rightmost column of values give, in order from left to right, the average time per run, the average verification time per run, and the average percentage of time spent in verification.
- The communication and AND gate values can be obtained by running a battery of tests in `debug` mode. These results will subsequently be stored in `comm_test_results_<party number>.csv` and `mult_test_results_<party number>.csv` respectively, and will also be exported from the container into the `mal-ext-circuits/compute/results` directory on the host.
  - These tests do not take timing data, so timing and communication\\AND gate data can be obtained during one container invocation by running two batches of tests sequentially on the same parameterization; one with and one without the `debug` flag.
  - The communication values and AND gate counts do not vary across runs, so no averages are taken of these values.
- Note that to obtain all data in the paper, at least four container runs will be needed.
  - One for arithmetic semi-honest tests.
  - One for arithmetic malicious tests.
  - One for bitwise semi-honest tests.
  - One for bitwise malicious tests.
  - Given the above, if you wish to save the ouput csv files, it is advisable to move and rename them after each container invocation because they will otherwise be erased\\overwritten.
  - For convenience, note that in such cases, when exiting from the container, it is advisable to exit party 0 before party 1. For if not, then due to the way the shell scripts are configured, the terminal instance for party 0 will be automatically closed on exiting party 1.


