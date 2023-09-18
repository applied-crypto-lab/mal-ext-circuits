The repository corresponds to the implementation in the article "**Efficiently Compiling Secure Computation Protocols From Passive to Active Security: Beyond Arithmetic Circuits**" published in the Proceedings on Privacy Enhancing Technologies (PoPETs), Vol. 2024, No. 1. 

## Description
We provide the source code necessary to build the software used to obtain the results in our paper, in Section 6, Performance.


## Basic Requirements


### Hardware Requirements
Our tests were run on virtual machine instances emulating machines running 2.6 GHz dual core Intel Xeon E5-2680 v4 processors with 26 GB of RAM. This 64-bit processor has a 32KB L1 cache, 4MB L2 cache, and 16MB L3 cache. This software should run on most platforms, but accurate replication the reported times will be much more likely the closer one can get to this architecture's specs. We aim to eventually provide a Docker container for this software, but are unable to as of this time.

### Network Environment
For our experiments, we aim to ensure a consistent LAN environment of 1Gbps throughput with 0.1ms one-way latency. For three VMs in a compute cluster, we acheived this by running the following commands (which will likely require superuser privelege):

```bash
sudo tc qdisc del dev ens3 root
sudo tc qdisc add dev ens3 root tbf rate 1000Mbit latency 0.1ms burst 500000
sudo tc qdisc show dev ens3
```
If separate machines are available with only significant network separation, it may be advisable to run all tests from a single computer using the above commands for each terminal instance. For convenience, these commands have been bundled into a shell script and included in the repository, ```compute/LAN.sh```, which can be called prior to testing.

### Software Requirements
The operating system used was Ubuntu 18.04.6 LTS with the GNU/Linux 4.15.0-193-generic x86_64 kernel. This software can be built on most platforms, though images of this operating system are available from ubuntu.com.

### Estimated Time and Storage Consumption
The individual algorithm tests run anywhere from a few seconds (e.g. for arithmtic addition), up to an hour or two for malicious arithmetic comparisons at the largest input sizes. For any tests run over SSH, use of a terminal multiplexer is recommended.

## Environment
Our source code is hosted in a GitHub repository, with instructions described below. The following software is required (all available free of charge):

  - GNU gcc g++ compiler
  - GMP (The GNU Multiple Precision Arithmetic Library)
  - openSSL library v1.1
  - GNU Bison parser

### Set up the environment
You can download the repository using HTTPS, SSH, or GitHub CLI. The respective commands (any one of which will suffice) are:

```bash
git clone https://github.com/applied-crypto-lab/mal-ext-circuits.git
git clone git@github.com:applied-crypto-lab/mal-ext-circuits.git
gh repo clone applied-crypto-lab/mal-ext-circuits
```

#### Once the repository has been downloaded, package installation can be verified by calling the following

```bash
apt list g++
apt list libgmp10
apt list libssl1.1
apt list bison
```

#### Any missing libraries can be installed as follows:

```bash
apt-get install g++
apt-get install libgmp10
apt-get install libssl1.1
apt-get install bison
```

Once the libraries are installed and the repository is downloaded, navigate to the ```mal-ext-circuits``` directory of the local repository and issue ```./build.sh```.

This should build all souce code, and you should see executables ```arith_sh, arithm_mal, bit_sh```, and ```bit_mal``` in the ```compute``` directory. You should also see three public and three private keys in the ```compute``` directory, named ```public-X.pem``` and ```private-X.pem``` for ```X = 1, 2, 3```.


### Main Results and Claims
Our experiments simulate three mutually distrusting parties engaging in distributed computation over a network. Our framework compiles computation with certain properties in protocols secure against semihonest adversaries (those seeking to learn protected information but not deviate from the protocol), into ones which are secure against malicious adversaries (those who may deviate from the protocol as well as learn unauthorized information). The latter case is well known to come at increased performance costs. These protocols are intended to be run over arithmetic circuits in a finite field of sufficient modulus size, and the increased security comes at only modest cost over the original semihonest protocols. Additionally, we introduce capapbilities beyond usual arithmetic circuit computation by allowing for values to be revealed mid-computation so long as they meet certain requirements and are verified against tampering on cetain prescribed occasions. The experiments highlight these claims and should replicate numbers provided in Section 6 of our paper.

### Experiments

- We compare performance of batches of addition, multiplication, less-than comparison, equality comparsion, and over-the-threshold Euclidean distance.
- We run tests for arithmetic and bitwise circuits. The latter serves to compare against arithmetic circuit computation as it is a primary alternative which for most computation, especially basic arithmetic operations such as addition and multiplication, comes at a significant performance cost.
  - We run input sizes in powers of ten for i=0..3 in bitwise computation, and i=0..5 in arithmetic.
  - The input size represents a vector of inputs for which a given operation is computed that many times in parallel
    - The one exception is Euclidean distance, for which the input size represents the size of each of two input vectors which produce a single boolean output decision.
  - The only situation where bitwise circuits outperform our arithmetic ones are generally in comparisons, but such performance loss is quite modest (roughly one and a half times the cost in the malicious case)
  - Thus for circuits for which malicious security is desired and which are not completely dominated by comparisons, our framework is a very attractive
    - In particular, the Euclidean distance protocol is many times faster in our framework.
- For both of the above cases, we compare semihonest computation performance with malicious and observe that our malicious secure protocols are a reasonable 2-5 times slower while providing much stronger security guarantees.
- For reference, we also provide communication totals for each protocol as well as AND gate depth for the bitwise protocols.
- We also provide the cost of verification against malicious tampering as a pecentage of the total protocol time, and observe favorable performance from an asymptotic standpoint.

## Artifact Evaluation

#### To run the relevant tests, do the following:

  - Open four terminals. Navigate to the `compute` directory in each and run `LAN.sh` script.
  - The program ```run-comp.sh``` runs all three computational parties as well as the required seed generation program as party 0
  - The command structure is
    - ```./run-comp.sh <circuit type> <threat model> <alg> <config file suffix> <party#> <debug flag>```
      - circuit type is in {arith, bit}
      - threat model is in {sh, mal}
      - alg is in {add, mul, lt, equ, ed, all}
      - config file suffix is explained below
      - party number is in {0..3}
      - debug flag is in {debug, single}

<br>
<br>
<br>

#### Some important notes about these commands:

- The programs must be run in descending order of party number, with the seed program last
- The ```run-comp.sh``` shell script performs basic error checking. However one should take care to run the exact same parameterization for each party or the programs may hang, crash, or produce garbage output.
- The name of the config file must be of the form "runtime-config-X" where X can be any name you would like to give any custom file you create
  - We have provided a file named runtime-config-local (and so you would type 'local' on the command line for this argument)
  - This file is set up to allow testing of all computational parties on the same machine
  - In order to use this program in a true network environment, you should enter the IP addresses, ports, and key files where your machines can accept TCP communication, into a copy of this file and rename it with a different suffix.
- If the debug flag is set as "debug", then the program runs input size 1, 10, and 100 at one iteration each
  - In this case, communication information and AND gate counts (only relevant for bitwise circuits) are provided
- If the debug flag is set to "single", then the program runs all input sizes at one iteration, reporting timing information
- If no debug flag is set, then all tests are run at default iteration counts in duplicate with timing information provided
- All test output information is averaged over all iterations and is provided both to console as well as to csv files
  - The csv files are written, one for each computational party, in append mode, so it is advisable to copy and or relocate files if you want to organize them by test

#### Some example commands:

- ```./run-comp.sh arith sh add local 3```
  - Starts the program for party 3 (which should be run first for all test runs), for semihonest arithmetic addition at default settings on the local machine
- ```./run-comp.sh arith mal ed LAN 2```
  - Starts the program for party 2 (which should be run second for all test runs), for malicious arithmetic Euclidean distance at default settings for the custom network configuration you have provided in a file called "runtime-config-LAN"
- ```./run-comp.sh bit mal equ local 1 debug```
  - Starts the program for party 1 (which should be run third for all test runs), for malicious bitwise equality testing in debug mode on the local machine
- ```./run-comp.sh bit sh lt local 0 single```
  - Starts the program for party 0 (the seed generation program, which should be run last for all test runs), for semihonest bitwise less-than testing in single mode on the local machine



## Limitations
For the largest input sizes, especially for malicious arithmetic at input size 100000, memory consumption can be an issue. We have restricted that largest size to 50 iterations and note that if less memory is available for testing, then this and possibly other iteration counts may need to be reduced. Conversely, if more memory is available, then more iterations may be comfortably run. In either case, memory paging should be avoided since it will negatively impact performance.

## Notes on Reusability
We aim to provide a general purpose multiparty computation compiler secure against malicious adversaries. In particular, we expect that the verification mechanism can be applied to other functionalities, further extending the security guarantees of preexisting semihonest protocols for modest performance cost.


