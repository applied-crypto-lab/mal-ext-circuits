/*
   PICCO: A General Purpose Compiler for Private Distributed Computation
   ** Copyright (C) 2013 PICCO Team
   ** Department of Computer Science and Engineering, University of Notre Dame

   PICCO is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   PICCO is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with PICCO. If not, see <http://www.gnu.org/licenses/>.
*/

#include "NodeNetwork.h"
#include <vector>
#include <cstdlib>
#include "NodeConfiguration.h"
#include <string>
#include "time.h"
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <iostream>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <sys/time.h>
#include <errno.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include "openssl/bio.h"
#include "unistd.h"

NodeConfiguration *config;
EVP_CIPHER_CTX *en, *de;
int base = 36;
int MAX_BUFFER_SIZE = 229376; // in bytes
//int MAX_BUFFER_SIZE = 4194304;

std::map<int, EVP_CIPHER_CTX*> peer2enlist;
std::map<int, EVP_CIPHER_CTX*> peer2delist;
std::string privatekeyfile;
unsigned char* KeyIV;
unsigned char* peerKeyIV;

/************ STATIC VARIABLES INITIALIZATION ***************/
int NodeNetwork::mode = -1; // -1 -- non-thread, 0 -- thread
int NodeNetwork::numOfChangedNodes = 0; //number of nodes that has changed modes so far
/************************************************************/


NodeNetwork::NodeNetwork(NodeConfiguration *nodeConfig, std::string privatekey_filename, int num_threads, unsigned char * key_0, unsigned char *key_1, int tt) {
	threshold = tt;
	comm_counter = new unsigned long[2];
	comm_counter[0] = 0;
	comm_counter[1] = 0;

	privatekeyfile = privatekey_filename;
	config = nodeConfig;
	connectToPeers(key_0,key_1);
	numOfThreads = num_threads; // it should be read from parsing
	int peers = config->getPeerCount();
	int numb = 8 * sizeof(char);
	int temp_buffer_size = MAX_BUFFER_SIZE/(peers+1)/((config->getBits()+numb-1)/numb);

	int pid = config->getID();
}

NodeNetwork::NodeNetwork() {}

NodeNetwork::~NodeNetwork() {}


void NodeNetwork::reset_comm_counter()
{
	comm_counter[0] = 0;
	comm_counter[1] = 0;
}


void NodeNetwork::getSummary(std::string test_description, bool writing_to_file)
{
	printf("Comm Counter 0 (bytes sent): %ld \n", comm_counter[0]);
	printf("Comm counter 1 (bytes received): %ld \n", comm_counter[1]);

	if (writing_to_file)
	{
		std::ofstream results_file;
		results_file.open("comm_test_results_" + std::to_string(getID()) + ".csv", std::ios::app);

		results_file << "\n" << test_description << "," << "," << comm_counter[0] << "\n";
		results_file.close();
	}
}



void NodeNetwork::sendDataToPeer(int id, mpz_t* data, int start, int amount, int size){
	try{
		int read_amount = 0;
		if(start+amount > size)
			read_amount = size-start;
		else
			read_amount = amount;

		int unit_size = get_unit_size();
		int buffer_size = unit_size * read_amount;
		char* buffer = (char*) malloc(sizeof(char) * buffer_size);
		char* pointer = buffer;
		memset(buffer, 0, buffer_size);
		for(int i = start; i < start+read_amount; i++){
			mpz_export(pointer, NULL, -1, 1, -1, 0, data[i]);
			pointer += unit_size;
		}
		EVP_CIPHER_CTX *en_temp = peer2enlist.find(id)->second;
		unsigned char *ciphertext = (unsigned char*) malloc(buffer_size * sizeof(unsigned char));
		aes_encrypt(en_temp, (unsigned char*)buffer, ciphertext, &buffer_size);
		sendDataToPeer(id, buffer_size, ciphertext);
		free(buffer);
		free(ciphertext);
	}catch(std::exception& e){
		std::cout << "An exception (in Send Data To Peer) was caught: " << e.what() << "\n";
	}
}

void NodeNetwork::sendDataToPeer(int id, int size, mpz_t *data)
{
    int count = 0, rounds = 0;
    getRounds(size, &count, &rounds);
    for(int k = 0; k <= rounds; k++)
        sendDataToPeer(id, data, k*count, count, size);
}

void NodeNetwork::sendDataToPeer(int id, int size, long long *data)
{
    int count = 0, rounds = 0;
    getRounds(size, &count, &rounds);
    mpz_t* data1 = new mpz_t[size];//(mpz_t*)malloc(sizeof(mpz_t) * size);
    for(int i = 0; i < size; i++)
   	mpz_init_set_ui(data1[i], data[i]);
    for(int k = 0; k <= rounds; k++)
        sendDataToPeer(id, data1, k*count, count, size);

   //free the memory
    for(int i = 0; i < size; i++)
		mpz_clear(data1[i]);
	delete data1;
    //free(data1);
}

void NodeNetwork::getDataFromPeer(int id, int size, mpz_t* buffer)
{
    int count = 0, rounds = 0;
    getRounds(size, &count, &rounds);
    for(int k = 0; k <= rounds; k++)
        getDataFromPeer(id, buffer, k*count, count, size);
}

void NodeNetwork::getDataFromPeer(int id, int size, long long *buffer)
{
    int count = 0, rounds = 0;
    mpz_t* buffer1 = new mpz_t[size];//(mpz_t*)malloc(sizeof(mpz_t) * size);
    for(int i = 0; i < size; i++)
   	mpz_init(buffer1[i]);
    getRounds(size, &count, &rounds);
    for(int k = 0; k <= rounds; k++)
        getDataFromPeer(id, buffer1, k*count, count, size);

    for(int i = 0; i < size; i++)
    {
	buffer[i] = mpz_get_ui(buffer1[i]);
    }
    for(int i = 0; i < size; i++)
	    mpz_clear(buffer1[i]);

	delete buffer1;
    //free(buffer1);
}

void NodeNetwork::sendDataToPeer(int id, int size, unsigned char* data){
	try{
		int on = 1;
		unsigned char* p = data;
		int bytes_read = sizeof(unsigned char) * size;
		int sockfd = peer2sock.find(id)->second;
  		fd_set fds;
		while(bytes_read > 0){
			int bytes_written = send(sockfd, p, sizeof(unsigned char) * bytes_read, MSG_DONTWAIT);
			if(bytes_written < 0){
				FD_ZERO(&fds);
				FD_SET(sockfd, &fds);
				int n = select(sockfd+1, NULL, &fds, NULL, NULL);
				if(n > 0)
					continue;
			}
			else{
				bytes_read -= bytes_written;
				p += bytes_written;
				comm_counter[0] += bytes_written;
				//printf("%i written\n", bytes_written);
				//send_counter.push_back(bytes_written);
			}
		}
	} catch(std::exception& e){
		std::cout << "An exception (in Send Data To Peer) was caught: " << e.what() << "\n";
	}
}

void NodeNetwork::sendDataToPeer(int id, int size, int* data){
	try{
		int* p = data;
		int bytes_read = sizeof(int) * size;
		int sockfd = peer2sock.find(id)->second;
		fd_set fds;
		while(bytes_read > 0){
			int bytes_written = send(sockfd, p, bytes_read, MSG_DONTWAIT);
			if(bytes_written < 0){
				FD_ZERO(&fds);
				FD_SET(sockfd, &fds);
				int n = select(sockfd+1, NULL, &fds, NULL, NULL);
				if(n > 0)
					continue;
			}
			else{
				bytes_read -= bytes_written;
				p += (bytes_written/sizeof(int));
				comm_counter[0] += bytes_written;
				//printf("%i written\n", bytes_written);
				//send_counter.push_back(bytes_written);
			}
		}
	}catch(std::exception& e){
		std::cout << "An exception (in Send Data To Peer) was caught: " << e.what() << "\n";
	}
}

void NodeNetwork::getDataFromPeer(int id, int size, int* buffer){
	try{
		int length = 0, bytes = 0;
		int* tmp_buffer = new int[size];//(int*)malloc(sizeof(int) * size);
		fd_set fds;
		std::map<int, int>::iterator it;
		int sockfd = peer2sock.find(id)->second;
		while(length < sizeof(int) * size){
				bytes = recv(sockfd, tmp_buffer, sizeof(int) * (size-length/sizeof(int)), MSG_DONTWAIT);
				if(bytes < 0){
					FD_ZERO(&fds);
					FD_SET(sockfd, &fds);
					int n = select(sockfd+1, &fds, NULL, NULL, NULL);
					if(n > 0)
						continue;
				}
				else{
					memcpy(&buffer[length/sizeof(int)], tmp_buffer, bytes);
					length += bytes;
					comm_counter[1] += bytes;
					//printf("%i read\n", bytes);
					//recv_counter.push_back(bytes);
				}
		}
		delete tmp_buffer;
		//free(tmp_buffer);
	}catch(std::exception& e){
		std::cout << "An exception (get Data From Peer) was caught: " << e.what() << "\n";
	}
}

void NodeNetwork::getDataFromPeer(int id, int size, unsigned char* buffer){
	try{
		int length = 0, bytes = 0;
		unsigned char* tmp_buffer = new unsigned char[size];//(unsigned char*)malloc(sizeof(unsigned char) * size);
		fd_set fds;
		int sockfd = peer2sock.find(id)->second;
		while(length < sizeof(unsigned char) * size){
			bytes = recv(sockfd, tmp_buffer, sizeof(unsigned char) * (size-length/sizeof(unsigned char)), MSG_DONTWAIT);
			if(bytes < 0){
				FD_ZERO(&fds);
				FD_SET(sockfd, &fds);
				int n = select(sockfd+1, &fds, NULL, NULL, NULL);
				if(n > 0)
					continue;
			}
			else{
				memcpy(&buffer[length/sizeof(unsigned char)], tmp_buffer, bytes);
				length += bytes;
				comm_counter[1] += bytes;
				//printf("%i read\n", bytes);
				//recv_counter.push_back(bytes);
			}
		}
		delete tmp_buffer;
		//free(tmp_buffer);
    }catch(std::exception& e){
        std::cout << "An exception (get Data From Peer) was caught: " << e.what() << "\n";
    }
}


void NodeNetwork::getDataFromPeer(int id, mpz_t* data, int start, int amount, int size){
	try{
		int write_amount = 0;
		if(start+amount > size)
			write_amount = size-start;
		else
			write_amount = amount;

		int unit_size = get_unit_size();
		EVP_CIPHER_CTX *de_temp = peer2delist.find(id)->second;
		int buffer_size = unit_size * write_amount;
		char* buffer = (char*) malloc(sizeof(char) * buffer_size);
		getDataFromPeer(id, buffer_size, (unsigned char*)buffer);
		unsigned char *plaintext = (unsigned char*) malloc(buffer_size * sizeof(unsigned char));
		aes_decrypt(de_temp, plaintext, (unsigned char*) buffer, &buffer_size);

		unsigned char *ptext_ptr = plaintext;
		for(int i = start; i < start+write_amount; i++)
		{
			mpz_import(data[i], unit_size, -1, 1, -1, 0, ptext_ptr);
			ptext_ptr += unit_size;
		}

		free(plaintext);
		free(buffer);
	}catch(std::exception& e){
		std::cout << "An exception (get Data From Peer) was caught: " << e.what() << "\n";
	}
}

void NodeNetwork::multicastToPeers(long long** srcBuffer, long long **desBuffer, int size){
    int peers = config->getPeerCount();
    mpz_t** buffer = new mpz_t*[peers+1];//(mpz_t**)malloc(sizeof(mpz_t*) * (peers+1));
    mpz_t** data = new mpz_t*[peers+1];//(mpz_t**)malloc(sizeof(mpz_t*) * (peers+1));
    int sendIdx = 0, getIdx = 0;
    for(int i = 0; i < peers + 1; i++)
    {
        buffer[i] = new mpz_t[size];//(mpz_t*)malloc(sizeof(mpz_t) * size);
        data[i] = new mpz_t[size];// = (mpz_t*)malloc(sizeof(mpz_t) * size);
        for(int j = 0; j < size; j++)
        {
                mpz_init(buffer[i][j]);
                mpz_init_set_ui(data[i][j], srcBuffer[i][j]);
        }
    }

    multicastToPeers(data, buffer, size, -1);
    for(int i = 0; i <= peers; i++)
	for(int j = 0; j < size; j++)
		desBuffer[i][j] = mpz_get_ui(buffer[i][j]);
    for(int i = 0; i < peers + 1; i++)
    {
		for(int j = 0; j < size; j++)
		{
			mpz_clear(buffer[i][j]);
			mpz_clear(data[i][j]);
		}
        //free(buffer[i]);
        //free(data[i]);
		delete buffer[i];
		delete data[i];
    }
    delete buffer;
    delete data;
}


void NodeNetwork::multicastToPeers(mpz_t** data, mpz_t** buffers, int size, int threadID){
    int id = getID();
    int peers = config->getPeerCount();
    struct timeval tv1, tv2;

    int sendIdx = 0, getIdx = 0;
    //compute the maximum size of data that can be communicated
    int count = 0, rounds = 0;
    getRounds(size, &count, &rounds);
    for(int i = 1; i <= peers+1; i++)
    {
	if(id == i)
        {
            for(int k = 0; k <= rounds; k++)
            {
                for(int j = 1; j <= peers+1; j++)
                {
                    if(id == j)
                        continue;
                    sendDataToPeer(j, data[j-1], k*count, count, size);
                }
                for(int j = 1; j <= peers+1; j++)
                {
                    if(id == j)
                        continue;
                    getDataFromPeer(j, buffers[j-1], k*count, count, size);
                }
            }
        }
    }
    for(int i = 0; i < size; i++)
	mpz_set(buffers[id-1][i], data[id-1][i]);
}


void NodeNetwork::broadcastToPeers(mpz_t* data, int size, mpz_t** buffers, int threadID)
{
	int id = getID();
	int peers = config->getPeerCount();

	int rounds = 0, count = 0;
	getRounds(size, &count, &rounds);
	for(int i = 1; i <= peers+1; i++)
	{
		if(id == i)
		{
			for(int k = 0; k <= rounds; k++)
			{
				for(int j = 1; j <= peers+1; j++)
				{
					if(id == j)
						continue;
					sendDataToPeer(j, data, k*count, count, size);
				}
				for(int j = 1; j <= peers+1; j++)
				{
					if(id == j)
						continue;
					getDataFromPeer(j, buffers[j-1], k*count, count, size);
				}
			}
			for(int j = 0; j < size; j++)
				mpz_set(buffers[id-1][j], data[j]);
		}
	}
}

void NodeNetwork::broadcastToPeers(long long* data, int size, long long** result){
    int id = getID();
    int peers = config->getPeerCount();
    mpz_t** buffers = new mpz_t*[peers + 1];//(mpz_t**)malloc(sizeof(mpz_t*) * (peers+1));
    mpz_t *data1 = new mpz_t[size];//(mpz_t*)malloc(size * sizeof(mpz_t));

    for(int i = 0; i < peers + 1; i++)
    {
        buffers[i] = new mpz_t[size];//(mpz_t*)malloc(sizeof(mpz_t) * size);
        for(int j = 0; j < size; j++)
                mpz_init(buffers[i][j]);
    }

    for(int i = 0; i < size; i++)
        mpz_init_set_ui(data1[i], data[i]);
    broadcastToPeers(data1, size, buffers, -1);
    for(int i = 0; i <= peers; i++)
	for(int j = 0; j < size; j++)
		result[i][j] = mpz_get_ui(buffers[i][j]);

	for(int i = 0; i < peers + 1; i++)
	{
		for(int j = 0; j < size; j++)
		{
			mpz_clear(buffers[i][j]);
			if (i == 0)
				mpz_clear(data1[i]);
		}
	}

    for(int i = 0; i <= peers; i++)
	{
        //free(buffers[i]);
		delete buffers[i];
	}

	delete buffers;
	delete data1;
}


void NodeNetwork::connectToPeers(unsigned char * key_0, unsigned char *key_1){
	int peers = config->getPeerCount();
	for (int i = 1; i <= peers+1; i++)
		if(config->getID() == i)
		{
			if(i != (peers+1))
				requestConnection(peers+1-i, key_0, key_1);
			if(i != 1)
				acceptPeers(i-1,  key_0, key_1);
		}
}


void NodeNetwork::sendModeToPeers(int id){
     int peers = config->getPeerCount();
     int msg = -2;
     for(int j = 1; j <= peers+1; j++){
        if(id == j)
          continue;
      	  sendDataToPeer(j, 1, &msg);
   }
   //sleep(1);
}



void NodeNetwork::sendDataToPeer(int id, mpz_t* data, int start, int amount, int size, int threadID){
	try{
		int read_amount = 0;
		if(start+amount > size)
			read_amount = size-start;
		else
			read_amount = amount;

		int unit_size = get_unit_size();
		int buffer_size = unit_size * read_amount;
		int* info = (int*) malloc(sizeof(int) * 3);
		info[0] = start;
		info[1] = amount;
		info[2] = size;

		char* buffer = (char*) malloc(sizeof(char) * buffer_size);
		char* pointer = buffer;
		memset(buffer, 0, buffer_size);
		for(int i = start; i < start+read_amount; i++){
			mpz_export(pointer, NULL, -1, 1, -1, 0, data[i]);
			pointer += unit_size;
		}

		EVP_CIPHER_CTX *en_temp = peer2enlist.find(id)->second;
		unsigned char *ciphertext = (unsigned char*) malloc(buffer_size * sizeof(unsigned char));
		aes_encrypt(en_temp, (unsigned char*)buffer, ciphertext, &buffer_size);
		sendDataToPeer(id, 1, &threadID);
		sendDataToPeer(id, 3, info);
		//sendDataToPeer(id, 1, &buffer_size);
		sendDataToPeer(id, buffer_size, ciphertext);
		free(buffer);
		free(info);
		free(ciphertext);
	}catch(std::exception& e){
		std::cout << "An exception (in Send Data To Peer) was caught: " << e.what() << "\n";
	}
}

void NodeNetwork::requestConnection(int numOfPeers, unsigned char * key_0, unsigned char *key_1){
		peerKeyIV = (unsigned char*)malloc(32);
		int* sockfd = (int*)malloc(sizeof(int) * numOfPeers);
		int* portno = (int*)malloc(sizeof(int) * numOfPeers);
		struct sockaddr_in *serv_addr = (struct sockaddr_in*)malloc(sizeof(struct sockaddr_in) * numOfPeers);
		struct hostent **server = (struct hostent**)malloc(sizeof(struct hostent*) * numOfPeers);
	 	int on = 1;

		for(int i = 0; i < numOfPeers; i++){
			int ID = config->getID()+i+1;
			portno[i] = config->getPeerPort(ID);
			sockfd[i] = socket(AF_INET, SOCK_STREAM, 0);
			if(sockfd[i] < 0)
				fprintf(stderr, "ERROR, opening socket\n");
			// the function below might not work in certain
			// configurations, e.g., running all nodes from the
			// same VM. it is not used for single-threaded programs
			// and thus be commented out or replaced with an
			// equivalent function otherwise.
 			//fcntl(sockfd[i], F_SETFL, O_NONBLOCK);
			int rc = setsockopt(sockfd[i], SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on));
			rc = setsockopt(sockfd[i], IPPROTO_TCP, TCP_NODELAY, (char*)&on, sizeof(on));
			server[i] = gethostbyname((config->getPeerIP(ID)).c_str());
			if(server[i] == NULL)
				fprintf(stderr, "ERROR, no such hosts \n");
			bzero((char*) &serv_addr[i], sizeof(serv_addr[i]));
			serv_addr[i].sin_family = AF_INET;
			bcopy((char*)server[i]->h_addr, (char*)&serv_addr[i].sin_addr.s_addr, server[i]->h_length);
			serv_addr[i].sin_port = htons(portno[i]);

			int res, valopt;
  			fd_set myset;
  			struct timeval tv;
  			socklen_t lon;
			res = connect(sockfd[i], (struct sockaddr*) &serv_addr[i], sizeof(serv_addr[i]));
			if (res < 0) {
     				if (errno == EINPROGRESS) {
        				tv.tv_sec = 15;
        				tv.tv_usec = 0;
        				FD_ZERO(&myset);
        				FD_SET(sockfd[i], &myset);
        				if (select(sockfd[i]+1, NULL, &myset, NULL, &tv) > 0) {
           					lon = sizeof(int);
           					getsockopt(sockfd[i], SOL_SOCKET, SO_ERROR, (void*)(&valopt), &lon);
           					if (valopt) {
							fprintf(stderr, "Error in connection() %d - %s\n", valopt, strerror(valopt));
              						exit(0);
           					}
        				}
        				else {
           					fprintf(stderr, "Timeout or error() %d - %s\n", valopt, strerror(valopt));
          				 	exit(0);
        			     	}
     				}
     				else {
        				fprintf(stderr, "Error connecting %d - %s\n", errno, strerror(errno));
        				exit(0);
     				}
  			}
			printf("Connected to node %d\n", ID);
			peer2sock.insert(std::pair<int, int>(ID, sockfd[i]));
			sock2peer.insert(std::pair<int, int>(sockfd[i], ID));

			FILE *prikeyfp = fopen(privatekeyfile.c_str(), "r");
			if( prikeyfp == NULL ) printf("File Open %s error\n", privatekeyfile.c_str());
			RSA *priRkey = PEM_read_RSAPrivateKey(prikeyfp, NULL, NULL, NULL);
			if( priRkey == NULL) printf("Read Private Key for RSA Error\n");
			char *buffer = (char*)malloc(RSA_size(priRkey));
    		int n = read(sockfd[i], buffer, RSA_size(priRkey));
    		if (n < 0) printf("ERROR reading from socket \n");
			char *decrypt = (char*)malloc(n);
			memset(decrypt, 0x00, n);
			int dec_len = RSA_private_decrypt(n, (unsigned char*)buffer, (unsigned char*)decrypt, priRkey, RSA_PKCS1_OAEP_PADDING);
			if(dec_len < 1) printf("RSA private decrypt error\n");
			memcpy(peerKeyIV, decrypt, 32);
			init_keys(ID, 1, key_0, key_1);
			free(buffer);
			free(decrypt);
		}
}

void NodeNetwork::acceptPeers(int numOfPeers, unsigned char * key_0, unsigned char *key_1){
		KeyIV = (unsigned char*)malloc(32);
		int sockfd, maxsd, portno, on = 1;
		int *newsockfd = (int*)malloc(sizeof(int) * numOfPeers);
		socklen_t *clilen = (socklen_t*)malloc(sizeof(socklen_t) * numOfPeers);
		struct sockaddr_in serv_addr;
		struct sockaddr_in *cli_addr = (struct sockaddr_in*)malloc(sizeof(struct sockaddr_in) * numOfPeers);

		fd_set master_set, working_set;
		sockfd = socket(AF_INET, SOCK_STREAM, 0);
		// see comment for fcntl above
		//fcntl(sockfd, F_SETFL, O_NONBLOCK);
		if(sockfd < 0)
			fprintf(stderr, "ERROR, opening socket\n");
		int rc = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on));
		rc = setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, (char*)&on, sizeof(on));
		if(rc < 0)
			printf("setsockopt() or ioctl() failed\n");
		bzero((char*) &serv_addr, sizeof(serv_addr));
		portno = config->getPort();
		serv_addr.sin_family = AF_INET;
		serv_addr.sin_addr.s_addr = INADDR_ANY;
		serv_addr.sin_port = htons(portno);
		if((bind(sockfd, (struct sockaddr*) &serv_addr, sizeof(serv_addr))) < 0)
			printf("ERROR, on binding \n");
		listen(sockfd, 7);
		// start to accept connections
		FD_ZERO(&master_set);
		maxsd = sockfd;
		FD_SET(sockfd, &master_set);
		for(int i = 0; i < numOfPeers; i++){
			memcpy(&working_set, &master_set, sizeof(master_set));
			rc = select(maxsd+1, &working_set, NULL, NULL, NULL);
			if(rc <= 0)
				printf("select failed or time out \n");
			if(FD_ISSET(sockfd, &working_set)){
				clilen[i] = sizeof(cli_addr[i]);
				newsockfd[i] = accept(sockfd, (struct sockaddr*) &cli_addr[i], &clilen[i]);
				if(newsockfd[i] < 0)
					fprintf(stderr, "ERROR, on accept\n");
				// see comment for fcntl above
 				//fcntl(newsockfd[i], F_SETFL, O_NONBLOCK);
				peer2sock.insert(std::pair<int, int>(config->getID() - (i+1), newsockfd[i]));
				sock2peer.insert(std::pair<int, int>(newsockfd[i], config->getID() - (i+1)));

				unsigned char key_iv[32];
				RAND_status();
				if( !RAND_bytes(key_iv, 32) )
					printf("Key, iv generation error\n");
				memcpy(KeyIV, key_iv, 32);
				int peer = config->getID() - (i+1);
				FILE *pubkeyfp = fopen((config->getPeerPubKey(peer)).c_str(), "r");
				if( pubkeyfp == NULL ) printf("File Open %s error \n", (config->getPeerPubKey(peer)).c_str());
				RSA *publicRkey = PEM_read_RSA_PUBKEY(pubkeyfp, NULL, NULL, NULL);
				if( publicRkey == NULL) printf("Read Public Key for RSA Error\n");
				char *encrypt = (char*)malloc(RSA_size(publicRkey));
				memset(encrypt, 0x00, RSA_size(publicRkey));
				int enc_len = RSA_public_encrypt(32, KeyIV, (unsigned char*)encrypt, publicRkey, RSA_PKCS1_OAEP_PADDING);
				if(enc_len < 1) printf("RSA public encrypt error\n");
				int n = write(newsockfd[i], encrypt, enc_len);
     			if (n < 0) printf("ERROR writing to socket \n");
				init_keys(peer, 0,  key_0, key_1);
				free(encrypt);
			}
		}
}


void NodeNetwork::init_keys(int peer, int nRead, unsigned char * key_0, unsigned char *key_1)
{
	int id = getID();
	int peers = 1 + config->getPeerCount();

	int id_p1 = (id + 1 + peers) % peers;
	if (id_p1 == 0) id_p1 = peers;

	int id_m1 = (id - 1 + peers) % peers;
	if (id_m1 == 0) id_m1 = peers;;

	//printf("this is %d, p1 is %d, m1 is %d\n, and peers is %d",id, id_p1, id_m1, peers);

	unsigned char key[16],iv[16];
	memset(key, 0x00, 16);
	memset(iv, 0x00, 16);
	if(0 == nRead) //useKey KeyIV
	{
		memcpy(key, KeyIV, 16);
		memcpy(iv, KeyIV+16, 16);
	}
	else //getKey from peers
	{
		memcpy(key, peerKeyIV, 16);
		memcpy(iv, peerKeyIV+16, 16);
	}
	if(peer == id_p1)
	{
		memcpy( key_1, key, 16);


	}else if(peer == id_m1)
	{
		memcpy( key_0, key, 16);
	}

	en = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(en,EVP_aes_128_ctr(), NULL, key, iv);
	de = EVP_CIPHER_CTX_new();
	EVP_DecryptInit_ex(de,EVP_aes_128_ctr(), NULL, key, iv);
	peer2enlist.insert(std::pair<int, EVP_CIPHER_CTX*>(peer, en));
	peer2delist.insert(std::pair<int, EVP_CIPHER_CTX*>(peer, de));
}

void NodeNetwork::mpzFromString(char *str, mpz_t* no, int* lengths, int size){

	for(int i = 0; i < size; i++){
		char temp[lengths[i]]; // = (char*)malloc(sizeof(char) * lengths[i]);
		memcpy(temp, str, lengths[i]);
		temp[lengths[i]] = '\0';
		str += lengths[i];
		mpz_set_str(no[i], temp, base);
	}
}


int NodeNetwork::get_unit_size()
{
	int bits = config->getBits();
	int pad_width = 8 * sizeof(char);
	return (bits + pad_width - 1) / pad_width;
}


void NodeNetwork::getRounds(int size, int *count, int *rounds)
{
	int unit_size = get_unit_size();
	int peers = config->getPeerCount();
    *count = MAX_BUFFER_SIZE/(peers+1)/unit_size;
    if(size % (*count) != 0)
    	*rounds = size/(*count);
    else
	*rounds = size/(*count)-1;
}


double NodeNetwork::time_diff(struct timeval *t1, struct timeval *t2){
	double elapsed;
	if(t1->tv_usec > t2->tv_usec){
		t2->tv_usec += 1000000;
		t2->tv_sec--;
	}

	elapsed = (t2->tv_sec-t1->tv_sec) + (t2->tv_usec - t1->tv_usec)/1000000.0;

	return(elapsed);
}

int NodeNetwork::getID(){
	return config->getID();
}

int NodeNetwork::getNumOfThreads(){
	return numOfThreads;
}



void NodeNetwork::aes_encrypt(EVP_CIPHER_CTX *e, unsigned char *plaintext, unsigned char *ciphertext, int *len){

	int c_len = *len;
	int f_len = 0;

	EVP_EncryptInit_ex(e, NULL, NULL, NULL, NULL);
	EVP_EncryptUpdate(e,ciphertext, &c_len, plaintext, *len);
	EVP_EncryptFinal_ex(e, ciphertext+c_len, &f_len);

	*len = c_len + f_len;
}



void NodeNetwork::aes_decrypt(EVP_CIPHER_CTX *e, unsigned char *plaintext, unsigned char *ciphertext, int *len){

	int p_len = *len;
	int f_len = 0;

	EVP_DecryptInit_ex(e, NULL, NULL, NULL, NULL);
	EVP_DecryptUpdate(e, plaintext, &p_len, ciphertext, *len);
	EVP_DecryptFinal_ex(e, plaintext+p_len, &f_len);

	*len = p_len  + f_len;
}



void NodeNetwork::multicastToPeers_Mul(mpz_t** data, int size, int threadID)
{
	int id = getID();
	int peers = 1 + config->getPeerCount();

	int id_p1 = (id + 1 + peers) % peers;
	if (id_p1 == 0) id_p1 = peers;

	int id_m1 = (id - 1 + peers) % peers;
	if (id_m1 == 0) id_m1 = peers;

	int sendIdx = 0, getIdx = 0;
	//compute the maximum size of data that can be communicated
	int count = 0, rounds = 0;
	getRounds(size, &count, &rounds);
	//printf("count: %i\t rounds%i\n", count, rounds);
	for(int k = 0; k <= rounds; k++)
	{
		sendDataToPeer(id_m1, data[id_m1-1], k*count, count, size);
		getDataFromPeer(id_p1, data[id_p1-1],k*count, count, size);
	}
}


void NodeNetwork::multicastToPeers_T(mpz_t** data, int size, int threshold, int threadID)
{
	int id = getID();
	int peers = 1 + config->getPeerCount();

	int id_p1 = id + 1 + peers;
	int id_m1 = id - 1 + peers;
	int peer = id_p1;

	while (peer < id + threshold + 1 + peers)
	{
		id_p1 %= peers;
		id_m1 %= peers;
		if (id_p1 == 0) id_p1 = peers;
		if (id_m1 == 0) id_m1 = peers;

		int sendIdx = 0, getIdx = 0;
		int count = 0, rounds = 0;
		getRounds(size, &count, &rounds);
		for(int k = 0; k <= rounds; k++)
		{
			sendDataToPeer(id_m1, data[id_m1 - 1], k * count, count, size);
			getDataFromPeer(id_p1, data[id_p1 - 1],k * count, count, size);
		}
		peer++;
		id_p1++;
		id_m1--;
	}
}


void NodeNetwork::broadcastToPeers_T(mpz_t data, mpz_t *buffers, int threshold, int threadID)
{
	int id = getID();
	int peers = 1 + config->getPeerCount();

	int id_p1 = id + 1 + peers;
	int id_m1 = id - 1 + peers;
	int peer = id_p1;

	mpz_set(buffers[id-1], data);

	while (peer < id + threshold + 1 + peers)
	{
		id_p1 %= peers;
		id_m1 %= peers;
		if (id_p1 == 0) id_p1 = peers;
		if (id_m1 == 0) id_m1 = peers;

		sendDataToPeer(id_m1, 1, &buffers[id-1]);
		getDataFromPeer(id_p1, 1, &buffers[id_p1 - 1]);

		peer++;
		id_p1++;
		id_m1--;
	}

}


void NodeNetwork::broadcastToPeers_T(mpz_t* data, int size, mpz_t** buffers, int threshold, int threadID)
{
	int id = getID();
	int peers = 1 + config->getPeerCount();

	int rounds = 0, count = 0;
	getRounds(size, &count, &rounds);

	int id_p1 = id + 1 + peers;
	int id_m1 = id - 1 + peers;
	int peer = id_p1;

	for(int j = 0; j < size; j++)
		mpz_set(buffers[id-1][j], data[j]);

	while (peer < id + threshold + 1 + peers)
	{
		id_p1 %= peers;
		id_m1 %= peers;
		if (id_p1 == 0) id_p1 = peers;
		if (id_m1 == 0) id_m1 = peers;

		for(int k = 0; k <= rounds; k++)
		{
			sendDataToPeer(id_m1, data, k * count, count, size);
			getDataFromPeer(id_p1, buffers[id_p1 - 1], k * count, count, size);
		}

		peer++;
		id_p1++;
		id_m1--;
	}
}


void NodeNetwork::Returnkey(unsigned char * key0,unsigned char * key1)
	{

	memcpy( key1, key_1, 16);
	memcpy( key0, key_0, 16);

	}

int NodeNetwork::getpeers() {
	return config->getPeerCount();
}
void NodeNetwork::closeAllConnections(){
}
