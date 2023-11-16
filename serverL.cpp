#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/wait.h>

#include <iostream>
#include <fstream>
#include <sstream>
#include <map>
#include <string>
#include <cstring>

#define PORT "42026"
#define LOCALHOST "127.0.0.1"
#define MAXDATASIZE 200

std::map<std::string, int> LiteratureLib;
int result;

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

// Load file to local map
void readFile(){
 std::ifstream inputFile("literature.txt");
	if (!inputFile) {
		std::cerr << "Error opening file." << std::endl;
	} else{
		std::string line;
		while (std::getline(inputFile, line)) {
			std::istringstream iss(line);
			std::string key;
			int value;
			if (std::getline(iss, key, ',') && (iss >> value)) {
				LiteratureLib[key] = value;
			} else {
				std::cerr << "Error parsing line: " << line << std::endl;
			}
		}	
	}
	inputFile.close();
}

// Checkout book based on the rule
void checkValue(const char* key, const char* status) {
    std::string keyString(key);
    auto it = LiteratureLib.find(keyString);
    if (it == LiteratureLib.end()) {
        result = -1;
    } else{
         int value = it->second;
    if (value == 0) {
        result = 0;
    } else {
     if(status[0]=='U') it->second--;
     result = value;
    }
    }
}

int main(void)
{
// UDP socket initialization (copied from Beej's-Guide: listener.c)
	int sockfd;
	struct addrinfo hints, *servinfo, *p;
	int rv;
	int numbytes;
	struct sockaddr_storage their_addr;
	socklen_t addr_len;
	char s[INET6_ADDRSTRLEN];
 char bookcode[MAXDATASIZE];
	char status[2];

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC; // set to AF_INET to force IPv4
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE; // use my IP

	if ((rv = getaddrinfo(LOCALHOST, PORT, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return 1;
	}

	// loop through all the results and bind to the first we can
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
				p->ai_protocol)) == -1) {
			perror("listener: socket");
			continue;
		}

		if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(sockfd);
			perror("listener: bind");
			continue;
		}

		break;
	}

	if (p == NULL) {
		fprintf(stderr, "listener: failed to bind socket\n");
		return 2;
	}

	freeaddrinfo(servinfo);

 readFile();

 printf("Server L is up and running using UDP on port 42026.\n");

while(1){
		addr_len = sizeof their_addr;
		if ((numbytes = recvfrom(sockfd, &bookcode, MAXDATASIZE-1 , 0,
			(struct sockaddr *)&their_addr, &addr_len)) == -1) {
			perror("recvfrom");
			exit(1);
		}

  /* Situations
   * 1. Book Code not fount. --> return -1
   * 2. Inventory == 0 --> return 0
   * 3. Success --> return #inventory
   * */
		int length = (bookcode[0] - '0') * 10 + (bookcode[1] - '0');
		status[0] = bookcode[length + 1];
		status[1] = '\0';
		char* code = new char[length-1];
		strncpy(code, bookcode + 2, length-1);
		code[length-1] = '\0';
		if(status[0]=='U'){
			std::cout << "Server L received " << code << " code from the Main Server." << std::endl;
		} else {
			std::cout << "Server L received an inventory status request for code " << code << "." << std::endl;
		}
	checkValue(code,status);
	if ((numbytes = sendto(sockfd, &result, sizeof(result), 0, (struct sockaddr *)&their_addr, addr_len)) == -1) {
			perror("senderr: sendto");
			exit(1);
		}
		if(status[0]=='U'){
			std::cout << "Server L finished sending the availability status of code " << code << " to the Main Server using UDP on port 42026." << std::endl;
		} else {
			std::cout << "Server L finished sending the inventory status to the Main server using UDP on port 42026." << std::endl;
		}
}
close(sockfd);
}

// g++ -std=c++11 -o serverL serverL.cpp
// ./serverL