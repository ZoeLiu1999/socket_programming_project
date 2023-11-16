#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <cstring>
#include <iostream>
#include <map>
#include <fstream>


#define LOCALHOST "127.0.0.1"
#define MY_TCP_PORT "45026"
#define MY_UDP_PORT "44026"
#define S_UDP_PORT "41026"
#define L_UDP_PORT "42026"
#define H_UDP_PORT "43026"

#define BACKLOG 10
#define MAXDATASIZE 200

std::map<std::string, std::string> credentialsMap;


// code copied from Beej's tutorial
void sigchld_handler(int s)
{
    // waitpid() might overwrite errno, so we save and restore it:
    int saved_errno = errno;

    while(waitpid(-1, NULL, WNOHANG) > 0);

    errno = saved_errno;
}


// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

// Decode username and password
void splitWords(const char* input, char*& word1, char*& word2) {
    int length = (input[0] - '0') * 10 + (input[1] - '0');
    word1 = new char[length + 1]; 
    word2 = new char[strlen(input) - length + 1]; 
    strncpy(word1, input + 2, length);
    word1[length] = '\0'; 
    strcpy(word2, input + 2 + length);
}

// load file to local map
int loadMembers() {
    std::ifstream inputFile("member.txt");
    if (!inputFile) {
        std::cerr << "Error opening file." << std::endl;
        return 1;
    }

    std::string line;
    while (std::getline(inputFile, line)) {
        std::string delimiter = ", ";
        size_t delimiterPos = line.find(delimiter);
        std::string temp_u = line.substr(0, delimiterPos);
        std::string temp_p = line.substr(delimiterPos + delimiter.length());
        temp_p.erase(temp_p.find_last_not_of("\r\n") + 1);
        credentialsMap[temp_u] = temp_p;
    }
    inputFile.close();
    printf("Main Server loaded the member list.\n");
    return 0;
}

// Check if the bookcode start with S,L,H
bool isValidQuery(const char* str) {
    if (str == nullptr || str[0] == '\0') {
        return false;
    }
    char firstChar = str[0];
    return (firstChar == 'S' || firstChar == 'L' || firstChar == 'H');
}



int main()
{
    // Initialize TCP socket.(codes copied from Beej's tutorial)
    // TCP variables
    int tcp_sockfd, child_fd, numbytes,len_recv; 
    struct addrinfo hints, *servinfo, *p;
    struct sockaddr_storage their_addr;
    socklen_t sin_size;
    struct sigaction sa;
    int yes=1;
    int no=0;
    int notFound=2;
    int libNotExist = -2;
    char s[INET6_ADDRSTRLEN];
    int rv;
    char clientmsg[MAXDATASIZE];
    char* username;
    char* password;
    

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; 

    if ((rv = getaddrinfo(LOCALHOST, MY_TCP_PORT, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    // loop through all the results and bind to the first we can
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((tcp_sockfd = socket(p->ai_family, p->ai_socktype,
                p->ai_protocol)) == -1) {
            perror("server: socket");
            continue;
        }

        if (setsockopt(tcp_sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
                sizeof(int)) == -1) {
            perror("setsockopt");
            exit(1);
        }

        if (bind(tcp_sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(tcp_sockfd);
            perror("server: bind");
            continue;
        }

        break;
    }

        freeaddrinfo(servinfo); // all done with this structure

    if (p == NULL)  {
        fprintf(stderr, "server: failed to bind\n");
        exit(1);
    }

    if (listen(tcp_sockfd, BACKLOG) == -1) {
        perror("listen");
        exit(1);
    }

    sa.sa_handler = sigchld_handler; // reap all dead processes
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("sigaction");
        exit(1);
    }
    // TCP socket initialization done.

	// Prepare UDP socket for communication with backend servers.(codes copied from Beej's tutorial)
	int udp_sockfd;
	struct addrinfo udp_hints, *udp_servinfo, *udp_p;
	int udp_rv;
	struct sockaddr_storage udp_their_addr;
	int fromBackend;
	socklen_t udp_addr_len;
	char udp_s[INET6_ADDRSTRLEN];

	memset(&udp_hints, 0, sizeof udp_hints);
	udp_hints.ai_family = AF_UNSPEC; 	// set to AF_INET to force IPv4
	udp_hints.ai_socktype = SOCK_DGRAM;
	udp_hints.ai_flags = AI_PASSIVE;	 // use my IP

	if ((udp_rv = getaddrinfo(LOCALHOST, MY_UDP_PORT, &udp_hints, &udp_servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(udp_rv));
		return 1;
	}

	// loop through all the results and bind to the first we can
	for(udp_p = udp_servinfo; udp_p != NULL; udp_p = udp_p->ai_next) {
		if ((udp_sockfd = socket(udp_p->ai_family, udp_p->ai_socktype,
				udp_p->ai_protocol)) == -1) {
			perror("listener: socket");
			continue;
		}

		if (bind(udp_sockfd, udp_p->ai_addr, udp_p->ai_addrlen) == -1) {
			close(udp_sockfd);
			perror("listener: bind");
			continue;
		}

		break;
	}

	if (udp_p == NULL) {
		fprintf(stderr, "listener: failed to bind socket\n");
		return 2;
	}

	freeaddrinfo(udp_servinfo);

	// UDP clients

	struct addrinfo hintsS, *servinfoS, *processS;
    struct addrinfo hintsL, *servinfoL, *processL;
    struct addrinfo hintsH, *servinfoH, *processH;
	int error;

	memset(&hintsS, 0, sizeof hintsS);
	hintsS.ai_family = AF_UNSPEC;
	hintsS.ai_socktype = SOCK_DGRAM;
    memset(&hintsL, 0, sizeof hintsL);
	hintsL.ai_family = AF_UNSPEC;
	hintsL.ai_socktype = SOCK_DGRAM;
    memset(&hintsH, 0, sizeof hintsH);
	hintsH.ai_family = AF_UNSPEC;
	hintsH.ai_socktype = SOCK_DGRAM;

	if ((error = getaddrinfo(LOCALHOST, S_UDP_PORT, &hintsS, &servinfoS)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(error));
		return 1;
	}
    if ((error = getaddrinfo(LOCALHOST, L_UDP_PORT, &hintsL, &servinfoL)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(error));
		return 1;
	}
    if ((error = getaddrinfo(LOCALHOST, H_UDP_PORT, &hintsH, &servinfoH)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(error));
		return 1;
	}
    processS = servinfoS;
    processL = servinfoL;
    processH = servinfoH;

    printf("Main Server is up and running.\n");

    // Load Memebers' credentials
    loadMembers();

    while(1) { 

        //accept message from client.(codes copied from Beej's tutorial)
        sin_size = sizeof their_addr;
		child_fd = accept(tcp_sockfd, (struct sockaddr *)&their_addr, &sin_size);
        if (child_fd == -1) {
			perror("accept");
			continue;
		}

		inet_ntop(their_addr.ss_family,
			get_in_addr((struct sockaddr *)&their_addr),
			s, sizeof s);

        if (!fork()) { // this is the child process
            close(tcp_sockfd); // child doesn't need the listener
			if ((numbytes = recv(child_fd, clientmsg, MAXDATASIZE-1, 0)) == -1) {
				perror("recv");
				exit(1);
			}
            
            
            if(strlen(clientmsg) == 0 ) {
                // null message received when user logout
                // do nothing
            }
            
            // Process Book Query
            /* Situations:
             * 1. No Library --> return -2
             * 2. Send to backend, no book --> return -1
             * 3. Send to backend, no inventory --> return 0
             * 4. Send to backend, success --> return the #inventory
             */
            
            else if(strlen(clientmsg) < 12){
                std::cout << "Main Server received the book request from client using TCP over port " << MY_TCP_PORT <<"."<< std::endl;
                std::string decodedBookcode( clientmsg );
                decodedBookcode.pop_back();
                // std::cout << "Received data: " << clientmsg << std::endl;
                if(!isValidQuery(clientmsg)){
                    std::cout << "Did not find " << decodedBookcode << " in the book code list." << std::endl;
                    if (send(child_fd, &libNotExist, sizeof(libNotExist), 0) == -1) perror("send");
                } else{
                    if(clientmsg[0]=='S'){
                        std::cout << "Found " << decodedBookcode << " located at Server S. Send to Server S." << std::endl;
                        if ((numbytes = sendto(udp_sockfd, clientmsg, strlen(clientmsg), 0,
                        processS->ai_addr, processS->ai_addrlen)) == -1) {
                            perror("talker: sendto");
                            exit(1);
                    }
                    if ((numbytes = recvfrom(udp_sockfd, &fromBackend, MAXDATASIZE-1 , 0,
                        (struct sockaddr *)&udp_their_addr, &udp_addr_len)) == -1) {
                        perror("recvfrom");
                        exit(1);
                    } 
                    freeaddrinfo(servinfoS);
                    if(fromBackend<0){
                        std::cout << "Did not find " << decodedBookcode << " in the book code list." << std::endl;
                    } else {
                        std::cout << "Main Server received from server S the book status result using UDP over port 44026:" << std::endl<<"Number of books "<< decodedBookcode << " available is: " << fromBackend<<"."<< std::endl;
                    }
                    if (send(child_fd, &fromBackend, sizeof(fromBackend), 0) == -1) perror("send");
                    printf("Main Server sent the book status to the client.\n");
                    }
                    if(clientmsg[0]=='L'){
                        std::cout << "Found " << decodedBookcode << " located at Server L. Send to Server L." << std::endl;
                        if ((numbytes = sendto(udp_sockfd, clientmsg, strlen(clientmsg), 0,
                        processL->ai_addr, processL->ai_addrlen)) == -1) {
                            perror("talker: sendto");
                            exit(1);
                    }
                    if ((numbytes = recvfrom(udp_sockfd, &fromBackend, MAXDATASIZE-1 , 0,			//wait for the incoming packets
                        (struct sockaddr *)&udp_their_addr, &udp_addr_len)) == -1) {
                        perror("recvfrom");
                        exit(1);
                    } 
                    freeaddrinfo(servinfoL);
                    if(fromBackend<0){
                        std::cout << "Did not find " << decodedBookcode << " in the book code list." << std::endl;
                    } else {
                        std::cout << "Main Server received from server L the book status result using UDP over port 44026:" << std::endl<<"Number of books "<< decodedBookcode << " available is: " << fromBackend<<"."<< std::endl;
                    }                    
                    if (send(child_fd, &fromBackend, sizeof(fromBackend), 0) == -1) perror("send");
                    printf("Main Server sent the book status to the client.\n");
                    }
                    if(clientmsg[0]=='H'){
                        std::cout << "Found " << decodedBookcode << " located at Server H. Send to Server H." << std::endl;
                        if ((numbytes = sendto(udp_sockfd, clientmsg, strlen(clientmsg), 0,
                        processH->ai_addr, processH->ai_addrlen)) == -1) {
                            perror("talker: sendto");
                            exit(1);
                    }
                    if ((numbytes = recvfrom(udp_sockfd, &fromBackend, MAXDATASIZE-1 , 0,
                        (struct sockaddr *)&udp_their_addr, &udp_addr_len)) == -1) {
                        perror("recvfrom");
                        exit(1);
                    } 
                    freeaddrinfo(servinfoH);
                    if(fromBackend<0){
                        std::cout << "Did not find " << decodedBookcode << " in the book code list." << std::endl;
                    } else {
                        std::cout << "Main Server received from server H the book status result using UDP over port 44026:" << std::endl<<"Number of books "<< decodedBookcode << " available is: " << fromBackend<<"."<< std::endl;
                    }                    
                    if (send(child_fd, &fromBackend, sizeof(fromBackend), 0) == -1) perror("send");
                    printf("Main Server sent the book status to the client.\n");
                    }

                }

            }   
            // Process Login
            else {
                std::cout << "Main Server received the username and password from the client using TCP over port " << MY_TCP_PORT <<"."<< std::endl;
                splitWords(clientmsg, username, password);

                std::cout << "Received username: " << username << std::endl;
                std::cout << "Received password: " << password << std::endl;

                std::string inputUsername(username);
                std::string inputPassword(password);

                // Compare with map entries
                auto it = credentialsMap.find(inputUsername);
                if (it != credentialsMap.end() && it->second == inputPassword) {
                    std::cout << "Password "<< password <<" matches the username. Send a reply to the client." << std::endl;
                    if (send(child_fd, &yes, sizeof(yes), 0) == -1) {
                        perror("send");
                    }
                } else {
                    if (it == credentialsMap.end()) {
                        // Username not found
                        std::cout << username << " is not registered. Send a reply to the client." << std::endl;
                        if (send(child_fd, &notFound, sizeof(notFound), 0) == -1) {
                            perror("send");
                        }
                    } else {
                        // Incorrect password
                        std::cout << "Password "<< password <<" does not match the username. Send a reply to the client." << std::endl;
                        if (send(child_fd, &no, sizeof(no), 0) == -1) {
                            perror("send");
                        }
                    }
                }

            }
        
            close(child_fd);
            exit(0);
        }
        close(child_fd);  // parent doesn't need this


     }
    close(tcp_sockfd);
    close(udp_sockfd);
    return 0;
}

// g++ -std=c++11 -o serverM serverM.cpp
// ./serverM