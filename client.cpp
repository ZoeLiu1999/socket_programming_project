#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <iostream>
#include <cstring>

#define MAXDATASIZE 200
#define LOCALHOST "127.0.0.1"
#define SERVER_TCP_PORT "45026"

// Client's Variable
std::string username, password, bookcode, copiedUsername, encodedBookcode;


// get sockaddr, IPv4 or IPv6: (copied from Beej's tutorial)
void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

// Ask for username and password and then store in the variables
void getUsernamePassword(std::string& username, std::string& password) {
    // Prompt the user for the username
    std::cout << "Please enter the username: ";
    std::getline(std::cin, username);

    // Prompt the user for the password
    std::cout << "Please enter the password: ";
    std::getline(std::cin, password);
}

// cipher the username and password based on the rule
void cipher(std::string& text) {
    for (char& currentChar : text) {
        if (currentChar >= 'A' && currentChar <= 'Z') {
            currentChar = 'A' + (currentChar - 'A' + 5) % 26;
        } else if (currentChar >= 'a' && currentChar <= 'z') {
            currentChar = 'a' + (currentChar - 'a' + 5) % 26;
        } else if (currentChar >= '0' && currentChar <= '9') {
            currentChar = '0' + (currentChar - '0' + 5) % 10;
        }
    }
}

// encode the username and the password to send it to the main server.
// len(username)+len(password)+ username + password
std::string encode(const std::string& str1, const std::string& str2) {
    int len = str1.length();
    int len2 = str2.length();
    std::string result;
    if(len<10) result+= "0";
    result.append(std::to_string(len));
    if(len2<10) result+= "0";
    result.append(std::to_string(len2));
    result += str1;
    result += str2;
    return result;
}

// Ask for bookcode and store it in the variable
void getBookCode(){
    std::cout << "Please enter book code to query: ";
    std::getline(std::cin, bookcode);
}




int main() {

    // initialize the TCP socket (copied from Beej's tutorial)
    int sockfd, numbytes;  
    char buf[MAXDATASIZE];
    struct addrinfo hints, *servinfo, *p;
    int rv;
    char s[INET6_ADDRSTRLEN];
    int recv_buf;
    int stage = 0; // indicate the the stage that user's at

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    printf("Client is up and running.\n");

    // Login stage
    while(stage==0){

        if ((rv = getaddrinfo(LOCALHOST, SERVER_TCP_PORT, &hints, &servinfo)) != 0) {
            fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
            return 1;
        }


        // loop through all the results and connect to the first we can
        for(p = servinfo; p != NULL; p = p->ai_next) {
            if ((sockfd = socket(p->ai_family, p->ai_socktype,
                    p->ai_protocol)) == -1) {
                perror("client: socket");
                continue;
            }

            if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
                close(sockfd);
                perror("client: connect");
                continue;
            }

            break;
        }

        if (p == NULL) {
            fprintf(stderr, "client: failed to connect\n");
            return 2;
        }

        // Get local port number (code inspired by the hint in the project guid)
        struct sockaddr_storage localAddr;
        socklen_t addrLen = sizeof localAddr;
        getsockname(sockfd, (struct sockaddr*)&localAddr, &addrLen);

        char localIP[INET6_ADDRSTRLEN];
        int localPort;

        if (localAddr.ss_family == AF_INET) {
            struct sockaddr_in* s = (struct sockaddr_in*)&localAddr;
            inet_ntop(AF_INET, &s->sin_addr, localIP, sizeof localIP);
            localPort = ntohs(s->sin_port);
        } else {
            struct sockaddr_in6* s = (struct sockaddr_in6*)&localAddr;
            inet_ntop(AF_INET6, &s->sin6_addr, localIP, sizeof localIP);
            localPort = ntohs(s->sin6_port);
        }

        inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr),s, sizeof s);
        freeaddrinfo(servinfo); // all done with this structure

        // Communicate with user
        getUsernamePassword(username, password);
        copiedUsername = username;
        cipher(username);
        cipher(password);

        // Prepare encoded msg to send to the main server
        std::string result = encode(username, password);

        // Send to the Main server
        if (send(sockfd, result.c_str(), result.size(), 0) == -1)
        perror("send");
        std::cout<<copiedUsername<<" sent an authentication request to the Main Server."<<std::endl;

        // Recieve from the Main server
        if ((numbytes = recv(sockfd, &recv_buf, MAXDATASIZE-1, 0)) == -1) {
            perror("recv");
            exit(1);
        }

        // Process the feedback
        if(recv_buf==0){
            std::cout << copiedUsername << " received the result of authentication from Main Server using TCP over port " << localPort <<"."<< std::endl<<"Authentication failed: Password does not match."<< std::endl;
        } else if(recv_buf==1){
            std::cout << copiedUsername << " received the result of authentication from Main Server using TCP over port " << localPort <<"."<< std::endl<<"Authentication is successful."<< std::endl;
            stage++; // proceed to Book Query stage
        } else{
            std::cout << copiedUsername << " received the result of authentication from Main Server using TCP over port " << localPort <<"."<< std::endl<<"Authentication failed: Username not found."<< std::endl;
        }
    } 

    // Book Query stage
    while(stage==1)
    {
        if ((rv = getaddrinfo(LOCALHOST, SERVER_TCP_PORT, &hints, &servinfo)) != 0) {
            fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
            return 1;
        }

        // loop through all the results and connect to the first we can
        for(p = servinfo; p != NULL; p = p->ai_next) {
            if ((sockfd = socket(p->ai_family, p->ai_socktype,
                    p->ai_protocol)) == -1) {
                perror("client: socket");
                continue;
            }

            if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
                close(sockfd);
                perror("client: connect");
                continue;
            }

            break;
        }
        if (p == NULL) {
            fprintf(stderr, "client: failed to connect\n");
            return 2;
        }
        inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr), s, sizeof s);
        freeaddrinfo(servinfo); // all done with this structure

        // Get local port number. (Codes inspired by the assignment guid)
        struct sockaddr_storage localAddr;
        socklen_t addrLen = sizeof localAddr;
        getsockname(sockfd, (struct sockaddr*)&localAddr, &addrLen);

        char localIP[INET6_ADDRSTRLEN];
        int localPort;

        if (localAddr.ss_family == AF_INET) {
            struct sockaddr_in* s = (struct sockaddr_in*)&localAddr;
            inet_ntop(AF_INET, &s->sin_addr, localIP, sizeof localIP);
            localPort = ntohs(s->sin_port);
        } else {
            struct sockaddr_in6* s = (struct sockaddr_in6*)&localAddr;
            inet_ntop(AF_INET6, &s->sin6_addr, localIP, sizeof localIP);
            localPort = ntohs(s->sin6_port);
        }

        // Communicate with the user
        getBookCode();

        // Encode the bookcode with user identity
        if(copiedUsername=="admin"){
            encodedBookcode = std::to_string(bookcode.length()+1) + bookcode + "A";
        } else {
            encodedBookcode = std::to_string(bookcode.length()+1) + bookcode + "U";
        }

        // Send to Main Server
        if (send(sockfd, encodedBookcode.c_str(), encodedBookcode.size(), 0) == -1)
        perror("send");
        if(copiedUsername=="admin"){
            printf("Request sent to the Main Server with Admin rights.\n");
        } else {
            std::cout << copiedUsername << " sent the request to the Main Server."<< std::endl;
        }
        
        // Recieve from the main server
        if ((numbytes = recv(sockfd, &recv_buf, MAXDATASIZE-1, 0)) == -1) {
            perror("recv");
            exit(1);
        }
        std::cout << "Response received from the Main Server on TCP port: " << localPort <<"."<< std::endl;

        // Process the feedback
        if(recv_buf>0){
            if(copiedUsername=="admin"){
                std::cout << "Total number of book " << bookcode <<" available = "<< recv_buf << std::endl << std::endl;
            } else {
                std::cout << "The requested book " << bookcode <<" is available in the library."<< std::endl << std::endl;
            }
            std::cout<< "—- Start a new query —-" << std::endl;
        } else if(recv_buf==0){
            if(copiedUsername=="admin"){
                std::cout << "Total number of book " << bookcode <<" available = "<< recv_buf << std::endl << std::endl;
            } else {
                std::cout << "The requested book " << bookcode <<" is NOT available in the library."<< std::endl << std::endl;
            }
            std::cout << "—- Start a new query —-" << std::endl;
        } else {
            std::cout << "Not able to find the book-code " << bookcode <<" in the system."<< std::endl << std::endl << "—- Start a new query —-" << std::endl;
        }
    }

    close(sockfd);

    
    return 0;
}


// g++ -std=c++11 -o client client.cpp
// ./client