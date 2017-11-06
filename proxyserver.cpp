// Homework 2 - Proxy Server
// Class: 5510 Computer Networks
// Greg Netzel, Elizabeth Phippen, Brandi Weekes

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
#include <string>
#include <iostream>
#include <vector>
#include <sstream>
using namespace std;

#define MAXDATASIZE 100 // max number of bytes we can get at once

#define BACKLOG 30     // how many pending connections queue will hold


void* runClient(void* threadInfo);
bool validRequest(string message);
string getHost(string message);
string getRelativeURI(string message, string host);
string getOtherFields(string message);
string formatRequest(string host, string relURI, string otherLines);
void *get_in_addr(struct sockaddr *sa);
struct addrinfo* create_and_bind_socket(struct addrinfo *servinfo_list, int& sockfd, int& yes);
struct addrinfo* create_socket_and_connect(struct addrinfo *proxyinfo_list, int& sockfd);
void sigchld_handler(int s);
void print_success_client_IP(struct sockaddr_storage &client_addr);
string recv_message(int sock_fd);
void send_message(int newfd, string msg, int msgLength);
void runRequest(int clientSocket);
string runServerRequest(string clientReq);
string runClientRequest(string clientRequest);

struct info{
	int newSock_fdesc; 
};

int main(int argNum, char* argValues[]){
	int host_sock_fdesc, newSock_fdesc;//, server_fdesc;  // listen on sock_fd, new connection on new_fd, server fd
	struct addrinfo host_info, *host_info_list, *socket_bind; //*socket_bind_remote;
	struct sockaddr_storage clientRequest_addr; // connector's address information
	socklen_t sin_size;
	struct sigaction sa;
	int yes=1;
	char s[INET6_ADDRSTRLEN];
	int rv;
	struct info threadInfo;


	if (argNum != 2){
		// Incorrect number of arguments
		cerr << "Incorrect number of arguments. Please try again." << endl;
		return -1;
	}
	//learn server address and port
	memset(&host_info, 0, sizeof host_info);
	host_info.ai_family = AF_UNSPEC;
	host_info.ai_socktype = SOCK_STREAM;
	host_info.ai_flags = AI_PASSIVE; // use my IP

	if ((rv = getaddrinfo(NULL, argValues[1], &host_info, &host_info_list)) != 0){
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return 1;
	}

	//prepare the socket: create and bind
	socket_bind = create_and_bind_socket(host_info_list, host_sock_fdesc, yes);

	freeaddrinfo(host_info_list); // all done with this structure

	if (socket_bind == NULL){
		fprintf(stderr, "server: failed to bind\n");
		exit(1);
	}

	//listen
	if (listen(host_sock_fdesc, BACKLOG) == -1){
		perror("listen");
		exit(1);
	}


	//accept
	while(1){
		sin_size = sizeof clientRequest_addr;
		newSock_fdesc = accept(host_sock_fdesc, (struct sockaddr *)&clientRequest_addr, &sin_size);
		if (newSock_fdesc == -1){
			perror("accept");
			return 1;
		}
		struct info* thrInfo = new info;
		thrInfo->newSock_fdesc = newSock_fdesc;
		pthread_t tid;
		int threadStatus = pthread_create(&tid, NULL, runClient, (void*)thrInfo);
		if (threadStatus != 0){
		  // Failed to create child thread
		  cerr << "Failed to create child process." << endl;
		  close(newSock_fdesc);
		  pthread_exit(NULL);
		}
	}

	close(host_sock_fdesc); 
	return 0;
}

void* runClient( void* threadInfo ){
	info* temp = (info*)threadInfo;
	int clientSock_fdesc = temp->newSock_fdesc;
	delete temp;
	
	pthread_detach(pthread_self());
	
	runRequest(clientSock_fdesc);
	
	close(clientSock_fdesc); 
	
	pthread_exit(NULL);
}

void runRequest(int clientSocket){
	// get client request
	string clientRequest = recv_message(clientSocket);
	string serverResponse;
	if(!validRequest(clientRequest)){
		send_message(clientSocket, "Error 500", 9);
	}
	else{
		serverResponse = runClientRequest(clientRequest);
	}
	send_message(clientSocket, serverResponse, serverResponse.length());
}

string runClientRequest(string clientRequest){
	struct addrinfo host_info;
	struct addrinfo *host_info_list;
	struct addrinfo *socket_bind_remote;
	int rv;
	int server_fdesc;
	string host = getHost(clientRequest);
	string relURI = getRelativeURI(clientRequest, host);
	string serverRequest = formatRequest(host, relURI, getOtherFields(clientRequest));
	string defPort = "80";
	
	// send request to server
	memset(&host_info, 0, sizeof host_info);
	host_info.ai_family = AF_UNSPEC;
	host_info.ai_socktype = SOCK_STREAM;

	
	if ((rv = getaddrinfo(host.c_str(), defPort.c_str(), &host_info, &host_info_list)) != 0){
		//fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return "Unknown Host\n";
	}

	//create socket and connect to remote server
	socket_bind_remote = create_socket_and_connect(host_info_list, server_fdesc);

	if (socket_bind_remote == NULL){
		fprintf(stderr,"Could not connect\n");
		exit(1);
	}
	freeaddrinfo(host_info_list);

	//send message to remote server
	send_message(server_fdesc, serverRequest, serverRequest.length());
	// get response
	string serverResponse = recv_message(server_fdesc);
	//cout << serverRequest << endl;
	//cout << serverResponse << endl;
	close(server_fdesc);
	return serverResponse;
}

// check for valid request
// GET AbsoluteURI HTTP/1.0
bool validRequest(string message){
	// can only process GET messages
	if(message.find("GET ") == string::npos){
		return false;
	}
	// must have HTTP/1.0 at end
	if(message.find(" HTTP/1.0")+11 == string::npos ||
		message.find(" HTTP/1.1")+11 == string::npos){
		return false;
	}
	return true;
}

// gets host from message
// http://www.host.com/relURI HTTP
string getHost(string message){
	string host = "";
	string temp = "";

	// www.host.com/relURI
	temp.append(message, message.find("://")+3,
				message.find(" HTTP") - (message.find("://")+3));

	// www.host.com
	if(temp.find('/') != string::npos){
		host.append(temp, 0, temp.find('/'));
	}
	else{
		host = temp;
	}

	return host;
}

string getOtherFields(string message){
	vector<string> lst;
	int pos;
	string del = "\r\n";
	string ret = message.substr(message.find("User-Agent"));
	while((pos =ret.find(del))!= string::npos){
		lst.push_back(ret.substr(0, pos));
		ret.erase(0, pos + del.length());
	}
	ret = "";
	string it;
	for (int i = 0; i < lst.size(); i++){
		it = lst.at(i);
		if (it.find("Connection") == string::npos ){//ignore connection
			if (it.find("Accept-Encoding") == string::npos){ //ignore encoding
				ret += it + "\r\n";
			}
		}
	}
	return ret;
}

string getRelativeURI(string message, string host){
	string relURI;

	int start = message.find(host);
	int len = message.find("HTTP") - 1 - start- host.length();
	relURI = message.substr(start+host.length(), len);

	if(relURI.find('/') == string::npos){// no uri present in message
		relURI = '/';
	}

	return relURI;
}

// formats server request
string formatRequest(string host, string relURI, string otherLines){
	string response = "GET " + relURI + " HTTP/1.0\r\n" + "Host: " + host + ":80" + "\r\n" + 
	+ "Connection: close\r\n" + otherLines + "\r\n\r\n";
	return response;
}

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa){
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

//proxy creates a socket and binds to local address and port number
struct addrinfo* create_and_bind_socket(struct addrinfo *servinfo_list, int& sockfd, int& yes){
	struct addrinfo* servinfo;
	// loop through all the results and bind to the first we can
	for(servinfo = servinfo_list; servinfo != NULL; servinfo = servinfo->ai_next){
		if ((sockfd = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol)) == -1){
			perror("proxy as server: socket");
			continue;
		}
		if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1){
			perror("setsockopt");
			exit(1);
		}
		if (bind(sockfd, servinfo->ai_addr, servinfo->ai_addrlen) == -1){
			close(sockfd);
			perror("proxy as server: bind");
			continue;
		}
		break;
	}
	return servinfo;
}

//proxy creates and socket and connects to remote server
struct addrinfo* create_socket_and_connect(struct addrinfo *proxyinfo_list, int& sockfd){
	struct addrinfo* proxyinfo;
	for(proxyinfo = proxyinfo_list; proxyinfo != NULL; proxyinfo = proxyinfo->ai_next)
	{
		if ((sockfd = socket(proxyinfo->ai_family, proxyinfo->ai_socktype, proxyinfo->ai_protocol)) == -1)
		{
			perror("proxy as client: socket");
			continue;
		}
		if (connect(sockfd, proxyinfo->ai_addr, proxyinfo->ai_addrlen) == -1){
			perror("proxy as client: connect");
			close(sockfd);
			continue;
		}
		break;
	}
	return proxyinfo;
}

void sigchld_handler(int s){
    // waitpid() might overwrite errno, so we save and restore it:
    int saved_errno = errno;

    while(waitpid(-1, NULL, WNOHANG) > 0);

    errno = saved_errno;
}

//prints IP address of successfully connected client to screen
void print_success_client_IP(struct sockaddr_storage &client_addr){
  char s[INET6_ADDRSTRLEN];

  inet_ntop(client_addr.ss_family,
      get_in_addr((struct sockaddr *)&client_addr),
      s, sizeof s);
  printf("server: got connection from %s\n", s);
}

//uses a loop to receive message from client, returns a message as string
string recv_message(int sock_fd){	
	stringstream ss;
	int bufferSize = 1000; 
	int totalSize = 0;
	int bytesRecv;
	char* buffer = new char[bufferSize];
	char* buffPTR = buffer;
	memset(buffPTR, '\0', bufferSize);
	
	// Handle communications
	while (true) {
		bytesRecv = recv(sock_fd, (void*) buffPTR, bufferSize, 0);
		if (bytesRecv < 0) {
			cerr << "Error occured while trying to receive data." << endl;	
			close(sock_fd);
			pthread_exit(NULL);	
		} 
		else if (bytesRecv == 0) {
			break;
		} 
		else {
			totalSize += bytesRecv;
			for (int i = 0; i < bytesRecv; i++) {
				ss << buffPTR[i];
			}
			if (totalSize > 4 ){
				string tmpMsg = ss.str();
				if (tmpMsg[tmpMsg.length()-4] == '\r'&& tmpMsg[tmpMsg.length()-3] == '\n'
				&& tmpMsg[tmpMsg.length()-2] == '\r'&& tmpMsg[tmpMsg.length()-1] == '\n') {
					break;
				}
			}
		}
	}
	return ss.str();
}

//sends message to client
void send_message(int newfd, string msg, int msgLength){
  int num_bytes_send = 0;
  char buf[msgLength];
  memcpy(buf, msg.c_str(), msgLength);

  while(num_bytes_send != msgLength)
	  num_bytes_send = send(newfd, &buf, msgLength, 0);
}
