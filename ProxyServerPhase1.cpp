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
using namespace std;

#define MAXDATASIZE 100 // max number of bytes we can get at once

#define BACKLOG 30     // how many pending connections queue will hold


bool validRequest(string message);
string getHost(string message);
string getRelativeURI(string message, string host);
string formatRequest(string host, string relURI);
void *get_in_addr(struct sockaddr *sa);
struct addrinfo* create_and_bind_socket(struct addrinfo *servinfo_list, int& sockfd, int& yes);
void sigchld_handler(int s);
void print_success_client_IP(struct sockaddr_storage &client_addr);
string recv_message(int sock_fd);
void send_message(int newfd, string msg, int msgLength);


int main(int argNum, char* argValues[])
{
	int host_sock_fdesc, newSock_fdesc, server_fdesc;  // listen on sock_fd, new connection on new_fd, server fd
	struct addrinfo host_info, *host_info_list, *socket_bind;
	struct sockaddr_storage clientRequest_addr; // connector's address information
	socklen_t sin_size;
	struct sigaction sa;
	int yes=1;
	char s[INET6_ADDRSTRLEN];
	int rv;
	string clientRequest = "";

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

	// reap all dead processes
	sa.sa_handler = sigchld_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	if (sigaction(SIGCHLD, &sa, NULL) == -1){
		perror("sigaction");
		exit(1);
	}

	printf("server: waiting for connections...\n");

	//accept
	sin_size = sizeof clientRequest_addr;
	newSock_fdesc = accept(host_sock_fdesc, (struct sockaddr *)&clientRequest_addr, &sin_size);
	if (newSock_fdesc == -1){
		perror("accept");
		return 1;
	}
	print_success_client_IP(clientRequest_addr);

	// get client request
	// client_Message = recv_message(sockfd);
	
	clientRequest = recv_message(newSock_fdesc);
	
	if(!validRequest(clientRequest)){
		// send 500 error to client
		send_message(newSock_fdesc, "Error 500", 9);
	}
	else{
		string host = getHost(clientRequest);
		string relURI = getRelativeURI(clientRequest, host);
		string serverRequest = formatRequest(host, relURI);
		string defPort = "80";
		
		cout << "host: " << host << endl;
		cout << "relative: " << relURI << endl;
		cout << "request: " << serverRequest << endl;
		
		// send request to server
		memset(&host_info, 0, sizeof host_info);
		host_info.ai_family = AF_UNSPEC;
		host_info.ai_socktype = SOCK_STREAM;
		
		if ((rv = getaddrinfo(host.c_str(), defPort.c_str(), &host_info, &host_info_list)) != 0){
			fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
			send_message(newSock_fdesc, "Unknown Host\n", 13);
			return 1;
		}
		
		for(socket_bind = host_info_list; socket_bind != NULL; socket_bind = socket_bind->ai_next){
			if((server_fdesc = socket(socket_bind->ai_family, socket_bind->ai_socktype, socket_bind->ai_protocol)) == -1){
				perror("socket");
				continue;
			}
			if (connect(server_fdesc, socket_bind->ai_addr, socket_bind->ai_addrlen) == -1){
				perror("connect");
				close(server_fdesc);
				continue;
			}
			break;
		}
		if (socket_bind == NULL){
			fprintf(stderr,"Could not connect\n");
			exit(1);
		}
		freeaddrinfo(host_info_list);
		send_message(server_fdesc, serverRequest, serverRequest.length());
		// get response		
		string serverResponse = recv_message(server_fdesc);
		cout << "Server Response: " << serverResponse << endl;
		close(server_fdesc);
		// send response to client
		send_message(newSock_fdesc, serverResponse, serverResponse.length());
		close(newSock_fdesc);		
	}
	close(host_sock_fdesc);
	return 0;
}

// check for valid request
// GET AbsoluteURI HTTP/1.0
bool validRequest(string message){
	// can only process GET messages
	cout << message << endl;
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
				message.find(" HTTP") - message.find("://")+3);
	// www.host.com
	host.append(temp, 0, temp.find('/'));

	return host;
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
string formatRequest(string host, string relURI){
	string response = "GET " + relURI + " HTTP/1.1\r\n" +
		"Host: " + host + ":80" + "\r\n\r\n";
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
			perror("server: socket");
			continue;
		}
		if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1){
			perror("setsockopt");
			exit(1);
		}
		if (bind(sockfd, servinfo->ai_addr, servinfo->ai_addrlen) == -1){
			close(sockfd);
			perror("server: bind");
			continue;
		}
		break;
	}
	return servinfo;
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
	char buf[MAXDATASIZE];
	int num_bytes_recv = 0;
	int checkbytes = 0;
	string clientMessage = "";
	while((num_bytes_recv = recv(sock_fd, buf, MAXDATASIZE-1, 0)) > 0){
		if (num_bytes_recv > 2){
			checkbytes += num_bytes_recv;
			buf[num_bytes_recv] = '\0';
			clientMessage.append(buf);
		}
		else 				//just end line characters means last message was blank line
			break;
	}

	if (num_bytes_recv == -1){
		perror("recv");
		exit(1);
	}
  
	return clientMessage;
}

//sends message to client
void send_message(int newfd, string msg, int msgLength){
  int num_bytes_send = 0;
  char buf[msgLength];
  memcpy(buf, msg.c_str(), msgLength);

  while(num_bytes_send != msgLength)
	  num_bytes_send = send(newfd, &buf, msgLength, 0);
}
