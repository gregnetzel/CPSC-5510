#include<iostream>
#include<sstream>
#include<string>
#include<cstring>
#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<unistd.h>
#include<netdb.h>
#include<pthread.h>
#include<tr1/unordered_map>
#include<ctime>
#include<errno.h>
#include<vector>
#include<cstdlib>
#include <csignal>

using namespace std;

// Data Structures
struct sockAddr {
  unsigned short sa_family; // Address family (AF_INET)
  char sa_data[14]; // Protocol-specific addressinfo
};

struct in_address {
  unsigned long s_addr; // Internet Address (32bits)
};

struct sockAddress_in {
  unsigned short sin_family; // Address family (AF_INET)
  unsigned short sin_port; // Port (16bits)
  struct in_addr sin_addr; // Internet address structure
  char sin_zero[8]; // Not Used.
};

struct threadArgs {
  int clientSock;
};

// Globals
const int MAXPENDING = 25;
unsigned short serverPort; 

void* clientThread(void* args_p);

void runServerRequest(int clientSock);

string getCacheControl(string httpMsg);

bool SendMessageStream(int hostSock, string Msgss);

string GetMessageStream(int clientSock, bool isHost);

string HostProcessing (string clientMsg);

//string getErrorMsg();


int main(int argNum, char* argValues[]) {

  vector<int> socketList;
  
  // Need to grab Command-line arguments and convert them to useful types
  // Initialize arguments with proper variables.
  if (argNum != 2){
    // Incorrect number of arguments
    cerr << "Incorrect number of arguments. Please try again." << endl;
    return -1;
  }

  // Need to store arguments
  serverPort = atoi(argValues[1]);

  // Create socket connection
  int conn_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (conn_socket < 0){
    cerr << "Error with socket." << endl;
    exit(-1);
  }

  // Set the socket Fields
  struct sockaddr_in serverAddress;
  serverAddress.sin_family = AF_INET; // Always AF_INET
  serverAddress.sin_addr.s_addr = htonl(INADDR_ANY);
  serverAddress.sin_port = htons(serverPort);
  
  // Assign Port to socket
  int sock_status = bind(conn_socket,
			 (struct sockaddr *) &serverAddress,
			 sizeof(serverAddress));
  if (sock_status < 0) {
    cerr << "Error with bind." << endl;
    exit(-1);
  }

  // Set socket to listen.
  int listen_status = listen(conn_socket, MAXPENDING);
  if (listen_status < 0) {
    cerr << "Error with listening." << endl;
    exit(-1);
  }
  
  // Accept connections
  while (true) {
    struct sockaddr_in clientAddress;
    socklen_t addrLen = sizeof(clientAddress);
    int clientSocket = accept(conn_socket, (struct sockaddr*) &clientAddress, &addrLen);
    if (clientSocket < 0) {
      cerr << "Error accepting connections." << strerror(errno) << endl;
      //break;
      continue;
    }
    // Create child thread to handle process
    struct threadArgs* args_p = new threadArgs;
    args_p -> clientSock = clientSocket;
    pthread_t tid;

	int threadStatus = pthread_create(&tid, NULL, clientThread, (void*)args_p);
	
    if (threadStatus != 0){
      // Failed to create child thread
      cerr << "Failed to create child process." << endl;
      close(clientSocket);
      pthread_exit(NULL);
    }
    
  }

  return 0;
}

void* clientThread(void* args_p){
  
  // Local Variables
  threadArgs* tmp = (threadArgs*) args_p;
  int clientSock = tmp -> clientSock;
  delete tmp;

  // Detach Thread to ensure that resources are deallocated on return.
  pthread_detach(pthread_self());

  // Communicate with Client
  runServerRequest(clientSock);
 
  // Close Client socket
  close(clientSock);

  // Quit thread
  pthread_exit(NULL);
}

void runServerRequest(int clientSock) {

  // Local Variables
  string requestMsg;
  string responseMsg;

  // Get Browser message
  requestMsg = GetMessageStream(clientSock, false);
  //cout << "\nrequest\n" << requestMsg;
  if(requestMsg[0] != 'G'){
	  responseMsg = "501 'Not Implemented' ";
  }else{
	  responseMsg = HostProcessing(requestMsg);
  }
  //cout << "response\n" << responseMsg;
  // Send back to Browser
  // Must use exception handling because browser can manually close connection.
  try {
  SendMessageStream(clientSock, responseMsg);
  } catch (...) {
    cerr << "Browser Closed Connection! " << endl;
    close(clientSock);
    pthread_exit(NULL);
  }
  // parse responseMsg for embedded objects
  // get embedded objects
  // send to browser
}

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

string HostProcessing (string clientMsg) {

  // Local Variables
  string responseMsg;
  struct hostent* host;
  struct sockAddress_in serverAddress;
  char* tmpIP;
  unsigned long hostIP;
  int status = 0;
  int hostSock;
  unsigned short hostPort = 80;
  string tmpMsg = clientMsg;
  string hostName = "";

  //parse host name
  hostName = getHost(tmpMsg);
  // Get Host IP Address
  host = gethostbyname(hostName.c_str());
  if (!host) {
    //cerr << "Unable to resolve hostname's IP Address. Exiting..." << endl;
    return "500 'Internal Error'";//getErrorMsg();
  }
  tmpIP = inet_ntoa(*(struct in_addr *)host ->h_addr_list[0]);

  status = inet_pton(AF_INET, tmpIP, (void*) &hostIP);
  if (status <= 0) return "500 'Internal Error'";//getErrorMsg();
  status = 0;

  // Establish socket and address to talk to Host
  hostSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  serverAddress.sin_family = AF_INET;
  serverAddress.sin_addr.s_addr = hostIP;
  serverAddress.sin_port = htons(hostPort);

  // Now we have the right information, let's open a connection to the host.
  status = connect(hostSock, (struct sockaddr *) &serverAddress, sizeof(serverAddress));
  if (status < 0) {
    cerr << "Error opening host connection." << endl;
    
    return "500 'Internal Error' ";
  }

  // Forward Message
  SendMessageStream(hostSock, clientMsg);
  
  // Receive Response
  responseMsg =  GetMessageStream(hostSock, true);

  close(hostSock);
  return responseMsg;
}

string GetMessageStream(int clientSock, bool isHost) {

  // Local Variables
  stringstream ss;
  int bufferSize = 1000; 
  int totalSize = 0;
  int bytesRecv;
  char* buffer = new char[bufferSize];
  char* buffPTR = buffer;
  time_t timer;
  time_t check;
  time(&timer);
  memset(buffPTR, '\0', bufferSize);

  // Handle communications
  while (true) {
    bytesRecv = recv(clientSock, (void*) buffPTR, bufferSize, 0);
    if (bytesRecv < 0) {
      cerr << "Error occured while trying to receive data." << endl;
      if (isHost) {
	return "500 'Internal Error' ";
      } else {
	close(clientSock);
	pthread_exit(NULL);
      }
    } else if (bytesRecv == 0) {
      break;
    } else {
      totalSize += bytesRecv;
      for (int i = 0; i < bytesRecv; i++) {
	ss << buffPTR[i];
      }
      if (totalSize > 4 && !isHost){
	string tmpMsg = ss.str();
	if (tmpMsg[tmpMsg.length()-4] == '\r'
	    && tmpMsg[tmpMsg.length()-3] == '\n'
	    && tmpMsg[tmpMsg.length()-2] == '\r'
	    && tmpMsg[tmpMsg.length()-1] == '\n') {
	  break;
	}
      }
      time(&check);
      if (difftime(check,timer) > 4) {
		  
	return "500 'Internal Error' ";
      }

    }
  }
  string tmpStr = ss.str();
  if (tmpStr.find("Connection: keep-alive") != string::npos)
    tmpStr.replace(tmpStr.find("Connection: keep-alive"), 24, "");
	delete[] buffer;
  return tmpStr;
}

bool SendMessageStream(int hostSock, string Msgss) {

  //Local
  string messageToSend = Msgss;
  int msgLength = messageToSend.length();
  int msgSent = 0;
  char *msgBuff = new char[msgLength];

  // Transfer message.
  memcpy(msgBuff, messageToSend.c_str(), msgLength);

  // Send message
  while (msgSent != msgLength) {
    msgSent = send(hostSock,(void*) msgBuff, msgLength, 0);
  }
  delete[] msgBuff;
  return true;
}