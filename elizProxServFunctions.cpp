
bool validRequest(string message);
string getHost(string message);
string getRelativeURI(string message, string host);
string formatRequest(string host, string relURI);


int main(int argNum, char* argValues[]){
	
	if (argNum != 2){
		// Incorrect number of arguments
		cerr << "Incorrect number of arguments. Please try again." << endl;
		return -1;
	}
	
	//create socket
	
	//listen
	
	//accept
	
	string clientRequest = "";
	
	// get client request
	
	if(!validRequest(clientRequest)){
		// send 500 error to client
	}else{
		string host = getHost(clientRequest);
		string relURI = getRelativeURI(clientRequest, host);
		string serverRequest = formatRequest(host, relURI);
		
		// send request to server
		
		// get response
		
		// send response to client
	}

	return 0;
}

// check for valid request
// GET AbsoluteURI HTTP/1.0
bool validRequest(string message){
	// can only process GET messages
	if(message.find("GET ") != 0){
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
	string relURI = "";
	
	relURI.append(message, message.find(host)+host.length(), 
				message.find(" HTTP") - message.find(host)+host.length());
	// no uri present in message
	if(relURI.find('/') == string::npos){
		relURI = '/';
	}
	
	return relURI;
}

// formats server request
string formatRequest(string host, string relURI){
	
	string response = "GET " + relURI + " HTTP\r\n" +
		"Host: " + host + "\r\n\r\n";
		
	return response;
}

