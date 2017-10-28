proxyMake: proxyserver.cpp
	g++ -pthread -o proxy proxyserver.cpp
	g++ ProxyServerPhase1.cpp -o proxyPhaseOne
