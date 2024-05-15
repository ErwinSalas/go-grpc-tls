cert:
	openssl genrsa -out ./cert/server.key 2048

	openssl req -nodes -new -x509 -sha256 -days 1825 -config ./cert/certificate.conf -extensions 'req_ext' -key ./cert/server.key -out ./cert/server.crt
