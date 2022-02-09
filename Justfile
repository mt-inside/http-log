default:
	@just --list

run-daemon *ARGS:
	go run ./cmd/http-log {{ARGS}}

certpair:
	openssl req -x509 -days 1 -nodes -newkey rsa:2048 -keyout server.key -out server.crt -subj "/CN=example.com" -addext "subjectAltName=DNS:example.com"
