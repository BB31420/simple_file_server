You need to generate a self-signed certificate and key with OpenSSL:

openssl req -x509 -newkey rsa:4096 -nodes -out server.crt -keyout server.key -days 365

This creates server.crt and server.key in your current directory

This script serves the application over HTTPS on port 8443. Access it via 
https://your-server-ip:8443

debug=True should be removed in production

This project is not complete. There are obvious pitfalls. Do not use 
