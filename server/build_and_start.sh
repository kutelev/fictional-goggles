docker build -f Dockerfile -t fictional-goggles:server .
docker run --rm -it -p 8081:8081 fictional-goggles:server
