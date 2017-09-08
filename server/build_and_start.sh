docker build -f Dockerfile -t fictional-goggles:server .
docker run --rm -it -p 80:80 fictional-goggles:server
