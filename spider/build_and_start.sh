docker build -f Dockerfile -t fictional-goggles:spider .
docker run --rm -e FRICTIONAL_GOGGLES_IP="$(hostname -I | awk '{print $1}'):8081" fictional-goggles:spider
