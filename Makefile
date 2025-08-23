BUILD_DIR=./build
BINARY=${BUILD_DIR}/keygloak

build:
	GOARCH=amd64 GOOS=darwin go build -o ${BINARY}-darwin_amd64 .
	GOARCH=amd64 GOOS=linux go build -o ${BINARY}-linux_amd64 .
	GOARCH=amd64 GOOS=windows go build -o ${BINARY}-windows_amd64 .

clean:
	go clean
	rm -rf ${BUILD_DIR}

