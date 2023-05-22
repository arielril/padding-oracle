GOCMD=go
GOBUILD=$(GOCMD) build
GOMOD=$(GOCMD) mod
BINARY=pad-oracle
GOHOME?=~/go

all: clean tidy build

build:
	env GOARCH=arm64 $(GOBUILD) -v -ldflags="-extldflags=-static" -o ${BINARY} cmd/paddingoracle/paddingoracle.go


build-linux:
	env GOOS=linux GOARCH=arm64 $(GOBUILD) -v -ldflags="-extldflags=-static" -o ${BINARY} cmd/paddingoracle/paddingoracle.go

move-bin-linux: 
	mv ${BINARY} ${GOHOME}/bin/${BINARY}

tidy:
	$(GOMOD) tidy

clean:
	rm -f ${BINARY}

