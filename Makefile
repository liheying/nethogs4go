BINARY_NAME_ARM32=nethogs4go.arm32
BINARY_NAME_MIPSLE=nethogs4go.mipsle
BINARY_NAME_ARM64=nethogs4go.arm64
BINARY_NAME_X86=nethogs4go

APP_VERSION?=1.0.1
VERSION=v$(APP_VERSION)-test

PREFIX?=nethogs4go
# amd64 or arm64
SUBARCH:=$(shell uname -m | sed -e s/i.86/i386/ -e s/x86_64/amd64/ -e s/aarch64/arm64/ )
ARCH?=$(SUBARCH)
ifeq ($(MAKECMDGOALS), builddebarm)
	ARCH=arm64
endif

GIT_COMMIT=$(shell git rev-parse --short HEAD)
TIMETAG:=$(shell date +'%Y%m%d%H%M')
TAG:=$(APP_VERSION)-$(GIT_COMMIT)-$(TIMETAG)
ifeq ($(ARCH), arm64)
	TAG:=$(APP_VERSION)-$(GIT_COMMIT)-$(TIMETAG)-$(ARCH)
endif

APP_VER = $(shell git describe --tags --abbrev=0)

all:
	make clean;
	make buildx86;
	make buildarm32;
	make buildarm64;
	#make buildmipsle;

buildx86:
	CGO_ENABLED=1 GOOS=linux GOARCH=amd64 CGO_CFLAGS="-I`pwd`/common/libpcap/include" CGO_LDFLAGS="-L`pwd`/common/libpcap/lib/x86" go build -ldflags "-extldflags --static -s -w" -o $(BINARY_NAME_X86)
	upx --best --lzma $(BINARY_NAME_X86)

buildmipsle:
	CGO_ENABLED=0 GOOS=linux GOARCH=mipsle go build -ldflags "-s -w" -o $(BINARY_NAME_MIPSLE)
	upx --best --lzma $(BINARY_NAME_MIPSLE)

buildarm32:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build -ldflags "-s -w" -o $(BINARY_NAME_ARM32)
	upx --best --lzma $(BINARY_NAME_ARM32)

buildarm64:
	CGO_ENABLED=1 GOOS=linux GOARCH=arm64 GOARM=7 CGO_CFLAGS="-I`pwd`/common/libpcap/include" CGO_LDFLAGS="-L`pwd`/common/libpcap/lib/arm64" CC=aarch64-linux-gnu-gcc go build -ldflags "-extldflags --static -s -w" -o $(BINARY_NAME_ARM64)
	upx --best --lzma $(BINARY_NAME_ARM64)

clean:
	rm -f $(BINARY_NAME_X86) $(BINARY_NAME_ARM32) $(BINARY_NAME_ARM64)
	rm -f nethogs4go.*
