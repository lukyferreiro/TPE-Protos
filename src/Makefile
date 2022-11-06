INCLUDE = -I ./include
GCC = gcc
#-pedantic -pedantic-errors -O3 -std=c11 -fsanitize=address -lrt -Werror -Wno-pointer-arith
GCCFLAGS = -g -Wall -Wextra -D_POSIX_C_SOURCE=200112L -Wno-unused-parameter -Wno-implicit-fallthrough $(INCLUDE) 
LDFLAGS = -pthread
UTILS=./logger/logger.c ./netutils/util.c ./netutils/tcpServerUtil.c ./netutils/tcpClientUtil.c

all: main

main: 
	$(GCC) $(LDFLAGS) $(GCCFLAGS) -o tcpServer tcpServer.c $(UTILS)

clean:
	rm -rf tcpServer

check:
	mkdir -p check
	cppcheck --quiet --enable=all --force --inconclusive . 2> ./check/cppout.txt

	pvs-studio-analyzer trace -- make
	pvs-studio-analyzer analyze
	plog-converter -a '64:1,2,3;GA:1,2,3;OP:1,2,3' -t tasklist -o ./check/report.tasks ./PVS-Studio.log

	rm PVS-Studio.log
	mv strace_out check

.PHONY: all clean check