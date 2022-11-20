INCLUDE = -I ./include
GCC = gcc
#-pedantic -pedantic-errors
GCCFLAGS = -g --std=c11 -O3 -Wall -Wextra -Werror -fsanitize=address -D_POSIX_C_SOURCE=200112L -Wno-unused-parameter -Wno-implicit-fallthrough $(INCLUDE)
LDFLAGS = -pthread -lrt
UTILS = ./logger/logger.c ./utils/util.c ./buffer/buffer.c ./hello/hello.c ./auth/auth.c ./selector/selector.c ./socks5/socks5nio.c ./stm/stm.c ./args.c ./request/request.c ./utils/socks_utils.c ./manager_protocol/alpha.c ./manager_protocol/alpha_manager.c ./pop3/sniffer.c

all: main

main: 
	$(GCC) $(LDFLAGS) $(GCCFLAGS) -o main main.c $(UTILS)
	$(GCC) $(LDFLAGS) $(GCCFLAGS) -o alpha_manager alpha_manager_client.c $(UTILS)

clean:
	rm -rf main alpha_manager
	rm -rf ./check

check:
	mkdir -p check
	cppcheck --quiet --enable=all --force --inconclusive . 2> ./check/cppout.txt

	pvs-studio-analyzer trace -- make
	pvs-studio-analyzer analyze
	plog-converter -a '64:1,2,3;GA:1,2,3;OP:1,2,3' -t tasklist -o ./check/report.tasks ./PVS-Studio.log

	rm PVS-Studio.log
	mv strace_out check

.PHONY: all clean check