INCLUDE = -I ./include
GCC = gcc
#-pedantic -pedantic-errors -O3 -fsanitize=address -Werror -Wno-pointer-arith
GCCFLAGS = -g --std=c11 -Wall -Wextra -D_POSIX_C_SOURCE=200112L -Wno-unused-parameter -Wno-implicit-fallthrough $(INCLUDE) 
#-lrt
LDFLAGS = -pthread
UTILS = ./logger/logger.c ./utils/util.c ./utils/tcpServerUtil.c ./utils/tcpClientUtil.c ./buffer/buffer.c ./hello/hello.c ./parser/parser_utils.c ./parser/parser.c ./selector/selector.c ./socks5/socks5nio.c ./stm/stm.c ./args.c ./request/request.c ./utils/socks_utils.c ./manager_protocol/alpha.c ./manager_protocol/alpha_manager.c ./utils/user_utils.c

all: main

main: 
	$(GCC) $(LDFLAGS) $(GCCFLAGS) -o main main.c $(UTILS)
	$(GCC) $(LDFLAGS) $(GCCFLAGS) -o alpha_manager alpha_manager_client.c $(UTILS)

clean:
	rm -rf main tcpServer
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