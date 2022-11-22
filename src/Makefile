INCLUDE = -I ./include
GCCFLAGS = -g --std=c11 -O3 -Wall -Wextra -Werror -fsanitize=address -pedantic -pedantic-errors -D_POSIX_C_SOURCE=200112L -D__BSD_VISIBLE=1 -Wno-unused-parameter -Wno-implicit-fallthrough $(INCLUDE)
LDFLAGS = -pthread -lrt
UTILS = ./logger/logger.c ./utils/util.c ./buffer/buffer.c ./hello/hello.c ./auth/auth.c ./selector/selector.c ./socks5/socks5nio.c ./stm/stm.c ./args.c ./request/request.c ./utils/socks_utils.c ./manager_protocol/alpha.c ./manager_protocol/alpha_manager.c ./pop3/sniffer.c ./utils/statistics_utils.c

all: main

main: 
	$(CC) $(LDFLAGS) $(GCCFLAGS) -o socks5d main.c $(UTILS)
	$(CC) $(LDFLAGS) $(GCCFLAGS) -o alpha_manager alpha_manager_client.c $(UTILS)

clean:
	rm -rf socks5d alpha_manager valgrind_socks5.txt
	rm -rf ./check

check:
	mkdir -p check
	cppcheck --quiet --enable=all --force --inconclusive . 2> ./check/cppout.txt

	pvs-studio-analyzer credentials PVS-Studio Free FREE-FREE-FREE-FREE
	pvs-studio-analyzer trace -- make
	pvs-studio-analyzer analyze
	plog-converter -a '64:1,2,3;GA:1,2,3;OP:1,2,3' -t tasklist -o ./check/report.tasks ./PVS-Studio.log

	rm PVS-Studio.log
	mv strace_out check

	valgrind --leak-check=yes --show-leak-kinds=all --track-origins=yes --verbose --log-file=valgrind_socks5.txt ./socks5d 


.PHONY: all clean check