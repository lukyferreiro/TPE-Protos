GCC=gcc
GCCFLAGS=-Wall -pedantic -fsanitize=address -g -lrt -pthread -Wno-implicit-fallthrough -Wextra -Werror -Wno-pointer-arith

SOURCES=$(wildcard src/*.c)
OUTPUT_FOLDER=./bin
OUTPUT_FILE=$(OUTPUT_FOLDER)/medias

all:
	mkdir -p $(OUTPUT_FOLDER)
	$(GCC) $(GCCFLAGS) $(SOURCES) -o $(OUTPUT_FILE)

clean:
	rm -rf $(OUTPUT_FOLDER)

check:
	mkdir -p check
	cppcheck --quiet --enable=all --force --inconclusive . 2> ./check/cppout.txt

	pvs-studio-analyzer trace -- make
	pvs-studio-analyzer analyze
	plog-converter -a '64:1,2,3;GA:1,2,3;OP:1,2,3' -t tasklist -o ./check/report.tasks ./PVS-Studio.log

	rm PVS-Studio.log
	mv strace_out check

.PHONY: all clean check