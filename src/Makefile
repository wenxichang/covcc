COVCC_FILES = covcc.c ac_lexer.c cov_inject.c
COVREADER_FILES = cov_reader.c hash.c cov_kcore.c cov_cobertuna.c

CFLGAS += -Wall -g
LDFLAGS +=
PREFIX ?= /usr/local/bin

.PHONY:all clean install

all: covcc cov_reader

covcc: $(COVCC_FILES)
	gcc $(CFLGAS) -o covcc $(COVCC_FILES) $(LDFLAGS)

cov_reader: $(COVREADER_FILES)
	gcc $(CFLGAS) -o cov_reader $(COVREADER_FILES) $(LDFLAGS)

clean:
	rm -f covcc cov_reader

install:
	install -m 0755 -v covcc cov_reader $(PREFIX)
