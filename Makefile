EXEC=resilient

CFLAGS=-Wall -Wextra

all: $(EXEC)

y.tab.c y.tab.h: config.yacc
	yacc -d $<

lex.yy.c: config.lex y.tab.h
	flex $<

lex.yy.o: lex.yy.c
y.tab.o: y.tab.c

resilient: resilient.o lex.yy.o y.tab.o
	$(CC) $(CFLAGS) -pthread -o $@ $^ -lssh

install:
	cp resilient.service /etc/systemd/system

clean:
	rm -f $(EXEC) *.o lex.yy.c y.tab.c y.tab.h

.PHONY: install clean
