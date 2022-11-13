###############################
# ISA proj 1
# Login: xvlkja07
# ###############################

CC=gcc
CFLAG=
exec=dns_receiver
login=xvlkja07
NAME=manual
SHELL=/usr/bin/env bash
FILES=*.cpp *.hpp Makefile manual.pdf flow.1 README.md

all: $(exec)

$(exec): dns.o common.o server.o dns_receiver_events.o base16.o
	$(CC) $(CFLAG) $^ -o $@ $(LDLIBS)

#### Object files
%.o: %.c
	$(CC) $(CFLAG) -c $^

#### MISC
clean:
	rm -f *.o $(exec)
	rm -f $(NAME).{aux,out,dvi,ps,log,te~,bcf,xml}

tar:
	tar -cf $(login).tar $(FILES)

zip:
	zip $(login).zip $(FILES)
