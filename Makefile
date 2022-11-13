###############################
# ISA proj 1
# Login: xplagi0b
###############################

CC=gcc
CFLAG=
LDLIBS=-lpcap
exec=flow
login=xvlkja07
NAME=manual
SHELL=/usr/bin/env bash
FILES=manual.pdf Makefile dnstest.sh
FOLDERS=reciver/ sender/

all:
	cd reciver/ ; make
	cp reciver/dns_receiver .
	cd sender/ ; make
	cp sender/dns_sender .

reciver:
	cd reciver/ ; make
	cp reciver/dns_receiver .

sender:
	cd sender/ ; make
	cp sender/dns_sender .

clean:
	cd reciver/ ; make clean
	cd reciver/ ; make clean
	rm $(login).tar
	rm -f $(NAME).{aux,out,dvi,ps,log,te~,bcf,xml}


latex:
	cd doc/ ; pdflatex main.tex

tar:
	tar -cf $(login).tar $(FILES) $(FOLDERS)


