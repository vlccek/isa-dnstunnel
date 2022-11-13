###############################
# ISA proj 1
# Login: xvlkja07
# ###############################

CC=gcc
CFLAG=
exec=dns_sender
login=xvlkja07
NAME=manual

all: $(exec)

$(exec): dns.o common.o client.o dns_sender_events.o base16.o
	$(CC) $(CFLAG) $^ -o $@ $(LDLIBS)

#### Object filess
%.o: %.c
	$(CC) $(CFLAG) -c $^

#### MISC
clean:
	rm -f *.o $(exec)
	rm -f $(NAME).{aux,out,dvi,ps,log,te~,bcf,xml}
