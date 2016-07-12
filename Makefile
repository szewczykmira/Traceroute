CC = gcc
CFLAGS = -Wall -W -Wshadow -std=gnu99
TARGETS = traceroute

all: $(TARGETS)

traceroute: sockwrap.o icmp.o request_receive.o

clean:
	rm -f *.o

distclean: clean
	rm -f $(TARGETS)
