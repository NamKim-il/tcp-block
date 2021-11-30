LDLIBS=-lpcap -lpthread

all: tcp-block

tcp-block: main.o tcphdr.o ethhdr.o ip.o mac.o iphdr.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f tcp-block *.o
