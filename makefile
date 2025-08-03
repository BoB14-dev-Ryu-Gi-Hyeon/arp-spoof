LDLIBS=-lpcap

all: send-arp


./lib/main.o: ./lib/mac.h ./lib/ip.h ./lib/ethhdr.h ./lib/arphdr.h main.cpp

./lib/arphdr.o: ./lib/mac.h ./lib/ip.h ./lib/arphdr.h ./lib/arphdr.cpp

./lib/ethhdr.o: ./lib/mac.h ./lib/ethhdr.h ./lib/ethhdr.cpp

./lib/ip.o: ./lib/ip.h ./lib/ip.cpp

./lib/mac.o : ./lib/mac.h ./lib/mac.cpp

send-arp: main.o ./lib/arphdr.o ./lib/ethhdr.o ./lib/ip.o ./lib/mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f send-arp *.o
	rm -f send-arp ./lib/*.o
