CC = g++
CFLAGS = -std=c++11
TARGETS = client serverM serverS serverL serverH

all: $(TARGETS)

client: client.cpp
	$(CC) $(CFLAGS) $^ -o $@

serverM: serverM.cpp
	$(CC) $(CFLAGS) $^ -o $@

serverS: serverS.cpp
	$(CC) $(CFLAGS) $^ -o $@

serverL: serverL.cpp
	$(CC) $(CFLAGS) $^ -o $@

serverH: serverH.cpp
	$(CC) $(CFLAGS) $^ -o $@

clean:
	rm -f $(TARGETS)