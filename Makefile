CC = gcc
CFLAGS = -Wall -g
LDFLAGS = -L/usr/lib -lssl -lcrypto
TARGET = test
SRC = proxyServer.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: all clean