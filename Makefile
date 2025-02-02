CC = gcc
CFLAGS = -Wall -g
LDFLAGS = -lssl -lcrypto
TARGET = test_proxy
INCLUDES = -I./
SRC = client_side.c http.c ssl_conn.c net.c log.c config_parser.c
OBJ = $(SRC:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJ) $(LDFLAGS) $(INCLUDES)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)

.PHONY: all clean
