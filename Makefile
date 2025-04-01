CC = gcc
CFLAGS = -Wall -g
LDFLAGS = -lssl -lcrypto
TARGET = test_proxy
INCLUDES = -I./
SRC = client_side.c http.c ssl_conn.c net.c log.c config_parser.c util.c
OBJ = $(SRC:.c=.o)
DFLAGS=
DFLAGS+=-DMULTI_THREAD
all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) $(INCLUDES) -o $(TARGET) $(OBJ) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) $(DFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)

.PHONY: all clean
