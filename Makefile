CC = gcc
CFLAGS = -Wall -g -O2 -pthread
LDFLAGS = -lssl -lcrypto -lsqlite3 -lodbc
TARGET = test_proxy
INCLUDES = -I./
SRC = client_side.c http.c ssl_conn.c net.c log.c config_parser.c util.c worker.c auth.c db_conn.c select_user.c
OBJ = $(SRC:.c=.o)
#DFLAGS=
#DFLAGS+=-DMULTI_THREAD
DFLAGS+=-DTEST_PROXY_DB
all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(INCLUDES) -o $(TARGET) $(OBJ) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) $(DFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)

.PHONY: all clean
