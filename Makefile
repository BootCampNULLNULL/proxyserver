CC = gcc
CFLAGS = -Wall -g
LDFLAGS = -lssl -lcrypto
TARGET = test_proxy
SRC = client_side.c ssl_conn.c http.c
OBJ = $(SRC:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJ) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)

.PHONY: all clean
