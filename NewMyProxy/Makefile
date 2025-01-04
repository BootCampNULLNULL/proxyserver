# Makefile for building the TLS Proxy Server

# Compiler and flags
CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -pedantic -O2

# OpenSSL libraries
LIBS = -lssl -lcrypto -lpthread

# Source files and target
SRCS = cloud_proxy_server.cpp
TARGET = proxy_server

# Build rules
all: $(TARGET)

$(TARGET): $(SRCS)
	$(CXX) $(CXXFLAGS) $(SRCS) -o $(TARGET) $(LIBS)

clean:
	rm -f $(TARGET)

