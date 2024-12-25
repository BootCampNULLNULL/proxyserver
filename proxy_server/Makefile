# Compiler and flags
CXX = g++
CXXFLAGS = -Iinclude -std=c++17 -Wall
LDFLAGS = -lssl -lcrypto

# Source files and object files
SRCS = main.cpp client_side.cpp server_side.cpp make_cert.cpp check_policy.cpp access_log.cpp
OBJS = $(SRCS:.cpp=.o)

# Target executable
TARGET = proxy_server

# Default build rule
all: $(TARGET)

# Linking rule
$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

# Compilation rule
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Clean rule
clean:
	rm -f $(OBJS) $(TARGET)

