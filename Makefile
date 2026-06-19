# wardencheck - WoW Warden client integrity checker
# Single translation unit, no third-party dependencies.

CXX      ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra
TARGET    = wardencheck
SRC       = wardencheck.cpp

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $@ $(SRC)

clean:
	rm -f $(TARGET) $(TARGET).exe
