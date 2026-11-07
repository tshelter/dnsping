CC ?= gcc
CFLAGS ?= -std=c99 -Wall -Wextra -O2
TARGET = dnsping-linux

.PHONY: all clean build

all: $(TARGET)

$(TARGET): main.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)

build: $(TARGET)
