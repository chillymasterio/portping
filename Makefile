CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -Wpedantic -std=c99
LDFLAGS ?=
LDLIBS ?= -lm

PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin

TARGET = portping
SRC = portping.c

ifeq ($(OS),Windows_NT)
    LDLIBS += -lws2_32
    TARGET = portping.exe
endif

.PHONY: all clean install uninstall

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -f $(TARGET)

install: $(TARGET)
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 $(TARGET) $(DESTDIR)$(BINDIR)/$(TARGET)

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(TARGET)
