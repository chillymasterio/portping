CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -Wpedantic -std=c99
LDFLAGS ?=
LDLIBS ?= -lm

PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
MANDIR ?= $(PREFIX)/share/man/man1

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
	install -d $(DESTDIR)$(MANDIR)
	install -m 644 portping.1 $(DESTDIR)$(MANDIR)/portping.1

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(TARGET)
	rm -f $(DESTDIR)$(MANDIR)/portping.1

PREFIX ?= /usr/local

install: portping
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 755 portping $(DESTDIR)$(PREFIX)/bin/portping
	install -d $(DESTDIR)$(PREFIX)/share/man/man1
	install -m 644 portping.1 $(DESTDIR)$(PREFIX)/share/man/man1/portping.1

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/portping
	rm -f $(DESTDIR)$(PREFIX)/share/man/man1/portping.1
