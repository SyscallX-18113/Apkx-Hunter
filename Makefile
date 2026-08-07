# APKX-Hunter Makefile

CC := gcc

TARGET := apkxhunter

PREFIX ?= /usr

SRC_DIR := Apkx-Hunter/src
INC_DIR := Apkx-Hunter/include

CFLAGS := -O2 -I$(INC_DIR)
LDFLAGS := -lssl -lcrypto -lm

SRCS := $(wildcard $(SRC_DIR)/*.c)
OBJS := $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) $(LDFLAGS) -o $@

$(SRC_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

install: $(TARGET)
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	install -m755 $(TARGET) $(DESTDIR)$(PREFIX)/bin/$(TARGET)

	mkdir -p $(DESTDIR)$(PREFIX)/share/apkx-hunter
	install -m644 model.bin $(DESTDIR)$(PREFIX)/share/apkx-hunter/model.bin

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/$(TARGET)
	rm -rf $(DESTDIR)$(PREFIX)/share/apkx-hunter

clean:
	rm -f $(TARGET)
	rm -f $(OBJS)

rebuild: clean all

.PHONY: all clean rebuild install uninstall
