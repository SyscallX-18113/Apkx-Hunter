CC = gcc
CFLAGS = -Iinclude
LDFLAGS = -lssl -lcrypto -lm

TARGET = apkxhunter

SRCS = Apkx-Hunter/src/main.c \
       Apkx-Hunter/src/apktool.c \
       Apkx-Hunter/src/banner.c \
       Apkx-Hunter/src/extract.c \
       Apkx-Hunter/src/file_making.c \
       Apkx-Hunter/src/functions.c \
       Apkx-Hunter/src/jadx.c \
       Apkx-Hunter/src/main_ai.c \
       Apkx-Hunter/src/masvs.c \
       Apkx-Hunter/src/multi_apk.c \
       Apkx-Hunter/src/run.c \
       Apkx-Hunter/src/scan_dir_func.c \
       Apkx-Hunter/src/scan_file_func.c \
       Apkx-Hunter/src/scan_secrets.c \
       Apkx-Hunter/src/patterns.c \
       Apkx-Hunter/src/define.c

PREFIX ?= /usr

all:
	$(CC) $(SRCS) $(CFLAGS) $(LDFLAGS) -o $(TARGET)

clean:
	rm -f $(TARGET)

install: $(TARGET)
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	install -m755 $(TARGET) $(DESTDIR)$(PREFIX)/bin/$(TARGET)
	
	mkdir -p $(DESTDIR)/usr/share/apkx-hunter
	install -m644 assets/model.bin $(DESTDIR)/usr/share/apkx-hunter/model.bin 2>/dev/null || true

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/$(TARGET)
	rm -f $(DESTDIR)/usr/share/apkx-hunter/model.bin

.PHONY: all clean install uninstall
