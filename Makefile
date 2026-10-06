CC = gcc
CFLAGS = -Iinclude 
LDFLAGS = -lssl -lcrypto -lm -lreadline

TARGET = apkxhunter

SRCS = src/main.c \
       src/ah_shell_interface.c \
       src/apktool.c \
       src/banner.c \
       src/extract.c \
       src/file_making.c \
       src/functions.c \
       src/jadx.c \
       src/main_ai.c \
       src/masvs.c \
       src/multi_apk.c \
       src/run.c \
       src/scan_dir_func.c \
       src/scan_file_func.c \
       src/scan_secrets.c \
       src/patterns.c \
       src/define.c

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
