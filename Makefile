CC = gcc

CFLAGS = -Wall -Wextra -O2

LIBS = -lm -lssl -lcrypto

TARGET = apkxhunter

SRC = Apkx-Hunter/main.c

all:
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LIBS)

clean:
	rm -f $(TARGET)

install:
	install -Dm755 $(TARGET) /usr/local/bin/$(TARGET)

uninstall:
	rm -f /usr/local/bin/$(TARGET)
