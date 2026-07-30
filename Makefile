CC = gcc

TARGET = apkxhunter

SRC = Apkx-Hunter/main.c

LIBS = -lm -lssl -lcrypto

all:
	$(CC) $(SRC) -o $(TARGET) $(LIBS)

clean:
	rm -f $(TARGET)

install:
	install -Dm755 $(TARGET) /usr/local/bin/$(TARGET)

uninstall:
	rm -f /usr/local/bin/$(TARGET)
