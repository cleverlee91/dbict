CC = gcc
CFLAGS +=
EXTRA_CFLAGS += -I.\
				-I../asn\
				-I../llc\

LDFLAGS += -L. -ltciasn -lpthread -lllc -lpcap

TARGET = tcia

.PHONY: $(TARGET)
$(TARGET):
	$(CC) tcia.c $(CFLAGS) $(EXTRA_CFLAGS) $(LDFLAGS) -o ./bin/$@
