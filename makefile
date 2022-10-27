CC = gcc
CFLAGS = -static

TARGET_TEST = dyn stat
TARGET = apager
OBJS = loader.o debug.o

all: $(TARGET) $(TARGET_TEST)

.PHONY: clean
clean: 
	rm -f *.o
	rm -f $(TARGET) $(TARGET_TEST)

dyn: tests/hello_world.c 
	$(CC) -o $@ $^

stat: tests/hello_world.c 
	$(CC) $(CFLAGS) -o $@ $^

apager: $(OBJS)
	$(CC) -o $@ $^

loader.o: src/loader.c
	$(CC) -c $^
debug.o: src/debug.c src/debug.h
	$(CC) -c $^