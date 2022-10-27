CC = gcc
CFLAGS = -static

TARGET_TEST = dyn stat
TARGET = apager dpager
OBJS = debug.o

all: $(TARGET) $(TARGET_TEST)

.PHONY: clean
clean: 
	rm -f *.o
	rm -f $(TARGET) $(TARGET_TEST)

dyn: tests/hello_world.c 
	$(CC) -o $@ $^

stat: tests/hello_world.c 
	$(CC) $(CFLAGS) -o $@ $^

apager: apager.o $(OBJS)
	$(CC) -o $@ $^

dpager: dpager.o $(OBJS)
	$(CC) -o $@ $^

apager.o: src/apager.c
	$(CC) -c $^
dpager.o: src/dpager.c
	$(CC) -c $^
debug.o: src/debug.c src/debug.h
	$(CC) -c $^