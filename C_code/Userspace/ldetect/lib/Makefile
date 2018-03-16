CFLAGS = -g
CFLAGS += -fPIC -Wall -Wunused-function -Wextra
CC = gcc
INCLUDES = -I../include -I../include/lib

LIB = libdetect.so

all:$(LIB)

OBJS = backtrace.o \
       daemon.o \
       io_wrapper.o \
       json.o \
       log.o \
       pidfile.o \
       thread.o \
       timer.o

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES)  -o $@ -c $<

$(LIB): $(OBJS)
	$(CC) -shared -o $@ $^
install:
	cp -rf $(LIB) /usr/lib64/

clean:
	rm -rf *.o $(LIB)
