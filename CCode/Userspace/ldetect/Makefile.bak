CC = gcc
CFLAGS = -g -Wall
INCLUDES = -I./include
LIBS_INCLUDES = -I./include/lib/
#LIBS_PATH = -L./lib
LIBS = -ldetect -lpthread -lm

DIRS = lib/


TARGET_OBJECTS = ld_config.o \
		 ld_recv.o \
		 ld_report.o \
		 ld_send.o \
		 ldetect.o
all: libdetect.so ldetect

libdetect.so:
	echo "MakeInfo: `date +"%D %T"` Installing $(DIRS) ..... ";
	make -C $(DIRS) 

ldetect: $(TARGET_OBJECTS)
#	$(CC) $(CFLAGS) $(INCLUDES) $(LIBS_PATH) $(TARGET_OBJECTS) $(LIBS) $(LIBS_INCLUDES) -o $@
	$(CC) $(CFLAGS) $(INCLUDES) $(TARGET_OBJECTS) $(LIBS) $(LIBS_INCLUDES) -o $@

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) $(LIBS_INCLUDES) -o $@ -c $<
install:
	make -C $(DIRS) install

clean:
	rm -rf *.o ldetect;
	make -C $(DIRS) clean;

